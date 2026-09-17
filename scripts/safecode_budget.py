"""SafeCode Persistent Budget 库（Recovery / Self-Healing 预算状态）。

职责：
- 每个 Task 一个可持久化 Budget State：``.safecode/state/<task-id>.json``
- 计数器在文件锁内"读-改-写"，原子替换写盘，避免并发丢失更新
- 状态损坏 / schema_version 不认识 / 字段类型错误 → 抛 BudgetError（Fail-Closed）
- 预算判定：max_recovery_attempts（单任务连续失败上限）+ 全局预算
  （max_total_test_runs / max_total_recoveries / max_total_time）
- 生成诊断报告 ``.safecode/diagnostic-report.md``

纯 Python 标准库，跨平台。Python >= 3.10。
并发锁：Windows 用 msvcrt.locking，POSIX 用 fcntl.flock。
"""

from __future__ import annotations

import collections
import datetime
import json
import os
import time
from typing import Any, Dict, List, Optional

from safecode_common import (
    now_utc_iso,
    parse_duration,
    read_json_file,
    repo_root,
    write_json_file,
)

if os.name == "nt":
    import msvcrt
else:
    import fcntl

# --------------------------------------------------------------------------- #
# 错误
# --------------------------------------------------------------------------- #

SCHEMA_VERSION = "1.0"

CODE_STATE_CORRUPT = "BUDGET_STATE_CORRUPT"
CODE_STATE_INVALID = "BUDGET_STATE_INVALID"
CODE_LOCK_TIMEOUT = "BUDGET_LOCK_TIMEOUT"

LOCK_TIMEOUT = 30.0  # 秒

DEFAULT_LIMITS: Dict[str, Any] = {
    "max_recovery_attempts": 3,
    "max_total_test_runs": 20,
    "max_total_recoveries": 10,
    "max_total_time": "30m",
}


class BudgetError(Exception):
    """预算状态错误。code 直接作为 JSON result 的 code 字段。"""

    def __init__(self, code: str, message: str, location: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.location = location


# --------------------------------------------------------------------------- #
# 路径解析
# --------------------------------------------------------------------------- #

def _resolve_root(root: Optional[str]) -> str:
    """状态根目录：显式 root > git repo 根 > 当前目录。"""
    if root:
        return root
    r = repo_root(os.getcwd())
    return r or os.getcwd()


def state_dir(root: Optional[str]) -> str:
    return os.path.join(_resolve_root(root), ".safecode", "state")


def state_path(root: Optional[str], task_id: str) -> str:
    return os.path.join(state_dir(root), f"{task_id}.json")


def current_path(root: Optional[str]) -> str:
    return os.path.join(state_dir(root), "current")


def set_current_task(task_id: str, root: Optional[str] = None) -> None:
    p = current_path(root)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(task_id)


def get_current_task(root: Optional[str] = None) -> str:
    p = current_path(root)
    if os.path.isfile(p):
        try:
            return open(p, encoding="utf-8").read().strip()
        except OSError:
            return ""
    return ""


def diagnostic_report_path(root: Optional[str] = None) -> str:
    return os.path.join(_resolve_root(root), ".safecode", "diagnostic-report.md")


# --------------------------------------------------------------------------- #
# 状态构造 / 校验
# --------------------------------------------------------------------------- #

def _new_state(task_id: str) -> Dict[str, Any]:
    now = now_utc_iso()
    return {
        "schema_version": SCHEMA_VERSION,
        "task_id": task_id,
        "started_at": now,
        "updated_at": now,
        "test_runs": 0,
        "recoveries": 0,
        "elapsed_seconds": 0,
        "last_result_code": "",
        "consecutive_failures": 0,
        "history": [],
    }


def _validate_state(data: Any, path: str) -> None:
    """校验已解析的状态对象。任何不合法 → BudgetError（Fail-Closed）。"""
    if not isinstance(data, dict):
        raise BudgetError(CODE_STATE_INVALID, f"state must be a JSON object: {path}", path)
    if data.get("schema_version") != SCHEMA_VERSION:
        raise BudgetError(
            CODE_STATE_INVALID,
            f"unsupported state schema_version: {data.get('schema_version')!r} (expected {SCHEMA_VERSION!r})",
            path,
        )
    for key in ("test_runs", "recoveries", "consecutive_failures", "elapsed_seconds"):
        v = data.get(key)
        if not isinstance(v, int) or isinstance(v, bool):
            raise BudgetError(CODE_STATE_INVALID, f"state field {key!r} must be int, got {v!r}", path)
    if not isinstance(data.get("task_id"), str):
        raise BudgetError(CODE_STATE_INVALID, "state.task_id must be a string", path)
    if not isinstance(data.get("history"), list):
        raise BudgetError(CODE_STATE_INVALID, "state.history must be a list", path)


def load_state(task_id: str, root: Optional[str] = None) -> Dict[str, Any]:
    """加载状态。文件缺失 → 返回全新状态（不报错）；损坏/不合法 → BudgetError。"""
    path = state_path(root, task_id)
    if not os.path.exists(path):
        return _new_state(task_id)
    try:
        data = read_json_file(path)
    except (json.JSONDecodeError, ValueError) as exc:
        raise BudgetError(CODE_STATE_CORRUPT, f"state file is not valid JSON: {path}: {exc}", path)
    except OSError as exc:
        raise BudgetError(CODE_STATE_CORRUPT, f"cannot read state file: {path}: {exc}", path)
    _validate_state(data, path)
    return data


# --------------------------------------------------------------------------- #
# 时间辅助
# --------------------------------------------------------------------------- #

def _parse_iso(ts: Any) -> Optional[datetime.datetime]:
    if not isinstance(ts, str):
        return None
    s = ts.replace("Z", "+00:00")
    try:
        return datetime.datetime.fromisoformat(s)
    except ValueError:
        return None


def _elapsed_seconds(state: Dict[str, Any]) -> int:
    start = _parse_iso(state.get("started_at"))
    if start is None:
        v = state.get("elapsed_seconds", 0)
        return int(v) if isinstance(v, int) else 0
    now = datetime.datetime.now(datetime.timezone.utc)
    return max(0, int((now - start).total_seconds()))


# --------------------------------------------------------------------------- #
# 并发文件锁（读-改-写临界区）
# --------------------------------------------------------------------------- #

def _open_lock_file(lock_path: str):
    """打开（必要时创建）锁文件：无缓冲、不写内容、不在持锁前 seek。

    Windows 上 CRT 的字节区间锁是**强制锁**：别的进程正持着这把锁时，对同一文件
    做带缓冲的 seek/write 会触发 flush 并落到被锁住的字节上，直接抛
    PermissionError。所以这里只 open，不写也不 seek；所有可能失败的定位动作都放到
    _acquire_lock 的重试循环里。

    锁的范围是文件头 1 字节；文件为空时也允许锁（Windows 允许锁超出 EOF 的区域，
    POSIX 的 flock 根本不看字节范围），因此不需要预先写一个字节进去。
    """
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    return os.fdopen(fd, "r+b", buffering=0)


def _acquire_lock(fh, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            if os.name == "nt":
                # 纯定位（无缓冲，不会写盘）；对方持锁时这里可能抛 PermissionError，
                # 由下面的 except 转成重试，而不是把进程打挂。
                os.lseek(fh.fileno(), 0, os.SEEK_SET)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise BudgetError(
                    CODE_LOCK_TIMEOUT,
                    f"could not acquire budget lock within {timeout}s: {fh.name}",
                )
            time.sleep(0.005)


def _release_lock(fh) -> None:
    """显式释放锁；失败也不能掩盖业务异常，交给 close 兜底。"""
    try:
        if os.name == "nt":
            os.lseek(fh.fileno(), 0, os.SEEK_SET)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass


def _with_lock(root: Optional[str], task_id: str, mutator, *, timeout: float = LOCK_TIMEOUT) -> Dict[str, Any]:
    """在文件锁内对状态做"读-改-写"，保证并发安全。"""
    path = state_path(root, task_id)
    lock_path = path + ".lock"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lock_fh = _open_lock_file(lock_path)
    try:
        _acquire_lock(lock_fh, timeout)
        if os.path.exists(path):
            try:
                data = read_json_file(path)
            except (json.JSONDecodeError, ValueError) as exc:
                raise BudgetError(CODE_STATE_CORRUPT, f"state file is not valid JSON: {path}: {exc}", path)
            except OSError as exc:
                raise BudgetError(CODE_STATE_CORRUPT, f"cannot read state file: {path}: {exc}", path)
            _validate_state(data, path)
        else:
            data = _new_state(task_id)
        data = mutator(data)
        data["updated_at"] = now_utc_iso()
        data["elapsed_seconds"] = _elapsed_seconds(data)
        write_json_file(path, data)
    finally:
        _release_lock(lock_fh)
        try:
            lock_fh.close()
        except OSError:
            pass
    return data


# --------------------------------------------------------------------------- #
# 计数操作
# --------------------------------------------------------------------------- #

def _append_history(state: Dict[str, Any], htype: str, level: str, code: str,
                    summary: str, duration_seconds: float) -> None:
    state.setdefault("history", []).append({
        "ts": now_utc_iso(),
        "type": htype,
        "level": level,
        "code": code,
        "summary": summary,
        "duration_seconds": duration_seconds,
    })


def record_test_run(task_id: str, *, root: Optional[str] = None, level: str = "L0",
                    code: str = "", summary: str = "", duration_seconds: float = 0,
                    limits: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """记录一次测试运行失败：test_runs +1，consecutive_failures +1。"""

    def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
        state["test_runs"] = int(state["test_runs"]) + 1
        state["consecutive_failures"] = int(state["consecutive_failures"]) + 1
        if code:
            state["last_result_code"] = code
        _append_history(state, "test_run", level, code, summary, duration_seconds)
        return state

    return _with_lock(root, task_id, mutate)


def record_recovery(task_id: str, *, root: Optional[str] = None, level: str = "L1",
                    code: str = "", summary: str = "", duration_seconds: float = 0,
                    limits: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """记录一次恢复失败：recoveries +1，consecutive_failures +1（不计入 test_runs）。"""

    def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
        state["recoveries"] = int(state["recoveries"]) + 1
        state["consecutive_failures"] = int(state["consecutive_failures"]) + 1
        if code:
            state["last_result_code"] = code
        _append_history(state, "recovery", level, code, summary, duration_seconds)
        return state

    return _with_lock(root, task_id, mutate)


def record_flaky_rerun(task_id: str, *, root: Optional[str] = None, level: str = "L1",
                       code: str = "", summary: str = "", duration_seconds: float = 0,
                       limits: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """记录一次 Flaky 重跑：只消耗 test_runs，不消耗 recoveries，不增加 consecutive_failures。"""

    def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
        state["test_runs"] = int(state["test_runs"]) + 1
        if code:
            state["last_result_code"] = code
        _append_history(state, "flaky_rerun", level, code, summary, duration_seconds)
        return state

    return _with_lock(root, task_id, mutate)


def record_success(task_id: str, *, root: Optional[str] = None, level: str = "L0",
                   code: str = "", summary: str = "", duration_seconds: float = 0,
                   limits: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """记录恢复成功：consecutive_failures 归零，任务完成。"""

    def mutate(state: Dict[str, Any]) -> Dict[str, Any]:
        state["consecutive_failures"] = 0
        if code:
            state["last_result_code"] = code
        return state

    return _with_lock(root, task_id, mutate)


def reset_state(task_id: str, root: Optional[str] = None) -> None:
    """显式清空某个 task 的状态（删除状态文件与锁文件）。"""
    path = state_path(root, task_id)
    for p in (path, path + ".lock"):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass


# --------------------------------------------------------------------------- #
# 预算判定
# --------------------------------------------------------------------------- #

def _resolve_limits(limits: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out = dict(DEFAULT_LIMITS)
    if isinstance(limits, dict):
        for key in DEFAULT_LIMITS:
            if limits.get(key) is not None:
                out[key] = limits[key]
    return out


def check_exhausted(state: Dict[str, Any], limits: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """返回耗尽原因（字符串）或 None。"""
    lim = _resolve_limits(limits)
    cf = int(state.get("consecutive_failures", 0))
    if cf >= int(lim["max_recovery_attempts"]):
        return (f"max_recovery_attempts: consecutive_failures={cf} "
                f">= {lim['max_recovery_attempts']}")
    tr = int(state.get("test_runs", 0))
    if tr >= int(lim["max_total_test_runs"]):
        return f"max_total_test_runs: test_runs={tr} >= {lim['max_total_test_runs']}"
    rc = int(state.get("recoveries", 0))
    if rc >= int(lim["max_total_recoveries"]):
        return f"max_total_recoveries: recoveries={rc} >= {lim['max_total_recoveries']}"
    limit_time = parse_duration(str(lim["max_total_time"]))
    if limit_time:
        el = _elapsed_seconds(state)
        if el >= limit_time:
            return f"max_total_time: elapsed={el}s >= {limit_time}s"
    return None


def budget_report(state: Dict[str, Any], limits: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """生成预算明细（计数 / 限制 / 剩余 / 是否耗尽）。"""
    lim = _resolve_limits(limits)
    counts = {
        "test_runs": int(state.get("test_runs", 0)),
        "recoveries": int(state.get("recoveries", 0)),
        "consecutive_failures": int(state.get("consecutive_failures", 0)),
        "elapsed_seconds": _elapsed_seconds(state),
    }
    reason = check_exhausted(state, lim)
    max_time_seconds = parse_duration(str(lim["max_total_time"])) or 0
    return {
        "counts": counts,
        "limits": {
            "max_recovery_attempts": int(lim["max_recovery_attempts"]),
            "max_total_test_runs": int(lim["max_total_test_runs"]),
            "max_total_recoveries": int(lim["max_total_recoveries"]),
            "max_total_time": str(lim["max_total_time"]),
            "max_total_time_seconds": max_time_seconds,
        },
        "remaining": {
            "max_recovery_attempts": max(0, int(lim["max_recovery_attempts"]) - counts["consecutive_failures"]),
            "max_total_test_runs": max(0, int(lim["max_total_test_runs"]) - counts["test_runs"]),
            "max_total_recoveries": max(0, int(lim["max_total_recoveries"]) - counts["recoveries"]),
        },
        "exhausted": reason is not None,
        "exhausted_reason": reason,
    }


# --------------------------------------------------------------------------- #
# 诊断报告
# --------------------------------------------------------------------------- #

def generate_diagnostic_report(state: Dict[str, Any], limits: Optional[Dict[str, Any]] = None,
                               reason: Optional[str] = None) -> str:
    """生成诊断报告 Markdown 文本。"""
    lim = _resolve_limits(limits)
    elapsed = _elapsed_seconds(state)

    dist: "collections.Counter" = collections.Counter()
    for h in state.get("history", []):
        if h.get("type") in ("test_run", "recovery", "flaky_rerun"):
            dist[h.get("level", "?")] += 1

    failures = [
        h for h in state.get("history", [])
        if h.get("type") in ("test_run", "recovery", "flaky_rerun")
    ]

    lines: List[str] = []
    lines.append("# SafeCode Recovery Diagnostic Report")
    lines.append("")
    lines.append(f"- Task ID: `{state.get('task_id', '')}`")
    lines.append(f"- Started: {state.get('started_at', '')}")
    lines.append(f"- Updated: {state.get('updated_at', '')}")
    lines.append(f"- Elapsed: {elapsed}s")
    lines.append(f"- Reason: {reason or 'recovery budget exhausted'}")
    lines.append("")
    lines.append("## Counters")
    lines.append(f"- test_runs: {state.get('test_runs', 0)} / limit {lim['max_total_test_runs']}")
    lines.append(f"- recoveries: {state.get('recoveries', 0)} / limit {lim['max_total_recoveries']}")
    lines.append(f"- consecutive_failures: {state.get('consecutive_failures', 0)} / limit {lim['max_recovery_attempts']}")
    lines.append(f"- max_total_time: {lim['max_total_time']}")
    lines.append("")
    lines.append("## Failure distribution by level")
    if dist:
        for lvl in sorted(dist):
            lines.append(f"- {lvl}: {dist[lvl]}")
    else:
        lines.append("- (none)")
    lines.append("")
    lines.append("## Failure summaries")
    if failures:
        for h in failures:
            lines.append(f"- [{h.get('ts', '')}] {h.get('level', '')} {h.get('code', '')}: {h.get('summary', '')}")
    else:
        lines.append("- (none)")
    lines.append("")
    lines.append("## Action required")
    lines.append("已达到最大自救轮数 / 预算耗尽，停止修改，禁止 Push，需人工介入。")
    lines.append("")
    lines.append("## Suggested investigation")
    lines.append("- 复核最近一次失败测试 / 构建的输出，以及相对上次已知良好状态的 diff。")
    lines.append("- 优先排查环境 / 依赖问题（L3），不要贸然修改业务代码。")
    lines.append("- 若判定为 Flaky，不要继续修改正确代码，应在干净环境重跑验证。")
    lines.append("- 修复后，在任意 Push 前重新跑完整 SafeCode 流水线（安全 + 测试 + Git Guard）。")
    return "\n".join(lines) + "\n"


def write_diagnostic_report(state: Dict[str, Any], limits: Optional[Dict[str, Any]] = None,
                            root: Optional[str] = None, reason: Optional[str] = None) -> str:
    """把诊断报告写到 .safecode/diagnostic-report.md，返回路径。"""
    directory = os.path.join(_resolve_root(root), ".safecode")
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "diagnostic-report.md")
    text = generate_diagnostic_report(state, limits, reason)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path
