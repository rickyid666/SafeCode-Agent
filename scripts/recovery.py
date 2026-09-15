#!/usr/bin/env python3
"""SafeCode Agent — 自救（recovery）状态机。

跟踪连续失败次数，达到上限（默认 3 轮）即停止修改、禁止 Push，并生成诊断报告。

子命令：
    record-failure [--level L1] [--summary "..."]
        失败计数 +1，写入状态文件；若达到上限或等级为 L5/L6，立即拒绝（退出码 10）
        并生成 .safecode/diagnostic-report.md。
    record-success
        清零连续失败计数（记录一次成功）。
    status
        打印当前计数与剩余额度。
    reset
        清零（等同于 record-success，但不写成功历史）。

状态文件：<repo-root>/.safecode/recovery-state.json
    字段： consecutive_failures, max_attempts, history[]

最大自救轮数：默认 3，可用 --max-attempts 覆盖；环境变量
SAFECODE_MAX_RECOVERY_ATTEMPTS 优先级最高。

退出码：
    0  正常（未达上限）
    10 达到自救上限 / L5/L6 立即上限（拒绝继续）
    2  用法错误 / 内部错误
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import safecode_common as sc

DEFAULT_MAX_ATTEMPTS = 3
STATE_DIRNAME = ".safecode"
STATE_FILE = "recovery-state.json"
DIAG_FILE = "diagnostic-report.md"


def state_dir() -> str:
    """状态目录：优先 git 仓库根，回退当前目录。"""
    root = sc.repo_root()
    base = root or os.getcwd()
    return os.path.join(base, STATE_DIRNAME)


def state_path() -> str:
    return os.path.join(state_dir(), STATE_FILE)


def diagnostic_path() -> str:
    return os.path.join(state_dir(), DIAG_FILE)


def effective_max_attempts(override: int | None) -> int:
    env_val = os.environ.get("SAFECODE_MAX_RECOVERY_ATTEMPTS", "").strip()
    if env_val and env_val.isdigit():
        return int(env_val)
    if override is not None:
        return override
    return DEFAULT_MAX_ATTEMPTS


def load_state(path: str, max_attempts: int) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            data.setdefault("consecutive_failures", 0)
            data.setdefault("max_attempts", max_attempts)
            data.setdefault("history", [])
            return data
        except (json.JSONDecodeError, OSError):
            pass
    return {"consecutive_failures": 0, "max_attempts": max_attempts, "history": []}


def save_state(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, ensure_ascii=False)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_diagnostic(state: dict) -> str:
    """生成诊断报告，返回文件路径。"""
    history = state.get("history", [])
    # 错误等级分布
    dist: dict = {}
    for h in history:
        lvl = h.get("level", "UNKNOWN")
        dist[lvl] = dist.get(lvl, 0) + 1

    lines = []
    lines.append("# SafeCode 自救诊断报告")
    lines.append("")
    lines.append(f"- 生成时间: {now_iso()}")
    lines.append(f"- 连续失败次数: {state.get('consecutive_failures', 0)}")
    lines.append(f"- 最大自救轮数: {state.get('max_attempts', DEFAULT_MAX_ATTEMPTS)}")
    lines.append("")
    lines.append("## 结论")
    lines.append("")
    lines.append("> **已达到最大自救轮数，停止修改，禁止 Push，请人工介入。**")
    lines.append("")
    lines.append("Agent 已连续尝试修复但未能通过，继续修改可能导致更多破坏。"
                 "请勿自动 Push，等待人工排查与处理。")
    lines.append("")
    lines.append("## 错误等级分布")
    lines.append("")
    if dist:
        for lvl, cnt in sorted(dist.items(), key=lambda x: -x[1]):
            lines.append(f"- {lvl} ({sc.error_level_meaning(lvl)}): {cnt} 次")
    else:
        lines.append("- 无记录")
    lines.append("")
    lines.append("## 历次失败摘要")
    lines.append("")
    if history:
        for i, h in enumerate(history, 1):
            ts = h.get("timestamp", "?")
            lvl = h.get("level", "?")
            summary = h.get("summary", "")
            lines.append(f"{i}. `[{ts}]` **{lvl}** — {summary}")
    else:
        lines.append("- 无记录")
    lines.append("")
    lines.append("## 建议排查方向")
    lines.append("")
    lines.append("- 查看上方历次失败摘要，定位反复出现的根因（依赖 / 编译 / 断言 / 环境）。")
    lines.append("- 对比最近一次成功提交（`git log` / `git diff`），确认引入的变更范围。")
    lines.append("- 如为 L5/L6：极可能是安全风险或无法确定，务必人工确认，切勿猜测后继续。")
    lines.append("- 考虑恢复到上一个已知安全状态（`git stash` / 临时分支 / checkpoint）。")
    lines.append("- 修复后重新运行测试与安全扫描；通过后再考虑提交与 Push。")
    lines.append("")

    content = "\n".join(lines)
    path = diagnostic_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def cmd_record_failure(args) -> int:
    max_attempts = effective_max_attempts(args.max_attempts)
    path = state_path()
    state = load_state(path, max_attempts)
    state["max_attempts"] = max_attempts

    level = args.level or sc.L1
    summary = args.summary or ""

    state["consecutive_failures"] = state.get("consecutive_failures", 0) + 1
    state.setdefault("history", []).append({
        "timestamp": now_iso(),
        "level": level,
        "summary": summary,
    })

    # 是否立即达到上限语义：连续失败达上限，或等级为 L5/L6
    reached_limit = (
        state["consecutive_failures"] >= max_attempts
        or level in (sc.L5, sc.L6)
    )

    if reached_limit:
        save_state(path, state)
        diag = generate_diagnostic(state)
        print(sc.colorize("SafeCode recovery: 已达到最大自救轮数，停止修改，禁止 Push。", "red"))
        print(f"连续失败: {state['consecutive_failures']}/{max_attempts}"
              + (f"（等级 {level} 触发立即上限）" if level in (sc.L5, sc.L6) else ""))
        print(f"诊断报告: {diag}")
        print("请人工介入，移除/修复问题后重新评估，不要自动继续修改或 Push。")
        return sc.EXIT_RECOVERY_LIMIT

    save_state(path, state)
    remaining = max_attempts - state["consecutive_failures"]
    print(sc.colorize(f"已记录一次失败（{level}）。剩余自救额度: {remaining}/{max_attempts}。", "yellow"))
    return sc.EXIT_PASS


def cmd_record_success(args) -> int:
    max_attempts = effective_max_attempts(args.max_attempts)
    path = state_path()
    state = load_state(path, max_attempts)
    state["consecutive_failures"] = 0
    state["max_attempts"] = max_attempts
    save_state(path, state)
    print(sc.colorize("已记录一次成功，连续失败计数清零。", "green"))
    return sc.EXIT_PASS


def cmd_status(args) -> int:
    max_attempts = effective_max_attempts(args.max_attempts)
    path = state_path()
    state = load_state(path, max_attempts)
    cf = state.get("consecutive_failures", 0)
    remaining = max(0, max_attempts - cf)
    print(f"连续失败次数: {cf}")
    print(f"最大自救轮数: {max_attempts}")
    print(f"剩余额度: {remaining}")
    print(f"状态文件: {path}")
    return sc.EXIT_PASS


def cmd_reset(args) -> int:
    max_attempts = effective_max_attempts(args.max_attempts)
    path = state_path()
    state = load_state(path, max_attempts)
    state["consecutive_failures"] = 0
    state["max_attempts"] = max_attempts
    save_state(path, state)
    print(sc.colorize("自救计数已重置。", "green"))
    return sc.EXIT_PASS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recovery.py",
        description="SafeCode 自救状态机（连续失败上限控制）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_fail = sub.add_parser("record-failure", help="记录一次失败（计数 +1）")
    p_fail.add_argument("--level", default=sc.L1,
                        choices=sc.ERROR_LEVELS,
                        help="本次失败的错误等级（默认 L1）")
    p_fail.add_argument("--summary", default="", help="失败摘要文本")
    p_fail.add_argument("--max-attempts", type=int, default=None,
                        help="覆盖最大自救轮数（环境变量 SAFECODE_MAX_RECOVERY_ATTEMPTS 优先）")

    p_ok = sub.add_parser("record-success", help="记录一次成功（清零）")
    p_ok.add_argument("--max-attempts", type=int, default=None)

    p_st = sub.add_parser("status", help="打印当前计数与剩余额度")
    p_st.add_argument("--max-attempts", type=int, default=None)

    p_rs = sub.add_parser("reset", help="清零计数")
    p_rs.add_argument("--max-attempts", type=int, default=None)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return sc.EXIT_USAGE

    handlers = {
        "record-failure": cmd_record_failure,
        "record-success": cmd_record_success,
        "status": cmd_status,
        "reset": cmd_reset,
    }
    try:
        return handlers[args.command](args)
    except Exception as exc:  # noqa: BLE001
        print(f"错误: recovery 内部错误: {exc}", file=sys.stderr)
        return sc.EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
