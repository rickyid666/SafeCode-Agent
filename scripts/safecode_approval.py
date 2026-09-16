#!/usr/bin/env python3
"""SafeCode Agent — Approval Token 与 Operation Fingerprint。

设计契约（SafeCode-Agent-v7.md）：

- 高风险操作的 Hard Stop 不能只依赖"用户说可以"，必须把授权绑定到具体操作。
- Operation Fingerprint = SHA-256(
      normalized_operation + repository_identity + repository_state
      + target + relevant_diff)
  输入按契约归一化，稳定可复现。
- Approval Token 只能授权已明确描述的单一操作，不能成为永久"解锁开关"：
    * 默认 TTL = 10 分钟
    * 一次性（nonce 核销后不可再用）
    * 绑定单一操作（operation_fingerprint）+ 仓库（repository_identity）
- verify_token 必须校验：token_type / operation / operation_fingerprint / expiry /
  nonce 已用 / repository+target 绑定。任一不符抛 ApprovalError。

纯标准库，跨平台。Python >= 3.10。
"""

from __future__ import annotations

import os
import sys

# 契约要求：CLI 脚本顶部先把自身目录加入 sys.path，再 import 共享内核。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import safecode_common as sc

# --------------------------------------------------------------------------- #
# 错误代码
# --------------------------------------------------------------------------- #

TOKEN_INVALID = "TOKEN_INVALID"
TOKEN_EXPIRED = "TOKEN_EXPIRED"
TOKEN_REPLAYED = "TOKEN_REPLAYED"
TOKEN_FINGERPRINT_MISMATCH = "TOKEN_FINGERPRINT_MISMATCH"
TOKEN_REPO_MISMATCH = "TOKEN_REPO_MISMATCH"
TOKEN_OPERATION_MISMATCH = "TOKEN_OPERATION_MISMATCH"


class ApprovalError(Exception):
    """授权校验失败。code 为稳定机器可读代码。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------------- #
# 归一化
# --------------------------------------------------------------------------- #

# 不影响操作语义的运行期开关（SafeCode / 通用 CLI 的输出与冗余选项）
_SEMANTIC_FREE_FLAGS = {
    "--json",
    "--verbose",
    "--quiet",
    "-v",
    "-q",
    "--strict",
    "--no-color",
    "--color",
}


def normalize_operation(argv_or_command: Any) -> str:
    """把命令行（argv 列表或字符串）规范化为稳定、可复现的操作字符串。

    - 折叠空白
    - 去掉 --json / --verbose 之类不影响语义的开关
    - 保持参数原始顺序（不重排序，避免改变 git push origin main 与
      git push main origin 这种语义不同的命令）
    """
    if argv_or_command is None:
        return ""
    if isinstance(argv_or_command, (list, tuple)):
        text = " ".join(str(part) for part in argv_or_command)
    else:
        text = str(argv_or_command)
    # 折叠任意空白为单个空格并裁边
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return ""
    tokens = text.split(" ")
    filtered = [t for t in tokens if t not in _SEMANTIC_FREE_FLAGS]
    if not filtered:
        return ""
    return " ".join(filtered)


def _stable_repo_state(cwd: Optional[str]) -> str:
    """稳定、可复现的仓库状态：HEAD + 当前分支 + 是否脏（忽略 SafeCode 自身 .safecode/ 簿记）。

    关键：签发 token 会把核销记录写入 .safecode/approvals/，若该目录被计入 dirty，
    会导致同一仓库内 issue -> verify 的指纹自行漂移、授权永远失败。因此 0/1 的 dirty
    判定排除 .safecode/ 路径，仅反映真正的业务改动。
    """
    head = sc.repo_head(cwd)
    branch = sc.current_branch(cwd)
    status = sc.run_git(["status", "--porcelain", "-uall"], cwd=cwd)
    dirty = False
    if status.returncode == 0:
        for line in status.stdout.splitlines():
            if len(line) < 4:
                continue
            tail = line[3:].replace("\\", "/")
            if tail.startswith(".safecode/") or "/.safecode/" in tail:
                continue
            dirty = True
            break
    return f"head={head};branch={branch};dirty={int(dirty)}"


def _normalize_diff(diff: str) -> str:
    """归一化 relevant diff：去掉空白差异（行尾空白、空行），过长截断。

    不做按行排序（排序会改变 diff 语义），保持内容顺序，只消除无关空白噪声，
    保证相同改动得到稳定指纹，同时避免超长 diff 造成指纹不稳定。
    """
    if not diff:
        return ""
    lines = [ln.rstrip() for ln in diff.splitlines()]
    lines = [ln for ln in lines if ln.strip() != ""]
    normalized = "\n".join(lines)
    # 截断，避免超大 diff 造成指纹过长 / 抖动
    if len(normalized) > 65536:
        normalized = normalized[:65536]
    return normalized


# --------------------------------------------------------------------------- #
# Operation Fingerprint
# --------------------------------------------------------------------------- #

def operation_fingerprint(
    *,
    operation: Any,
    target: str = "",
    relevant_diff: str = "",
    cwd: Optional[str] = None,
    repo: Optional[str] = None,
) -> str:
    """计算稳定、可复现的操作指纹。

        SHA-256(
            normalized_operation
            + repository_identity
            + repository_state
            + target
            + relevant_diff)

    repo 显式传入时优先使用，否则按 cwd 解析，保证指纹与仓库绑定。
    """
    norm_op = normalize_operation(operation)
    if repo is None:
        repo = sc.repo_identity(cwd)
    state = _stable_repo_state(cwd)
    diff = _normalize_diff(relevant_diff)
    material = "\n".join([
        "operation=" + norm_op,
        "repo=" + (repo or ""),
        "state=" + state,
        "target=" + (target or ""),
        "diff=" + diff,
    ])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return "sha256:" + digest


# --------------------------------------------------------------------------- #
# 时间辅助
# --------------------------------------------------------------------------- #

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# 持久化：一次性 nonce 核销记录
# --------------------------------------------------------------------------- #

APPROVALS_DIR = os.path.join(".safecode", "approvals")
SCHEMA_VERSION = "1.0"
TOKEN_TYPE = "APPROVAL"


def approval_record_path(nonce: str, cwd: Optional[str] = None) -> str:
    """返回某个 nonce 的核销记录路径（.safecode/approvals/<nonce>.json）。"""
    root = sc.repo_root(cwd) or (cwd or os.getcwd())
    return os.path.join(root, APPROVALS_DIR, f"{nonce}.json")


def _write_record(nonce: str, record: Dict[str, Any], cwd: Optional[str] = None) -> None:
    path = approval_record_path(nonce, cwd)
    sc.write_json_file(path, record)


def _read_record(nonce: str, cwd: Optional[str] = None) -> Optional[Dict[str, Any]]:
    path = approval_record_path(nonce, cwd)
    if not os.path.isfile(path):
        return None
    try:
        return sc.read_json_file(path)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# 结构化授权请求
# --------------------------------------------------------------------------- #

def build_authorization_request(
    code: str,
    operation: Any,
    *,
    severity: str,
    risk_level: str,
    target: str = "",
    cwd: Optional[str] = None,
    ttl_minutes: int = 10,
) -> Dict[str, Any]:
    """构造结构化授权请求（PASS + REQUIRE_APPROVAL）。

    这是 Hard Stop 的输出：检查程序正常完成，但策略要求人工授权。
    metadata 含 operation_fingerprint 与"如何返回 token"的说明。
    """
    fp = operation_fingerprint(operation=operation, target=target, cwd=cwd)
    return {
        "schema_version": sc.SCHEMA_VERSION,
        "status": sc.STATUS_PASS,
        "decision": sc.DECISION_REQUIRE_APPROVAL,
        "severity": severity,
        "category": sc.CATEGORY_GIT,
        "code": code,
        "message": (
            f"高风险操作需要人工授权：{normalize_operation(operation)}"
        ),
        "locations": [],
        "metadata": {
            "hard_stop": True,
            "risk_level": risk_level,
            "non_blocking": True,  # 不阻塞等待 stdin，交由 Host 处理授权
            "operation": normalize_operation(operation),
            "operation_fingerprint": fp,
            "target": target or "",
            "ttl_minutes": ttl_minutes,
            "how_to_approve": (
                "宿主在获得人工批准后，应调用 safecode_approval.issue_token(operation, ...) "
                "生成一次性 Approval Token，并通过 SAFECODE_APPROVAL_TOKEN（文件路径或 JSON）"
                "或 git-guard approve --token <file|-> 回传。SafeCode 随后停止后的重新执行由 "
                "Host / Runtime 决定，SafeCode 不阻塞等待 stdin。"
            ),
        },
    }


# --------------------------------------------------------------------------- #
# 签发 / 校验 / 核销
# --------------------------------------------------------------------------- #

def issue_token(
    operation: Any,
    *,
    approved_by: str = "human",
    ttl_minutes: int = 10,
    target: str = "",
    relevant_diff: str = "",
    cwd: Optional[str] = None,
) -> Dict[str, Any]:
    """签发一次性 Approval Token 并持久化核销记录。

    字段：schema_version / token_type="APPROVAL" / operation / operation_fingerprint /
    approved_by / issued_at / expires_at / nonce / target / repository_identity。
    同一 token 仅可使用一次（consume_token 标记已用）。
    """
    repo = sc.repo_identity(cwd)
    fp = operation_fingerprint(
        operation=operation, target=target, relevant_diff=relevant_diff, cwd=cwd, repo=repo
    )
    now = _utcnow()
    expires = now + timedelta(minutes=max(0, int(ttl_minutes)))
    nonce = secrets.token_hex(16)
    token: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "token_type": TOKEN_TYPE,
        "operation": normalize_operation(operation),
        "operation_fingerprint": fp,
        "approved_by": approved_by,
        "issued_at": _iso(now),
        "expires_at": _iso(expires),
        "nonce": nonce,
        "target": target or "",
        "repository_identity": repo,
    }
    record = dict(token)
    record["consumed"] = False
    _write_record(nonce, record, cwd)
    return token


def _load_token(token: Any) -> Dict[str, Any]:
    """token 可以是 dict，或 JSON 字符串，或指向 JSON 文件的路径。"""
    if isinstance(token, dict):
        return token
    if isinstance(token, str):
        raw = token.strip()
        if not raw:
            raise ApprovalError(TOKEN_INVALID, "empty token")
        if os.path.isfile(raw):
            try:
                return sc.read_json_file(raw)
            except Exception as exc:
                raise ApprovalError(TOKEN_INVALID, f"cannot read token file: {exc}") from exc
        try:
            return json.loads(raw)
        except Exception as exc:
            raise ApprovalError(TOKEN_INVALID, f"token is not valid JSON: {exc}") from exc
    raise ApprovalError(TOKEN_INVALID, "token must be dict / JSON string / file path")


def verify_token(
    token: Any,
    *,
    operation: Any,
    target: str = "",
    relevant_diff: str = "",
    cwd: Optional[str] = None,
) -> Dict[str, Any]:
    """校验 token 是否可授权当前操作。

    校验顺序：token_type / 必填字段 / 过期 / nonce 已用 / operation / 仓库 / fingerprint。
    任一不符抛 ApprovalError（code 说明具体原因）。成功返回 token dict。
    """
    data = _load_token(token)
    if not isinstance(data, dict):
        raise ApprovalError(TOKEN_INVALID, "token must be a JSON object")

    if data.get("token_type") != TOKEN_TYPE:
        raise ApprovalError(
            TOKEN_INVALID, f"unexpected token_type: {data.get('token_type')!r}"
        )

    required = ("operation", "operation_fingerprint", "nonce", "issued_at", "expires_at")
    for field in required:
        if field not in data:
            raise ApprovalError(TOKEN_INVALID, f"token missing required field: {field}")

    # 过期
    try:
        expires = _parse_iso(data["expires_at"])
    except Exception as exc:
        raise ApprovalError(TOKEN_INVALID, f"invalid expires_at: {exc}") from exc
    if _utcnow() > expires:
        raise ApprovalError(
            TOKEN_EXPIRED,
            f"token expired at {data['expires_at']}",
        )

    # operation 不匹配
    norm_op = normalize_operation(operation)
    if data.get("operation") != norm_op:
        raise ApprovalError(
            TOKEN_OPERATION_MISMATCH,
            f"token operation {data.get('operation')!r} != current {norm_op!r}",
        )

    # 仓库绑定（直接用 token 中记录的 repository_identity 比较，无需依赖磁盘记录，
    # 这样跨仓库使用会被明确识别为 TOKEN_REPO_MISMATCH 而非 TOKEN_INVALID）
    cur_repo = sc.repo_identity(cwd)
    token_repo = data.get("repository_identity")
    if token_repo and cur_repo and token_repo != cur_repo:
        raise ApprovalError(
            TOKEN_REPO_MISMATCH,
            f"token repository {token_repo!r} != current {cur_repo!r}",
        )

    # nonce 已用（replay 防护）——以磁盘核销记录为准
    nonce = data["nonce"]
    record = _read_record(nonce, cwd)
    if record is None:
        raise ApprovalError(
            TOKEN_INVALID, "token nonce not found in persisted approvals (not issued here)"
        )
    if record.get("consumed"):
        raise ApprovalError(
            TOKEN_REPLAYED, f"token nonce already consumed: {nonce}"
        )

    # fingerprint 绑定（target / relevant_diff / state 变化都会触发）
    cur_fp = operation_fingerprint(
        operation=operation, target=target, relevant_diff=relevant_diff, cwd=cwd
    )
    if data.get("operation_fingerprint") != cur_fp:
        raise ApprovalError(
            TOKEN_FINGERPRINT_MISMATCH,
            "operation_fingerprint changed: operation/target/diff/repository mismatch",
        )

    return data


def consume_token(
    token: Any,
    *,
    operation: Any,
    target: str = "",
    relevant_diff: str = "",
    cwd: Optional[str] = None,
) -> Dict[str, Any]:
    """校验通过后把 nonce 标记为已用（原子写）。

    同一 token 第二次使用必须被拒（verify_token 会命中 consumed 记录 -> TOKEN_REPLAYED）。
    """
    data = verify_token(
        token, operation=operation, target=target, relevant_diff=relevant_diff, cwd=cwd
    )
    nonce = data["nonce"]
    record = _read_record(nonce, cwd)
    if record is None:
        raise ApprovalError(TOKEN_INVALID, "token nonce record missing")
    if record.get("consumed"):
        raise ApprovalError(TOKEN_REPLAYED, f"token nonce already consumed: {nonce}")
    record["consumed"] = True
    record["consumed_at"] = _iso(_utcnow())
    _write_record(nonce, record, cwd)
    return data


# --------------------------------------------------------------------------- #
# 可选 CLI（供子进程调用 / 调试；主用途是 import）
# --------------------------------------------------------------------------- #

def _cli_issue(args: argparse.Namespace) -> int:
    token = issue_token(
        args.operation,
        approved_by=args.approved_by,
        ttl_minutes=args.ttl,
        target=args.target or "",
        cwd=args.cwd,
    )
    reporter = sc.Reporter(json_only=True)
    reporter.emit_json(token)
    return sc.EXIT_OK


def _cli_verify(args: argparse.Namespace) -> int:
    reporter = sc.Reporter(json_only=True)
    try:
        data = verify_token(
            args.token,
            operation=args.operation,
            target=args.target or "",
            cwd=args.cwd,
        )
    except ApprovalError as exc:
        result = sc.fail_deny_result(
            exc.code, f"token rejected: {exc.message}",
            category=sc.CATEGORY_GIT,
        )
        reporter.emit_result(result, exit_code=sc.EXIT_FINDING)
        return sc.EXIT_FINDING
    result = sc.pass_result(
        "TOKEN_VALID", "approval token valid",
        category=sc.CATEGORY_GIT,
        metadata={"nonce": data.get("nonce"), "approved_by": data.get("approved_by")},
    )
    reporter.emit_result(result, exit_code=sc.EXIT_OK)
    return sc.EXIT_OK


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(prog="safecode_approval.py", description="SafeCode Approval Token")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_issue = sub.add_parser("issue", help="签发一次性 Approval Token")
    sc.add_common_arguments(p_issue)
    p_issue.add_argument("--operation", required=True)
    p_issue.add_argument("--target", default="")
    p_issue.add_argument("--ttl", type=int, default=10)
    p_issue.add_argument("--approved-by", default="human")

    p_verify = sub.add_parser("verify", help="校验 Approval Token")
    sc.add_common_arguments(p_verify)
    p_verify.add_argument("--token", required=True, help="token 文件路径 / JSON / -")
    p_verify.add_argument("--operation", required=True)
    p_verify.add_argument("--target", default="")

    args = parser.parse_args(argv)
    if args.cmd == "issue":
        return _cli_issue(args)
    if args.cmd == "verify":
        return _cli_verify(args)
    parser.error("unknown command")
    return sc.EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
