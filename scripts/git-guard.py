#!/usr/bin/env python3
"""SafeCode Agent — Git 门禁 CLI（覆盖旧实现）。

模式 / 子命令：

  --pre-push
      读取 git pre-push hook 的 stdin（每行 "local_ref local_sha remote_ref remote_sha"，
      允许空行与 EOF 结束），逐项检查：
        * 删除远程分支（local_sha 全零）-> 拒绝
        * 强推：remote_sha 非全零 且 git merge-base --is-ancestor 失败 -> 拒绝（L6 授权）
        * merge-base 执行失败 -> 按 L6 处理（不确定 = 不安全）
        * 推送到受保护分支（配置 protected_branches，默认 main/master）
          -> 除非 SAFECODE_ALLOW_MAIN=1 否则拒绝
        * 影响范围过大（--max-changed-files 默认 500 / --max-deleted-files 默认 50）
          -> L6 请求授权

  --check-diff
      扫 git diff --cached -U0 新增行 + 已暂存新增文件中的危险内容：
        git push --force / git reset --hard / filter-branch|filter-repo / git rebase -i /
        rm -rf 作用于仓库根或大范围 / DROP DATABASE / TRUNCATE TABLE /
        绑定 0.0.0.0 暴露服务 / 上传私密数据（*.sqlite/*.db/*.pem/大文件）/
        修改生产环境路径（prod/production/deploy 等）。

  --preflight --command "git push --force origin main"
      高危命令预检（Hard Stop 主入口）。命中即输出结构化授权请求（REQUIRE_APPROVAL），
      未命中 -> PASS + ALLOW。Hard Stop 不阻塞等待 stdin。

  --status
      输出 branch / git status / staged diff 摘要 / unstaged / untracked /
      recent commits / outgoing push content 的检查结果（信息性，PASS + ALLOW）。

  approve --token <file|->
      校验 + 核销 Approval Token；也接受环境变量 SAFECODE_APPROVAL_TOKEN。

契约要点：
  - stdout 只放一个 Structured JSON；人类日志走 stderr（--json 静默）。
  - 退出码：拒绝 / 需要授权 -> 1；参数错误 -> 2；git 不可用等环境问题 -> 4；通过 -> 0。
  - --no-verify 出现在被检查命令中 -> 视为绕过事件，写入 .safecode/events.jsonl 并拒绝，
    不得当作"安全流程通过"。
  - 与 Authorized 操作联动：检测到需要授权的操作时，若提供了匹配当前 operation_fingerprint
    的有效 token（SAFECODE_APPROVAL_TOKEN），则放行并记录 token nonce / approved_by；否则
    REQUIRE_APPROVAL 并停止。

纯标准库，跨平台。Python >= 3.10。
"""

from __future__ import annotations

import os
import re
import sys

# 契约要求：CLI 脚本顶部先把自身目录加入 sys.path，再 import 共享内核。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import json

import safecode_common as sc
import safecode_config as sc_config
import safecode_approval as sa

ZERO_SHA = "0" * 40

# 默认受保护分支（配置优先）
DEFAULT_PROTECTED_BRANCHES = ("main", "master")

# --------------------------------------------------------------------------- #
# 风险等级 / 结果代码
# --------------------------------------------------------------------------- #

SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _max_severity(sevs):
    best = "LOW"
    for s in sevs:
        if SEV_RANK.get(s, 0) > SEV_RANK.get(best, 0):
            best = s
    return best


# --check-diff 危险内容模式（扫描暂存区新增行）
_CHECK_DIFF_PATTERNS = [
    ("GIT_FORCE_PUSH", re.compile(r"git\s+push\s+(?:--force\b|--force-with-lease\b|-f\b|.*\s--force\b)"), "HIGH"),
    ("GIT_RESET_HARD", re.compile(r"git\s+reset\s+(?:--hard|-[a-zA-Z]*h\b)"), "HIGH"),
    ("GIT_HISTORY_REWRITE", re.compile(r"git\s+filter-(?:branch|repo)\b"), "HIGH"),
    ("GIT_REBASE_INTERACTIVE", re.compile(r"git\s+rebase\b[^\n]*?-i\b"), "HIGH"),
    ("IRREVERSIBLE_DELETE", re.compile(r"\brm\s+-[a-zA-Z]*rf\b\s+(?:\.|/|\S*\*)"), "HIGH"),
    ("DATA_DROP", re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE), "CRITICAL"),
    ("DATA_TRUNCATE", re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE), "CRITICAL"),
    ("PUBLIC_EXPOSURE", re.compile(r"(?:host|bind|listen|addr)\s*[=:]\s*[\"']?0\.0\.0\.0\b|0\.0\.0\.0:\d+"), "HIGH"),
]

# 私密数据扩展名（已暂存新增文件）
_PRIVATE_DATA_EXT = {".sqlite", ".db", ".pem", ".key", ".p12", ".pfx", ".env"}

# 生产环境路径启发式
_PROD_PATH_RE = re.compile(r"(?:^|/)(?:prod|production|deploy|staging|live)(?:/|$)", re.IGNORECASE)

# --preflight 高危命令分类（第一个命中即采用）
_PREFLIGHT_RULES = [
    ("FORCE_PUSH", re.compile(r"git\s+push\b[^\n]*?(?:--force\b|--force-with-lease\b|-f\b)"), "CRITICAL", sc.L6),
    ("GIT_RESET_HARD", re.compile(r"git\s+reset\s+(?:--hard|-[a-zA-Z]*h\b)"), "HIGH", sc.L6),
    ("GIT_HISTORY_REWRITE", re.compile(r"git\s+filter-(?:branch|repo)\b"), "HIGH", sc.L6),
    ("GIT_REBASE_INTERACTIVE", re.compile(r"git\s+rebase\b[^\n]*?-i\b"), "HIGH", sc.L6),
    ("IRREVERSIBLE_DELETE", re.compile(r"\brm\s+-[a-zA-Z]*rf\b\s+(?:\.|/|\S*\*)"), "HIGH", sc.L6),
    ("DATA_DROP", re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE), "CRITICAL", sc.L6),
    ("DATA_TRUNCATE", re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE), "CRITICAL", sc.L6),
    ("PUBLIC_EXPOSURE", re.compile(r"(?:host|bind|listen|addr)\s*[=:]\s*[\"']?0\.0\.0\.0\b|0\.0\.0\.0:\d+"), "HIGH", sc.L6),
]

_NO_VERIFY_RE = re.compile(r"--no-verify\b")


# --------------------------------------------------------------------------- #
# 绕过事件记录
# --------------------------------------------------------------------------- #

def _record_bypass_event(command: str, fingerprint: str, cwd: str | None) -> None:
    """把 --no-verify 等绕过尝试写入 .safecode/events.jsonl（时间 / 命令 / 操作指纹）。"""
    root = sc.repo_root(cwd) or (cwd or os.getcwd())
    events_path = os.path.join(root, ".safecode", "events.jsonl")
    os.makedirs(os.path.dirname(events_path), exist_ok=True)
    entry = {
        "time": sc.now_utc_iso(),
        "event": "bypass_attempt",
        "command": command,
        "operation_fingerprint": fingerprint,
    }
    try:
        with open(events_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# git 辅助（只读）
# --------------------------------------------------------------------------- #

def _parse_added_lines(cwd):
    """返回 [(file, line_no, text), ...] 来自 git diff --cached -U0 的新增行。"""
    proc = sc.run_git(["diff", "--cached", "-U0", "--no-color"], cwd=cwd)
    if proc.returncode != 0 or not proc.stdout:
        return []
    out = []
    cur_file = None
    new_lineno = 0
    in_hunk = False
    for line in proc.stdout.split("\n"):
        if line.startswith("diff --git"):
            in_hunk = False
            m = re.search(r" b/(.+)$", line)
            cur_file = m.group(1) if m else None
        elif line.startswith("@@"):
            in_hunk = True
            m = re.search(r"\+(\d+)", line)
            new_lineno = int(m.group(1)) if m else 0
        elif in_hunk and line.startswith("+") and not line.startswith("+++"):
            out.append((cur_file, new_lineno, line[1:]))
            new_lineno += 1
        elif in_hunk and line.startswith(" "):
            new_lineno += 1
    return out


def _staged_new_files(cwd):
    proc = sc.run_git(["diff", "--cached", "--name-only", "--diff-filter=A", "--no-color"], cwd=cwd)
    if proc.returncode != 0:
        return []
    return [l for l in proc.stdout.splitlines() if l.strip()]


def _staged_files(cwd):
    proc = sc.run_git(["diff", "--cached", "--name-only", "--no-color"], cwd=cwd)
    if proc.returncode != 0:
        return []
    return [l for l in proc.stdout.splitlines() if l.strip()]


def _protected_branches(cwd):
    try:
        cfg = sc_config.load_config(cwd=cwd)
        branches = cfg.protected_branches
        if branches:
            return list(branches)
    except sc_config.ConfigError:
        pass
    return list(DEFAULT_PROTECTED_BRANCHES)


# --------------------------------------------------------------------------- #
# 模式实现
# --------------------------------------------------------------------------- #

def cmd_check_diff(reporter, cwd) -> int:
    findings = []

    for fname, lineno, text in _parse_added_lines(cwd):
        # 绕过检测
        if _NO_VERIFY_RE.search(text):
            fp = sa.operation_fingerprint(operation=text, cwd=cwd)
            _record_bypass_event(text, fp, cwd)
            findings.append({
                "code": "BYPASS_NO_VERIFY",
                "severity": "HIGH",
                "file": fname,
                "line": lineno,
                "snippet": text,
            })
            continue
        for code, pat, sev in _CHECK_DIFF_PATTERNS:
            if pat.search(text):
                findings.append({
                    "code": code,
                    "severity": sev,
                    "file": fname,
                    "line": lineno,
                    "snippet": text,
                })
                break

    for fname in _staged_new_files(cwd):
        ext = os.path.splitext(fname)[1].lower()
        if ext in _PRIVATE_DATA_EXT:
            findings.append({
                "code": "PRIVATE_DATA_UPLOAD",
                "severity": "CRITICAL",
                "file": fname,
                "line": None,
                "snippet": f"staged new file with sensitive extension: {fname}",
            })

    for fname in _staged_files(cwd):
        if _PROD_PATH_RE.search(fname):
            findings.append({
                "code": "PROD_MODIFICATION",
                "severity": "HIGH",
                "file": fname,
                "line": None,
                "snippet": f"staged change under production-like path: {fname}",
            })

    if not findings:
        result = sc.pass_result(
            "CHECK_DIFF_OK", "staged changes contain no dangerous operations",
            category=sc.CATEGORY_GIT,
        )
        return _emit(reporter, result)

    sev = _max_severity([f["severity"] for f in findings])
    code = findings[0]["code"]
    locations = []
    for f in findings:
        loc = {"file": f["file"]} if f["file"] else {"file": "<staged>"}
        if f.get("line"):
            loc["line"] = f["line"]
        locations.append(loc)
    result = sc.fail_deny_result(
        code,
        f"staged changes contain dangerous operation(s): {code}",
        severity=sev,
        category=sc.CATEGORY_GIT,
        locations=locations,
        metadata={
            "findings": [
                {k: f[k] for k in ("code", "severity", "file", "line") if f.get(k) is not None}
                for f in findings
            ],
            "count": len(findings),
            "note": "dangerous content in staged changes is a policy finding (fail-closed); remove it before staging.",
        },
    )
    return _emit(reporter, result)


def _classify_command(command):
    """返回 (code, severity, risk_level) 或 None。"""
    for code, pat, sev, level in _PREFLIGHT_RULES:
        if pat.search(command):
            return code, sev, level
    return None


def _try_authorize(operation, target, relevant_diff, cwd):
    """尝试用 SAFECODE_APPROVAL_TOKEN 授权当前操作。

    返回：
      ("authorized", token_dict)             -> 已核销，可放行
      ("rejected", (code, message))          -> token 已提供但 replay/expired/invalid -> 明确 DENY
      ("unauthorized", None)                 -> 未提供 token 或 token 与本操作不匹配 -> 走 REQUIRE_APPROVAL
    """
    env_val = os.environ.get("SAFECODE_APPROVAL_TOKEN")
    if not env_val:
        return ("unauthorized", None)
    try:
        token = sa.consume_token(
            env_val, operation=operation, target=target, relevant_diff=relevant_diff, cwd=cwd
        )
        return ("authorized", token)
    except sa.ApprovalError as exc:
        if exc.code in (sa.TOKEN_REPLAYED, sa.TOKEN_EXPIRED, sa.TOKEN_INVALID):
            return ("rejected", (exc.code, exc.message))
        # 操作 / 指纹 / 仓库不匹配 -> 该 token 不能授权本操作，按"需要授权"处理
        return ("unauthorized", None)


def cmd_preflight(reporter, command, cwd) -> int:
    norm_command = sa.normalize_operation(command)
    fp = sa.operation_fingerprint(operation=command, cwd=cwd)

    # 绕过检测优先
    if _NO_VERIFY_RE.search(command):
        _record_bypass_event(command, fp, cwd)
        result = sc.fail_deny_result(
            "BYPASS_NO_VERIFY",
            "git push --no-verify is a hook bypass and must not be treated as a safe pass",
            severity=sc.SEVERITY_HIGH,
            category=sc.CATEGORY_GIT,
            metadata={"command": norm_command, "operation_fingerprint": fp},
        )
        return _emit(reporter, result)

    classified = _classify_command(command)
    if classified is None:
        result = sc.pass_result(
            "PREFLIGHT_OK", "command is not a recognized high-risk operation",
            category=sc.CATEGORY_GIT,
            metadata={"command": norm_command},
        )
        return _emit(reporter, result)

    code, sev, level = classified
    # 尝试用有效 token 授权
    status, payload = _try_authorize(command, target="", relevant_diff="", cwd=cwd)
    if status == "authorized":
        result = sc.pass_result(
            code,
            f"high-risk operation authorized by approval token: {norm_command}",
            severity=sev,
            category=sc.CATEGORY_GIT,
            metadata={
                "authorized": True,
                "token_nonce": payload.get("nonce"),
                "approved_by": payload.get("approved_by"),
                "operation": norm_command,
                "operation_fingerprint": fp,
            },
        )
        return _emit(reporter, result)
    if status == "rejected":
        rcode, rmsg = payload
        result = sc.fail_deny_result(
            rcode, f"approval token rejected: {rmsg}",
            severity=sev, category=sc.CATEGORY_GIT,
            metadata={"operation": norm_command, "operation_fingerprint": fp},
        )
        return _emit(reporter, result)

    req = sa.build_authorization_request(
        code, command, severity=sev, risk_level=level, cwd=cwd, ttl_minutes=10
    )
    # 转为 Result 输出（保持结构化授权请求语义）
    result = sc.Result.from_dict(req)
    return _emit(reporter, result)


def cmd_pre_push(reporter, stdin_text, cwd, max_changed, max_deleted) -> int:
    protected = _protected_branches(cwd)

    hard_reasons = []   # FAIL + DENY
    soft_reasons = []   # REQUIRE_APPROVAL（可授权）
    hard_meta = []
    soft_meta = []

    for raw_line in stdin_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local_ref, local_sha, remote_ref, remote_sha = parts[0], parts[1], parts[2], parts[3]

        # 删除远程分支
        if local_sha == ZERO_SHA:
            hard_reasons.append("BRANCH_DELETE_REJECTED")
            hard_meta.append(f"refusing to delete remote branch: {remote_ref} (local_sha is zero)")
            continue

        # 受保护分支
        if "refs/heads/" in remote_ref:
            branch = remote_ref.split("refs/heads/", 1)[1]
        else:
            branch = remote_ref
        if branch in protected:
            allow_main = os.environ.get("SAFECODE_ALLOW_MAIN", "") == "1"
            if branch in ("main", "master") and allow_main:
                pass
            else:
                hard_reasons.append("PROTECTED_BRANCH_REJECTED")
                hard_meta.append(
                    f"refusing push to protected branch {remote_ref} "
                    f"(set SAFECODE_ALLOW_MAIN=1 only to override main/master after human review)"
                )
                continue

        # 非全零 remote_sha：检查强推 / 影响范围
        if remote_sha != ZERO_SHA:
            mb = sc.run_git(["merge-base", "--is-ancestor", remote_sha, local_sha], cwd=cwd)
            if mb.returncode != 0:
                if mb.returncode in (127, 124) or "not found" in mb.stderr.lower():
                    # git 不可用 / 超时 -> 不确定 = L6
                    soft_reasons.append("MERGE_BASE_ERROR")
                    soft_meta.append(
                        f"cannot determine ancestry for {remote_ref} (merge-base unavailable) -> treat as unsafe"
                    )
                else:
                    soft_reasons.append("FORCE_PUSH")
                    soft_meta.append(
                        f"refusing force push: {remote_ref} (remote_sha not ancestor of local_sha)"
                    )
            # 影响范围
            if remote_sha != ZERO_SHA and local_sha != ZERO_SHA:
                diff_proc = sc.run_git(
                    ["diff", "--name-only", remote_sha, local_sha], cwd=cwd, timeout=30
                )
                if diff_proc.returncode == 0:
                    changed = [l for l in diff_proc.stdout.splitlines() if l.strip()]
                    if len(changed) > max_changed:
                        soft_reasons.append("OVERSCOPE_PUSH")
                        soft_meta.append(
                            f"push affects {len(changed)} files (> max {max_changed}) -> require approval"
                        )
                    del_proc = sc.run_git(
                        ["diff", "--diff-filter=D", "--name-only", remote_sha, local_sha],
                        cwd=cwd, timeout=30,
                    )
                    if del_proc.returncode == 0:
                        deleted = [l for l in del_proc.stdout.splitlines() if l.strip()]
                        if len(deleted) > max_deleted:
                            soft_reasons.append("OVERSCOPE_DELETE")
                            soft_meta.append(
                                f"push deletes {len(deleted)} files (> max {max_deleted}) -> require approval"
                            )

    # 硬拒绝优先
    if hard_reasons:
        code = hard_reasons[0]
        result = sc.fail_deny_result(
            code,
            "; ".join(hard_meta),
            severity=sc.SEVERITY_HIGH,
            category=sc.CATEGORY_GIT,
            metadata={"reasons": hard_meta, "fingerprint_required": False},
        )
        return _emit(reporter, result)

    if soft_reasons:
        # 尝试用 token 授权（operation 绑定到本次 push）
        operation = sa.normalize_operation(stdin_text) or "git push"
        status, payload = _try_authorize(operation, target="", relevant_diff="", cwd=cwd)
        if status == "authorized":
            result = sc.pass_result(
                soft_reasons[0],
                f"pre-push risk authorized by approval token: {'; '.join(soft_meta)}",
                severity=sc.SEVERITY_HIGH,
                category=sc.CATEGORY_GIT,
                metadata={
                    "authorized": True,
                    "token_nonce": payload.get("nonce"),
                    "approved_by": payload.get("approved_by"),
                    "reasons": soft_meta,
                },
            )
            return _emit(reporter, result)
        if status == "rejected":
            rcode, rmsg = payload
            result = sc.fail_deny_result(
                rcode, f"approval token rejected: {rmsg}",
                severity=sc.SEVERITY_HIGH, category=sc.CATEGORY_GIT,
                metadata={"reasons": soft_meta},
            )
            return _emit(reporter, result)
        req = sa.build_authorization_request(
            soft_reasons[0], operation,
            severity=sc.SEVERITY_HIGH, risk_level=sc.L6, cwd=cwd, ttl_minutes=10,
        )
        req["metadata"]["reasons"] = soft_meta
        req["message"] = "; ".join(soft_meta)
        result = sc.Result.from_dict(req)
        return _emit(reporter, result)

    result = sc.pass_result(
        "PRE_PUSH_OK", "pre-push checks passed",
        category=sc.CATEGORY_GIT,
    )
    return _emit(reporter, result)


def cmd_status(reporter, cwd) -> int:
    summary = {}

    branch = sc.current_branch(cwd)
    summary["branch"] = branch

    status = sc.run_git(["status", "--porcelain"], cwd=cwd)
    if status.returncode != 0:
        result = sc.env_error_result("GIT_UNAVAILABLE", "cannot read git status")
        return _emit(reporter, result)
    porcelain = status.stdout.splitlines()
    summary["staged"] = [l for l in porcelain if l[:1] in ("M", "A", "D", "R", "C", "U")]
    summary["unstaged"] = [l for l in porcelain if len(l) >= 2 and l[1:2] in ("M", "D", "U") and l[:1] == " "]
    summary["untracked"] = [l for l in porcelain if l.startswith("??")]

    diff_names = sc.run_git(["diff", "--cached", "--name-only", "--no-color"], cwd=cwd)
    summary["staged_diff"] = [l for l in diff_names.stdout.splitlines() if l.strip()] if diff_names.returncode == 0 else []

    commits = sc.run_git(["log", "--oneline", "-5"], cwd=cwd)
    summary["recent_commits"] = [l for l in commits.stdout.splitlines() if l.strip()] if commits.returncode == 0 else []

    outgoing = sc.run_git(["log", "--oneline", "@{upstream}..HEAD"], cwd=cwd, timeout=30)
    if outgoing.returncode == 0:
        summary["outgoing_push"] = [l for l in outgoing.stdout.splitlines() if l.strip()]
    else:
        summary["outgoing_push"] = []
        summary["outgoing_push_note"] = "no upstream configured or upstream unavailable"

    result = sc.pass_result(
        "STATUS_OK", "repository status collected",
        category=sc.CATEGORY_GIT,
        metadata=summary,
    )
    return _emit(reporter, result)


def _resolve_token_source(token_arg):
    """--token 值：文件路径或 JSON；- 表示读 SAFECODE_APPROVAL_TOKEN 或 stdin。"""
    if token_arg and token_arg != "-":
        return token_arg
    env_val = os.environ.get("SAFECODE_APPROVAL_TOKEN")
    if env_val:
        return env_val
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def cmd_approve(reporter, token_arg, cwd) -> int:
    src = _resolve_token_source(token_arg)
    if not src or not src.strip():
        result = sc.usage_error_result("TOKEN_MISSING", "no approval token provided (--token / - / SAFECODE_APPROVAL_TOKEN)")
        return _emit(reporter, result)
    try:
        token = sa._load_token(src)
    except sa.ApprovalError as exc:
        result = sc.fail_deny_result(exc.code, f"invalid token: {exc.message}", category=sc.CATEGORY_GIT)
        return _emit(reporter, result)

    operation = token.get("operation", "")
    target = token.get("target", "")
    try:
        data = sa.consume_token(token, operation=operation, target=target, cwd=cwd)
    except sa.ApprovalError as exc:
        result = sc.fail_deny_result(
            exc.code, f"approval token rejected: {exc.message}",
            category=sc.CATEGORY_GIT,
            metadata={"operation": operation},
        )
        return _emit(reporter, result)

    result = sc.pass_result(
        "TOKEN_CONSUMED", "approval token verified and consumed",
        category=sc.CATEGORY_GIT,
        metadata={
            "token_nonce": data.get("nonce"),
            "approved_by": data.get("approved_by"),
            "operation": operation,
            "operation_fingerprint": data.get("operation_fingerprint"),
        },
    )
    return _emit(reporter, result)


# --------------------------------------------------------------------------- #
# 输出 / 退出码
# --------------------------------------------------------------------------- #

def _emit(reporter, result):
    code = sc.exit_code_for(result)
    reporter.emit_result(result, exit_code=code)
    return code


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser():
    parser = argparse.ArgumentParser(prog="git-guard.py", description="SafeCode Git 安全门禁")
    sc.add_common_arguments(parser)
    parser.add_argument("--cwd", default=None, help="仓库根目录（默认当前工作目录）")
    group = parser.add_argument_group("modes (exactly one required unless using 'approve')")
    group.add_argument("--pre-push", action="store_true", help="读取 pre-push hook stdin 检查强推/分支保护/删除分支/影响范围")
    group.add_argument("--check-diff", action="store_true", help="扫描暂存区危险内容")
    group.add_argument("--preflight", action="store_true", help="高危命令预检（Hard Stop 主入口）")
    group.add_argument("--status", action="store_true", help="输出仓库状态检查摘要（信息性）")
    parser.add_argument("--command", default=None, help="与 --preflight 配合的高危命令")
    parser.add_argument("--max-changed-files", type=int, default=500, help="影响范围过大阈值（变更文件数）")
    parser.add_argument("--max-deleted-files", type=int, default=50, help="影响范围过大阈值（删除文件数）")

    sub = parser.add_subparsers(dest="cmd")
    p_approve = sub.add_parser("approve", help="校验并核销 Approval Token")
    sc.add_common_arguments(p_approve, suppress_defaults=True)
    p_approve.add_argument("--token", default=None, help="token 文件路径 / JSON / -（从 SAFECODE_APPROVAL_TOKEN 或 stdin 读取）")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    reporter = sc.reporter_from_args(args)
    cwd = getattr(args, "cwd", None)

    # 子命令 approve
    if args.cmd == "approve":
        return cmd_approve(reporter, args.token, cwd)

    mode_flags = [args.pre_push, args.check_diff, args.preflight, args.status]
    if sum(1 for f in mode_flags if f) != 1:
        result = sc.usage_error_result(
            "USAGE", "exactly one of --pre-push / --check-diff / --preflight / --status is required"
        )
        return _emit(reporter, result)

    # 这些模式都需要 git 仓库（preflight 不需要，但 preflight 分支已单独处理）
    if args.check_diff or args.pre_push or args.status:
        if not sc.is_git_repo(cwd):
            result = sc.env_error_result("NOT_A_GIT_REPO", "current directory is not a git repository")
            return _emit(reporter, result)

    if args.check_diff:
        return cmd_check_diff(reporter, cwd)
    if args.pre_push:
        stdin_text = ""
        if not sys.stdin.isatty():
            try:
                stdin_text = sys.stdin.read()
            except Exception:
                stdin_text = ""
        return cmd_pre_push(reporter, stdin_text, cwd, args.max_changed_files, args.max_deleted_files)
    if args.preflight:
        if not args.command:
            result = sc.usage_error_result("USAGE", "--preflight requires --command")
            return _emit(reporter, result)
        return cmd_preflight(reporter, args.command, cwd)
    if args.status:
        return cmd_status(reporter, cwd)

    result = sc.usage_error_result("USAGE", "no mode selected")
    return _emit(reporter, result)


if __name__ == "__main__":
    sys.exit(main())
