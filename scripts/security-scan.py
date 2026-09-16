#!/usr/bin/env python3
"""SafeCode Agent — Security Gate（Secret Scanner + Security Gate）。

覆盖旧实现。职责：

1. 读取项目配置（Fail-Closed：配置错误 → exit 2 + DENY）。
2. 打开 Baseline（损坏 / 无效 → DENY + exit 1，绝不放过）。
3. Native 扫描（复用 safecode_secret）：按 scope 取内容
   - staged：git diff --cached -U0 新增行 + 已暂存新增文件
   - worktree：git diff -U0 + 未跟踪文件
   - all / repo：工作区全量（跳过 .git / __pycache__ / node_modules / 二进制 / >1MB）
   - history：git log -p --all --no-color 新增行（记录 commit sha）
4. 敏感文件检查：被跟踪的 .env / .pem / .key / .p12 / .pfx（排除 .example/.sample/.template）。
5. Shallow 检测：存在 .git/shallow 或 is-shallow-repository=true，且 scope 为完整扫描
   （history / repo / all）→ FAIL + DENY + SHALLOW_HISTORY + exit 3；diff 场景允许但
   metadata 标注 incomplete_history=true。
6. 外部 Scanner：按配置调用；不可用 / 全部 ERROR → LOCAL 非 strict 降级 DEGRADED，
   strict / CI 直接 DENY；部分可用部分失败同样 DEGRADED。绝不声称"安全扫描通过"。
7. 结果合并：每个 finding 依次判定 allow_list → baseline（known/expired/new）→ 归类。
   NEW → DENY；known 且未过期 → 放行；expired → DENY(BASELINE_EXPIRED)；同 rule 同 path
   换值 / 换路径 → NEW → DENY。
8. 输出单个 Structured JSON；locations 只放阻断性 finding；metadata 放完整明细。
9. --write-baseline：把当前 findings 写成 baseline 条目（必须 --reason；指纹须齐全）。
10. 退出码：阻断 finding → 1；无法完成检查 → 2/3/4；干净 → 0。

Fail-Closed 是核心：任何 scanner 异常都不得 PASS。

纯 Python 标准库，Windows 与 Linux 都能跑。Python >= 3.10。
"""

from __future__ import annotations

import argparse
import datetime
import os
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from safecode_common import (  # noqa: E402
    CATEGORY_CONFIG,
    CATEGORY_SECURITY,
    DECISION_ALLOW,
    DECISION_DENY,
    EXIT_ENV,
    EXIT_FINDING,
    EXIT_OK,
    EXIT_TOOL,
    EXIT_USAGE,
    MODE_STRICT,
    Reporter,
    add_common_arguments,
    degraded_result,
    fail_deny_result,
    make_result,
    pass_result,
    reporter_from_args,
    repo_root,
    resolve_mode,
    run_git,
    usage_error_result,
)
from safecode_config import ConfigError, load_config  # noqa: E402
from safecode_secret import (  # noqa: E402
    CODE_BASELINE_EXPIRED,
    CODE_BASELINE_INVALID,
    CODE_SECRET_DETECTED,
    FINDING_TYPE_SECRET,
    FINDING_TYPE_SENSITIVE_FILE,
    SOURCE_EXTERNAL,
    SOURCE_NATIVE,
    Baseline,
    BaselineError,
    Finding,
    allow_list_match,
    build_rules,
    default_baseline_path,
    is_ignored_path,
    is_sensitive_file,
    normalize_path,
    scan_line_for_secrets,
    scan_text_for_findings,
    sensitive_file_finding,
    truncate_evidence,
)
from safecode_scanners import discover, run_scanner, unavailable_outcome  # noqa: E402

# --------------------------------------------------------------------------- #
# scope 常量
# --------------------------------------------------------------------------- #
SCOPE_STAGED = "staged"
SCOPE_WORKTREE = "worktree"
SCOPE_ALL = "all"
SCOPE_REPO = "repo"
SCOPE_HISTORY = "history"

FULL_SCAN_SCOPES = (SCOPE_ALL, SCOPE_REPO, SCOPE_HISTORY)

# 结果代码
CODE_SHALLOW_HISTORY = "SHALLOW_HISTORY"
CODE_EXTERNAL_UNAVAILABLE = "EXTERNAL_SCANNER_UNAVAILABLE"
CODE_EXTERNAL_ERROR = "EXTERNAL_SCANNER_ERROR"
CODE_SECRET_SCAN_CLEAN = "SECRET_SCAN_CLEAN"
CODE_BASELINE_WRITTEN = "BASELINE_WRITTEN"
CODE_MISSING_REASON = "MISSING_BASELINE_REASON"
CODE_FINGERPRINT_INCOMPLETE = "BASELINE_FINGERPRINT_INCOMPLETE"

# 扫描时跳过的目录（all / repo 模式）
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".idea", ".vscode"}
_MAX_FILE_BYTES = 1 * 1024 * 1024  # 1 MB

_SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


# --------------------------------------------------------------------------- #
# 读取内容（按 scope）
# --------------------------------------------------------------------------- #

def _git_name_only(args: Sequence[str], cwd: str) -> List[str]:
    proc = run_git(["diff", *args, "--name-only", "--no-color"], cwd=cwd)
    if proc.returncode != 0:
        return []
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def _git_untracked(cwd: str) -> List[str]:
    proc = run_git(["ls-files", "--others", "--exclude-standard"], cwd=cwd)
    if proc.returncode != 0:
        return []
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def _is_excluded_sensitive(path: str) -> bool:
    """敏感文件排除：以 .example / .sample / .template 结尾的不算。"""
    base = os.path.basename(path).lower()
    for suf in (".example", ".sample", ".template"):
        if base == suf or base.endswith(suf):
            return True
    return False


def parse_diff_added_lines(diff_text: str) -> List[Tuple[str, int, str]]:
    """解析 `git diff -U0` 输出，返回 [(file, new_line_no, text), ...]（仅新增行）。"""
    results: List[Tuple[str, int, str]] = []
    cur_file: Optional[str] = None
    new_lineno = 0
    in_hunk = False
    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            in_hunk = False
            m = re.search(r" b/(.+)$", line)
            cur_file = m.group(1) if m else None
        elif line.startswith("@@"):
            in_hunk = True
            m = re.search(r"\+(\d+)", line)
            new_lineno = int(m.group(1)) if m else 0
        elif in_hunk and cur_file:
            if line.startswith("+") and not line.startswith("+++"):
                results.append((cur_file, new_lineno, line[1:]))
                new_lineno += 1
            elif line.startswith(" "):
                new_lineno += 1
    return results


def parse_history_added(output: str) -> List[Tuple[str, str, int, str]]:
    """解析 `git log -p --all` 输出，返回 [(sha, file, new_line_no, text), ...]。

    只统计 diff hunk 内（`@@` 之后）且以 `+` 开头的新增行，避免把提交信息里的
    类似内容误判。
    """
    results: List[Tuple[str, str, int, str]] = []
    cur_sha: Optional[str] = None
    cur_file: Optional[str] = None
    in_hunk = False
    new_lineno = 0
    for line in output.split("\n"):
        if line.startswith("commit "):
            m = re.match(r"^commit ([0-9a-f]{7,40})", line)
            cur_sha = m.group(1) if m else None
            cur_file = None
            in_hunk = False
            continue
        if line.startswith("diff --git"):
            mm = re.search(r" b/(.+)$", line)
            cur_file = mm.group(1) if mm else None
            in_hunk = False
            continue
        if line.startswith("@@"):
            in_hunk = True
            m = re.search(r"\+(\d+)", line)
            new_lineno = int(m.group(1)) if m else 0
            continue
        if in_hunk and cur_file and line.startswith("+"):
            text = line[1:]
            if text:
                results.append((cur_sha or "", cur_file, new_lineno, text))
            new_lineno += 1
        elif in_hunk and line.startswith(" "):
            new_lineno += 1
    return results


def _iter_file_lines(path: str):
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            return
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, raw in enumerate(fh, start=1):
                yield i, raw.rstrip("\n").rstrip("\r")
    except (OSError, UnicodeDecodeError):
        return


def _is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(8192)
        return b"\x00" in chunk
    except OSError:
        return True


def _walk_all(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            yield full, rel.replace("\\", "/")


# --------------------------------------------------------------------------- #
# Native 扫描（按 scope）
# --------------------------------------------------------------------------- #

def _scan_text_lines(lines: Sequence[Tuple[int, str]], path: str, rules, ignore_paths: Sequence[str]) -> List[Finding]:
    findings: List[Finding] = []
    for lineno, text in lines:
        if is_ignored_path(path, ignore_paths):
            continue
        for finding in scan_text_for_findings(text, path, rules, base_line=lineno):
            findings.append(finding)
    return findings


def scan_staged(rules, ignore_paths: Sequence[str], root: str) -> List[Finding]:
    findings: List[Finding] = []
    files = _git_name_only(["--cached"], root)
    for f in files:
        if is_sensitive_file(f) and not _is_excluded_sensitive(f) and not is_ignored_path(f, ignore_paths):
            findings.append(sensitive_file_finding(f))
    proc = run_git(["diff", "--cached", "-U0", "--no-color"], cwd=root)
    if proc.returncode == 0:
        for path, lineno, text in parse_diff_added_lines(proc.stdout):
            findings.extend(_scan_text_lines([(lineno, text)], path, rules, ignore_paths))
    return findings


def scan_worktree(rules, ignore_paths: Sequence[str], root: str) -> List[Finding]:
    findings: List[Finding] = []
    changed = _git_name_only([], root)
    untracked = _git_untracked(root)
    scanned_files = set()
    for f in changed + untracked:
        if is_sensitive_file(f) and not _is_excluded_sensitive(f) and not is_ignored_path(f, ignore_paths):
            findings.append(sensitive_file_finding(f))
    proc = run_git(["diff", "-U0", "--no-color"], cwd=root)
    if proc.returncode == 0:
        for path, lineno, text in parse_diff_added_lines(proc.stdout):
            findings.extend(_scan_text_lines([(lineno, text)], path, rules, ignore_paths))
    for rel in untracked:
        full = os.path.join(root, rel)
        if not os.path.isfile(full) or _is_binary(full):
            continue
        base_findings = _scan_text_lines(list(_iter_file_lines(full)), rel, rules, ignore_paths)
        findings.extend(base_findings)
        scanned_files.add(rel)
    return findings


def scan_all(rules, ignore_paths: Sequence[str], root: str) -> List[Finding]:
    findings: List[Finding] = []
    for full, rel in _walk_all(root):
        if is_ignored_path(rel, ignore_paths):
            continue
        if is_sensitive_file(rel) and not _is_excluded_sensitive(rel):
            findings.append(sensitive_file_finding(rel))
        if _is_binary(full):
            continue
        findings.extend(_scan_text_lines(list(_iter_file_lines(full)), rel, rules, ignore_paths))
    return findings


def scan_history(rules, ignore_paths: Sequence[str], root: str, max_commits: Optional[int]) -> Tuple[List[Finding], bool]:
    findings: List[Finding] = []
    args = ["log", "-p", "--all", "--no-color"]
    if max_commits and max_commits > 0:
        args += ["-n", str(max_commits)]
    proc = run_git(args, cwd=root, timeout=300)
    if proc.returncode != 0:
        return findings, False
    sensitive_seen: set = set()
    for sha, file, lineno, text in parse_history_added(proc.stdout):
        if is_ignored_path(file, ignore_paths):
            continue
        for rule_name, severity, captured in scan_line_for_secrets(text, rules):
            f = Finding(
                rule=rule_name,
                path=file,
                line=lineno,
                severity=severity,
                finding_type=FINDING_TYPE_SECRET,
                evidence=truncate_evidence(text.strip()),
                matched_value=captured,
                source=SOURCE_NATIVE,
            )
            setattr(f, "commit_sha", sha)
            findings.append(f)
        if is_sensitive_file(file) and not _is_excluded_sensitive(file) and file not in sensitive_seen:
            sensitive_seen.add(file)
            sf = sensitive_file_finding(file)
            setattr(sf, "commit_sha", sha)
            findings.append(sf)
    return findings, True


# --------------------------------------------------------------------------- #
# Shallow 检测
# --------------------------------------------------------------------------- #

def detect_shallow(root: str) -> bool:
    gd = run_git(["rev-parse", "--git-dir"], cwd=root).stdout.strip()
    if gd:
        shallow_path = os.path.join(gd if os.path.isabs(gd) else os.path.join(root, gd), "shallow")
        if os.path.isfile(shallow_path):
            return True
    proc = run_git(["rev-parse", "--is-shallow-repository"], cwd=root)
    if proc.returncode == 0 and proc.stdout.strip() == "true":
        return True
    return False


# --------------------------------------------------------------------------- #
# 外部 scanner 调用
# --------------------------------------------------------------------------- #

def run_external_scanners(config, scope: str, root: str, timeout: int,
                          reporter: Reporter) -> Tuple[List[Finding], Dict[str, Any]]:
    """返回 (外部 findings, 各 scanner 汇总)。未启用 / --no-external 时返回空。"""
    if not config.external_scanners_enabled:
        return [], {}
    tools = config.external_scanner_tools
    discovered = discover(tools)
    outcomes: Dict[str, Any] = {}
    findings: List[Finding] = []
    for tool in tools:
        path = discovered.get(tool)
        if not path:
            oc = unavailable_outcome(tool)
        else:
            try:
                oc = run_scanner(tool, path, scope, root, timeout)
            except Exception as exc:  # noqa: BLE001
                reporter.error(f"external scanner {tool} crashed: {exc}")
                oc = unavailable_outcome(tool, message=f"crash: {exc}")
        outcomes[tool] = oc.to_summary()
        findings.extend(oc.findings)
    return findings, outcomes


def external_has_problem(outcomes: Dict[str, Any]) -> bool:
    for oc in outcomes.values():
        if oc.get("available") is False or oc.get("status") == "ERROR" or oc.get("status") == "UNKNOWN":
            return True
    return False


def external_problem_code(outcomes: Dict[str, Any]) -> str:
    for oc in outcomes.values():
        if oc.get("status") == "ERROR":
            return CODE_EXTERNAL_ERROR
    return CODE_EXTERNAL_UNAVAILABLE


# --------------------------------------------------------------------------- #
# 结果判定与归类
# --------------------------------------------------------------------------- #

def classify(findings: List[Finding], allow_list, baseline: Baseline
             ) -> Tuple[List[Finding], List[Dict[str, Any]], Dict[str, int]]:
    blocking: List[Finding] = []
    details: List[Dict[str, Any]] = []
    stats = {"known": 0, "new": 0, "expired": 0, "allowed": 0}

    for f in findings:
        al = allow_list_match(f, allow_list)
        if al:
            classification = "allowed"
            stats["allowed"] += 1
        else:
            bstatus = baseline.status_for(f)
            if bstatus == "known":
                classification = "known"
                stats["known"] += 1
            elif bstatus == "expired":
                classification = "expired"
                stats["expired"] += 1
                blocking.append(f)
            else:  # new
                classification = "new"
                stats["new"] += 1
                blocking.append(f)

        detail = f.to_dict()
        detail["classification"] = classification
        sha = getattr(f, "commit_sha", None)
        if sha:
            detail["commit_sha"] = sha
        details.append(detail)

    return blocking, details, stats


def _max_severity(findings: List[Finding]) -> str:
    best = "LOW"
    for f in findings:
        if _SEVERITY_ORDER.get(f.severity, 0) > _SEVERITY_ORDER.get(best, 0):
            best = f.severity
    return best


# --------------------------------------------------------------------------- #
# 参数解析
# --------------------------------------------------------------------------- #

def resolve_scope(args) -> str:
    if args.staged:
        return SCOPE_STAGED
    if args.worktree:
        return SCOPE_WORKTREE
    if args.all:
        return SCOPE_ALL
    if args.repo:
        return SCOPE_REPO
    if args.history:
        return SCOPE_HISTORY
    return SCOPE_STAGED if repo_root() else SCOPE_ALL


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-scan.py",
        description="SafeCode Secret Scanner + Security Gate",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--staged", action="store_true", help="扫描 git 暂存区（默认，在 git 仓库内）")
    group.add_argument("--worktree", action="store_true", help="扫描 git 工作区改动 + 未跟踪文件")
    group.add_argument("--all", action="store_true", help="扫描工作区全部文件（跳过 .git/node_modules/二进制/>1MB）")
    group.add_argument("--repo", action="store_true", help="完整仓库扫描（首次接入 / 全量）")
    group.add_argument("--history", action="store_true", help="扫描完整 Git History（新增行）")
    parser.add_argument("--no-external", action="store_true", help="跳过外部 scanner（仅 Native 检测）")
    parser.add_argument("--max-commits", type=int, default=0, help="history 扫描最多扫描 N 个提交（0=不限）")
    parser.add_argument("--write-baseline", action="store_true", help="把当前 findings 写入 Baseline（需 --reason）")
    parser.add_argument("--reason", default=None, help="--write-baseline 所需的审计原因")
    parser.add_argument("--expires", default=None, help="Baseline 条目过期时间（YYYY-MM-DD）")
    add_common_arguments(parser)
    return parser


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #

def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    reporter = reporter_from_args(args)

    scope = resolve_scope(args)
    cwd = os.getcwd()
    root = repo_root(cwd) or cwd

    # ---- 配置（Fail-Closed） ----
    try:
        config = load_config(args.config, cwd=cwd)
    except ConfigError as exc:
        code = exc.code or "CONFIG_INVALID"
        result = fail_deny_result(code, exc.message, category=CATEGORY_CONFIG)
        reporter.emit_result(result, exit_code=EXIT_USAGE)
        return EXIT_USAGE

    # ---- Baseline（损坏绝不放过） ----
    baseline_path = args.baseline or default_baseline_path(root)
    try:
        baseline = Baseline.load(baseline_path, root=root)
    except BaselineError as exc:
        result = fail_deny_result(CODE_BASELINE_INVALID, exc.message,
                                  severity="HIGH", category=CATEGORY_SECURITY)
        reporter.emit_result(result, exit_code=EXIT_FINDING)
        return EXIT_FINDING

    # ---- Shallow（完整扫描时 Fail-Closed） ----
    shallow = detect_shallow(root)
    if scope in FULL_SCAN_SCOPES and shallow:
        result = fail_deny_result(
            CODE_SHALLOW_HISTORY,
            "shallow repository: full history scan is incomplete. "
            "Run `git fetch --unshallow` (or `git fetch --depth=1000000`) then re-scan.",
            severity="HIGH", category=CATEGORY_SECURITY,
        )
        reporter.emit_result(result, exit_code=EXIT_TOOL)
        return EXIT_TOOL

    # ---- Native 扫描 ----
    rules = build_rules(config.custom_rules)
    ignore_paths = config.ignore_paths
    try:
        if scope == SCOPE_STAGED:
            native = scan_staged(rules, ignore_paths, root)
        elif scope == SCOPE_WORKTREE:
            native = scan_worktree(rules, ignore_paths, root)
        elif scope in (SCOPE_ALL, SCOPE_REPO):
            native = scan_all(rules, ignore_paths, root)
        else:  # history
            native, _hist_ok = scan_history(rules, ignore_paths, root, args.max_commits)
    except Exception as exc:  # noqa: BLE001
        reporter.error(f"native scan failed: {exc}")
        result = fail_deny_result("NATIVE_SCAN_ERROR", f"native scan failed: {exc}",
                                  category=CATEGORY_SECURITY)
        reporter.emit_result(result, exit_code=EXIT_TOOL)
        return EXIT_TOOL

    # ---- 外部 scanner ----
    ext_findings: List[Finding] = []
    ext_outcomes: Dict[str, Any] = {}
    if not args.no_external:
        ext_findings, ext_outcomes = run_external_scanners(
            config, scope, root, config.external_scanner_timeout, reporter
        )

    all_findings = list(native) + list(ext_findings)

    # ---- --write-baseline ----
    if args.write_baseline:
        if not args.reason or not args.reason.strip():
            result = usage_error_result(CODE_MISSING_REASON,
                                        "--write-baseline requires --reason")
            reporter.emit_result(result, exit_code=EXIT_USAGE)
            return EXIT_USAGE
        incomplete = [f for f in all_findings
                      if not str(getattr(f, "fingerprint", "")).startswith("sha256:")]
        if incomplete:
            result = usage_error_result(CODE_FINGERPRINT_INCOMPLETE,
                                        "cannot baseline findings without complete fingerprints")
            reporter.emit_result(result, exit_code=EXIT_USAGE)
            return EXIT_USAGE
        from safecode_secret import make_baseline_entry
        entries = [make_baseline_entry(f, args.reason, expires=args.expires) for f in all_findings]
        merged = {e["fingerprint"]: e for e in baseline.entries}
        for e in entries:
            merged[e["fingerprint"]] = e
        new_baseline = Baseline(list(merged.values()))
        new_baseline.save(baseline_path)
        result = pass_result(CODE_BASELINE_WRITTEN,
                             f"Wrote {len(entries)} baseline entr(y/ies) to {baseline_path}",
                             category=CATEGORY_SECURITY)
        result.metadata["baseline_path"] = baseline_path
        result.metadata["entries_written"] = len(entries)
        reporter.emit_result(result, exit_code=EXIT_OK)
        return EXIT_OK

    # ---- 归类 ----
    blocking, details, stats = classify(all_findings, config.allow_list, baseline)

    mode = resolve_mode(strict_flag=bool(args.strict), config=config)
    strict = (mode == MODE_STRICT)

    # ---- 组装结果 ----
    metadata: Dict[str, Any] = {
        "scope": scope,
        "policy_mode": mode,
        "shallow": shallow,
        "incomplete_history": bool(shallow and scope not in FULL_SCAN_SCOPES),
        "counts": {
            "total": len(all_findings),
            "blocking": len(blocking),
            "native": len(native),
            "external": len(ext_findings),
        },
        "baseline": {
            "path": baseline_path,
            "entries": len(baseline.entries),
            "known": stats["known"],
            "new": stats["new"],
            "expired": stats["expired"],
            "allowed": stats["allowed"],
        },
        "findings": details,
    }
    if ext_outcomes:
        metadata["scanners"] = ext_outcomes

    if blocking:
        expired = any(d.get("classification") == "expired" for d in details)
        code = CODE_BASELINE_EXPIRED if expired else CODE_SECRET_DETECTED
        severity = _max_severity(blocking)
        locations = [f.location().to_dict() for f in blocking]
        result = fail_deny_result(code, "Secret or sensitive finding detected.", severity=severity,
                                  category=CATEGORY_SECURITY, locations=locations, metadata=metadata)
        reporter.emit_result(result, exit_code=EXIT_FINDING)
        return EXIT_FINDING

    # 无阻断 finding：看外部 scanner 是否出问题
    if ext_outcomes and external_has_problem(ext_outcomes):
        code = external_problem_code(ext_outcomes)
        if strict:
            result = fail_deny_result(code,
                                      "External scanner(s) unavailable or errored; "
                                      "security gate cannot be considered complete.",
                                      severity="MEDIUM", category=CATEGORY_SECURITY,
                                      metadata=metadata)
            reporter.emit_result(result, exit_code=EXIT_TOOL)
            return EXIT_TOOL
        # LOCAL 非 strict：降级但明确不是 PASS
        result = degraded_result(code,
                                 "External scanner(s) unavailable or errored; "
                                 "native gate passed but full coverage not verified.",
                                 metadata=metadata)
        reporter.emit_result(result, exit_code=EXIT_OK)
        return EXIT_OK

    # 干净
    result = pass_result(CODE_SECRET_SCAN_CLEAN, "No secret or sensitive findings.",
                         severity="LOW", category=CATEGORY_SECURITY, metadata=metadata)
    reporter.emit_result(result, exit_code=EXIT_OK)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
