"""SafeCode Pre-push Pipeline：把各 Gate 串成一条真正会阻断 Push 的流水线。

流水线（契约要求的顺序）：

    git 状态 -> 当前分支 -> Diff 检查 -> 新增文件 -> 测试 -> 安全扫描
    -> 依赖检查 -> Git Guard(pre-push) -> Decision Resolver -> 允许 / 阻断

关键点：

- 每个步骤的子进程输出被当作机器协议读取（Structured JSON + 退出码），
  由 Decision Resolver 统一合并，**不由本脚本自行解释"是否安全"**。
- 某一步无法完成（脚本缺失、JSON 不可解析、超时）一律视为阻断，不允许静默通过。
- 本脚本作为 .githooks/pre-push 的入口：stdin 上的 hook 数据原样转交 git-guard。
- 不阻塞等待人工输入：需要授权时输出结构化授权请求后退出（无人值守环境同样适用）。

纯 Python 标准库。Python >= 3.10。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from safecode_common import (  # noqa: E402
    CATEGORY_GIT,
    DECISION_ALLOW,
    DECISION_DENY,
    EXIT_FINDING,
    EXIT_OK,
    EXIT_USAGE,
    Reporter,
    add_common_arguments,
    current_branch,
    fail_deny_result,
    make_result,
    pass_result,
    read_stdin_safely,
    repo_root,
    reporter_from_args,
    resolve_decision,
    resolve_mode,
    run_git,
    stricter,
)
from safecode_config import ConfigError, load_config  # noqa: E402

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

CODE_PIPELINE_PASSED = "PIPELINE_PASSED"
CODE_PIPELINE_BLOCKED = "PIPELINE_BLOCKED"
CODE_STEP_UNAVAILABLE = "PIPELINE_STEP_UNAVAILABLE"
CODE_STEP_INVALID_RESULT = "PIPELINE_STEP_INVALID_RESULT"


class StepOutcome:
    """单个 Gate 的执行结果。"""

    def __init__(self, name: str, script: str, argv: Sequence[str],
                 exit_code: Optional[int], payload: Optional[Dict[str, Any]],
                 narration: str, error: str = "", duration: float = 0.0) -> None:
        self.name = name
        self.script = script
        self.argv = list(argv)
        self.exit_code = exit_code
        self.payload = payload
        self.narration = narration
        self.error = error
        self.duration = duration

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.name,
            "script": self.script,
            "argv": self.argv,
            "exit_code": self.exit_code,
            "status": (self.payload or {}).get("status"),
            "decision": (self.payload or {}).get("decision"),
            "code": (self.payload or {}).get("code"),
            "message": (self.payload or {}).get("message"),
            "duration_seconds": round(self.duration, 2),
            "narration": self.narration,
            "error": self.error,
        }


def _run_step(name: str, script: str, argv: Sequence[str], *, mode: str,
              stdin_text: Optional[str] = None,
              reporter: Optional[Reporter] = None) -> StepOutcome:
    """执行一个 Gate，并把它的 JSON + 退出码合并为有效决策。"""
    path = os.path.join(SCRIPTS_DIR, script)
    reporter = reporter or Reporter()
    if not os.path.isfile(path):
        return StepOutcome(name, script, argv, None, None,
                           narration="script missing",
                           error=f"gate script not found: {script}")

    cmd = [sys.executable, path, *argv]
    started = time.time()
    try:
        proc = subprocess.run(
            cmd, cwd=os.getcwd(),
            input=stdin_text,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace", timeout=3600,
        )
    except subprocess.TimeoutExpired:
        return StepOutcome(name, script, argv, None, None,
                           narration="timeout",
                           error=f"{script} timed out", duration=time.time() - started)
    except OSError as exc:
        return StepOutcome(name, script, argv, None, None,
                           narration="exec error", error=str(exc),
                           duration=time.time() - started)

    duration = time.time() - started
    payload = _parse_payload(proc.stdout)
    if payload is None:
        return StepOutcome(name, script, argv, proc.returncode, None,
                           narration="unparseable output",
                           error=f"{script} produced no parsable Structured JSON: "
                                 f"{(proc.stderr or proc.stdout)[:300]}",
                           duration=duration)

    resolution = resolve_decision(payload, proc.returncode, mode)
    narration = resolution.effective_decision
    return StepOutcome(name, script, argv, proc.returncode, payload,
                       narration=narration,
                       error="" if not resolution.blocking else
                       "; ".join(resolution.reasons), duration=duration)


def _parse_payload(stdout: str) -> Optional[Dict[str, Any]]:
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        candidate = json.loads(text)
        return candidate if isinstance(candidate, dict) else None
    except ValueError:
        for line in reversed(text.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    candidate = json.loads(line)
                    if isinstance(candidate, dict):
                        return candidate
                except ValueError:
                    continue
    return None


def _git_state(root: str) -> Dict[str, Any]:
    status = run_git(["status", "--porcelain"], cwd=root)
    staged = run_git(["diff", "--cached", "--name-status"], cwd=root)
    untracked = [line[3:] for line in (status.stdout or "").splitlines()
                 if line.startswith("?? ")]
    changed = [line for line in (staged.stdout or "").splitlines() if line.strip()]
    return {
        "dirty": bool((status.stdout or "").strip()),
        "branch": current_branch(root),
        "staged_files": changed,
        "untracked_files": untracked,
        "status_porcelain": (status.stdout or "").strip().splitlines(),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pre-push.py",
        description="SafeCode pre-push pipeline (git hook entry point).",
    )
    parser.add_argument("--scope", default="staged", choices=["staged", "worktree", "all"],
                        help="安全扫描范围（默认 staged）")
    parser.add_argument("--skip-tests", action="store_true", help="跳过测试步骤（不推荐）")
    parser.add_argument("--skip-dependency", action="store_true", help="跳过依赖检查")
    parser.add_argument("--dry-run", action="store_true", help="只报告，不因阻断返回非零")
    add_common_arguments(parser)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    reporter: Reporter = reporter_from_args(args)

    cwd = os.getcwd()
    try:
        config = load_config(args.config, cwd)
    except ConfigError as exc:
        reporter.error(f"{exc.code}: {exc.message}")
        result = make_result("FAIL", "DENY", exc.code, exc.message, category=CATEGORY_GIT)
        return reporter.emit_result(result, exit_code=EXIT_USAGE)

    root = repo_root(cwd) or cwd
    mode = resolve_mode(strict_flag=bool(args.strict), config=config)

    # git hook 通过 stdin 传入要推送的 ref；手动运行时 stdin 通常是终端，直接跳过。
    # 用带超时的读取，避免在 stdin 是不关闭的管道时永久阻塞。
    hook_stdin, stdin_timed_out = read_stdin_safely(timeout=10.0)
    if stdin_timed_out:
        reporter.warn("stdin did not reach EOF within timeout; continuing without hook input")
    if hook_stdin is not None and not hook_stdin.strip():
        hook_stdin = None

    common = ["--config", config.path] if config.path else []
    if args.strict:
        common.append("--strict")

    reporter.info("=== SafeCode pre-push pipeline ===")
    reporter.info(f"mode={mode} scope={args.scope} root={root}")

    state = _git_state(root)
    reporter.info(f"branch={state['branch']} dirty={state['dirty']} "
                  f"staged={len(state['staged_files'])} untracked={len(state['untracked_files'])}")

    outcomes: List[StepOutcome] = []

    # 1. Diff / 危险内容
    outcomes.append(_run_step("git-guard:diff", "git-guard.py", [*common, "--check-diff"],
                              mode=mode, reporter=reporter))
    reporter.info(f"step git-guard:diff -> {outcomes[-1].narration}")

    # 2. 安全扫描
    scan_args = [*common, f"--{args.scope}"]
    outcomes.append(_run_step("security-scan", "security-scan.py", scan_args,
                              mode=mode, reporter=reporter))
    reporter.info(f"step security-scan -> {outcomes[-1].narration}")

    # 3. 依赖 / 供应链
    if not args.skip_dependency:
        outcomes.append(_run_step("dependency-guard", "dependency-guard.py",
                                  [*common, f"--scope={args.scope}"],
                                  mode=mode, reporter=reporter))
        reporter.info(f"step dependency-guard -> {outcomes[-1].narration}")

    # 4. 测试
    if not args.skip_tests:
        outcomes.append(_run_step("test-runner", "test-runner.py", [*common],
                                  mode=mode, reporter=reporter))
        reporter.info(f"step test-runner -> {outcomes[-1].narration}")

    # 5. git hook 输入（强推 / 删分支 / 受保护分支）
    if hook_stdin:
        outcomes.append(_run_step("git-guard:pre-push", "git-guard.py",
                                  [*common, "--pre-push"],
                                  mode=mode, stdin_text=hook_stdin, reporter=reporter))
        reporter.info(f"step git-guard:pre-push -> {outcomes[-1].narration}")
    else:
        reporter.debug("no pre-push hook input on stdin; skipping git-guard --pre-push")

    # 聚合：取最严格结果
    effective = DECISION_ALLOW
    blocking_steps: List[str] = []
    unavailable: List[str] = []
    invalid: List[str] = []

    for outcome in outcomes:
        if outcome.payload is None:
            if outcome.exit_code is None and "not found" in (outcome.error or ""):
                unavailable.append(outcome.name)
            else:
                invalid.append(outcome.name)
            blocking_steps.append(outcome.name)
            effective = DECISION_DENY
            continue
        resolution = resolve_decision(outcome.payload, outcome.exit_code or 0, mode)
        if resolution.blocking:
            blocking_steps.append(outcome.name)
        effective = stricter(effective, resolution.effective_decision)

    metadata: Dict[str, Any] = {
        "mode": mode,
        "scope": args.scope,
        "root": root,
        "git_state": state,
        "steps": [o.to_dict() for o in outcomes],
        "blocking_steps": blocking_steps,
        "unavailable_steps": unavailable,
        "invalid_steps": invalid,
        "hook_input_received": bool(hook_stdin),
    }

    if unavailable or invalid:
        code = CODE_STEP_UNAVAILABLE if unavailable else CODE_STEP_INVALID_RESULT
        message = ("pipeline step could not be completed -> blocked: "
                   + ", ".join(sorted(set(unavailable + invalid))))
        result = fail_deny_result(code, message, category=CATEGORY_GIT, metadata=metadata)
        reporter.error(message)
        if args.dry_run:
            return reporter.emit_result(result, exit_code=EXIT_OK)
        return reporter.emit_result(result, exit_code=EXIT_FINDING)

    if effective != DECISION_ALLOW:
        message = (f"push blocked: {effective}; blocking steps: "
                   f"{', '.join(blocking_steps) if blocking_steps else 'none'}")
        result = fail_deny_result(CODE_PIPELINE_BLOCKED, message,
                                  severity="MEDIUM", category=CATEGORY_GIT,
                                  metadata=metadata)
        reporter.error(message)
        if args.dry_run:
            return reporter.emit_result(result, exit_code=EXIT_OK)
        return reporter.emit_result(result, exit_code=EXIT_FINDING)

    result = pass_result(CODE_PIPELINE_PASSED,
                         "SAFECODE: all gates passed, push allowed",
                         category=CATEGORY_GIT, metadata=metadata)
    reporter.info("SAFECODE: all gates passed, push allowed")
    return reporter.emit_result(result, exit_code=EXIT_OK)


if __name__ == "__main__":
    sys.exit(main())
