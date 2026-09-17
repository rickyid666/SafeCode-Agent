"""SafeCode Test Runner：统一执行项目测试，并做可复现的 Flaky 检测。

关键语义（对应 v7 契约）：

- 失败分类：编译 / 语法 -> L2，断言 -> L1，依赖 / 收集 -> L3，pytest 自身异常 -> L3，
  无法归类 -> L6。等级是 Policy Engine 的输入，不是给 Agent 的建议。
- Flaky 检测：初始运行 FAIL 后，在代码与环境不变的前提下额外 rerun N 次
  （默认取 .safecode.yml 的 testing.flaky_detection.reruns，缺省 3）。
  结果不稳定（既有 PASS 又有 FAIL）-> category = FLAKY_TEST，
  仍然 DENY（测试套件确实没通过，不能放行 Push），但明确提示"不要修改业务代码"。
  每次运行结果都记录下来（run 序号、退出码、失败测试、HEAD sha、环境摘要）以便复现与审计。
- 预算：**每一次真实测试执行都计入 test_runs**（含通过的那次与每一次 Flaky rerun），
  因为契约把 MAX_TOTAL_TEST_RUNS 定义为"实际执行次数"。通过时 consecutive_failures
  归零、失败时累加；两者都不计 recoveries。失败路径上预算耗尽 -> BUDGET_EXHAUSTED + DENY；
  已经通过的那次不因预算耗尽被拒，只在结果里标注 budget_exhausted 并提示不要再跑。
- 检查无法完成（pytest 不可用、超时）-> 不 PASS。

纯 Python 标准库。Python >= 3.10。
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from safecode_common import (  # noqa: E402
    CATEGORY_TEST,
    EXIT_ENV,
    EXIT_FINDING,
    EXIT_OK,
    EXIT_TOOL,
    EXIT_USAGE,
    L0,
    L1,
    L2,
    L3,
    L6,
    Reporter,
    add_common_arguments,
    fail_deny_result,
    make_result,
    pass_result,
    repo_head,
    repo_root,
    reporter_from_args,
    resolve_mode,
    tool_error_result,
)
from safecode_budget import (  # noqa: E402
    BudgetError,
    budget_report,
    check_exhausted,
    get_current_task,
    load_state,
    record_flaky_rerun,
    record_test_run,
    set_current_task,
)
from safecode_config import ConfigError, load_config  # noqa: E402

CODE_TEST_PASSED = "TEST_PASSED"
CODE_TEST_FAILED = "TEST_FAILED"
CODE_FLAKY_TEST = "FLAKY_TEST"
CODE_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
CODE_PYTEST_UNAVAILABLE = "PYTEST_UNAVAILABLE"
CODE_TEST_TIMEOUT = "TEST_TIMEOUT"

DEFAULT_TIMEOUT = 1800
MAX_OUTPUT_KEPT = 400_000

# pytest 退出码含义
PYTEST_OK = 0
PYTEST_TESTS_FAILED = 1
PYTEST_INTERRUPTED = 2
PYTEST_INTERNAL_ERROR = 3
PYTEST_USAGE_ERROR = 4
PYTEST_NO_TESTS = 5

_FAILED_LINE_RE = re.compile(r"^(?P<kind>FAILED|ERROR)\s+(?P<node>[^\s]+)(?:\s+-\s+(?P<msg>.*))?$")
_TESTS_SUMMARY_RE = re.compile(r"^(?P<count>\d+)\s+failed")
_PASSED_SUMMARY_RE = re.compile(r"^(?P<count>\d+)\s+passed")


class RunResult:
    """一次 pytest 执行的结果。"""

    def __init__(self, returncode: int, stdout: str, stderr: str,
                 duration: float, timed_out: bool = False, error: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.duration = duration
        self.timed_out = timed_out
        self.error = error

    @property
    def passed(self) -> bool:
        return self.returncode == PYTEST_OK and not self.timed_out and not self.error

    def failed_tests(self) -> List[Dict[str, Any]]:
        found: List[Dict[str, Any]] = []
        seen = set()
        for line in (self.stdout or "").splitlines():
            match = _FAILED_LINE_RE.match(line.strip())
            if not match:
                continue
            node = match.group("node")
            if node in seen:
                continue
            seen.add(node)
            path, _, test_name = node.partition("::")
            entry: Dict[str, Any] = {
                "node_id": node,
                "file": path,
                "test": test_name or "",
            }
            msg = (match.group("msg") or "").strip()
            if msg:
                entry["message"] = msg[:300]
            found.append(entry)
        return found

    def summary_line(self) -> str:
        for line in reversed((self.stdout or "").splitlines()):
            stripped = line.strip()
            if "passed" in stripped or "failed" in stripped or "error" in stripped.lower():
                return stripped[:200]
        return ""

    def to_dict(self, index: int) -> Dict[str, Any]:
        return {
            "run": index,
            "exit_code": self.returncode,
            "passed": self.passed,
            "timed_out": self.timed_out,
            "duration_seconds": round(self.duration, 2),
            "summary": self.summary_line(),
            "failed_tests": [t["node_id"] for t in self.failed_tests()],
        }


def classify_failure(result: RunResult) -> Tuple[str, str]:
    """把失败归类为 L1 / L2 / L3 / L6，返回 (level, code)。"""
    if result.timed_out:
        return L3, CODE_TEST_TIMEOUT
    text = f"{result.stdout}\n{result.stderr}"
    lowered = text.lower()

    if result.returncode == PYTEST_INTERNAL_ERROR:
        return L3, "PYTEST_INTERNAL_ERROR"
    if result.returncode == PYTEST_USAGE_ERROR:
        return L3, "PYTEST_USAGE_ERROR"
    if result.returncode == PYTEST_NO_TESTS:
        return L3, "NO_TESTS_COLLECTED"
    if "no module named pytest" in lowered or "pytest: not found" in lowered:
        return L3, CODE_PYTEST_UNAVAILABLE

    if re.search(r"(syntaxerror|indentationerror|taberror)", lowered):
        return L2, "COMPILE_ERROR"
    if re.search(r"(modulenotfounderror|importerror|cannot import name)", lowered):
        return L3, "DEPENDENCY_ERROR"
    if re.search(r"(error collecting|collection error|errors during collection)", lowered):
        return L3, "COLLECTION_ERROR"
    if re.search(r"(fixture .* not found|error in fixture)", lowered):
        return L3, "FIXTURE_ERROR"
    if re.search(r"(assertionerror|\bassert\b)", lowered):
        return L1, "ASSERTION_FAILURE"
    if result.returncode == PYTEST_TESTS_FAILED:
        return L6, "UNKNOWN_FAILURE"
    return L6, "UNKNOWN_FAILURE"


def environment_summary() -> Dict[str, Any]:
    """环境摘要，用于让 Flaky 结果可复现。"""
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
    }


def run_pytest(targets: Sequence[str], passthrough: Sequence[str], timeout: int,
               cwd: str) -> RunResult:
    """执行一次 pytest。"""
    cmd = [sys.executable, "-m", "pytest", *targets, *passthrough]
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        return RunResult(EXIT_ENV, stdout[:MAX_OUTPUT_KEPT], stderr[:MAX_OUTPUT_KEPT],
                         time.time() - started, timed_out=True,
                         error=f"pytest timed out after {timeout}s")
    except FileNotFoundError as exc:
        return RunResult(EXIT_TOOL, "", str(exc), time.time() - started,
                         error=f"cannot execute pytest: {exc}")

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    if "No module named pytest" in stderr or "No module named pytest" in stdout:
        return RunResult(EXIT_TOOL, stdout[:MAX_OUTPUT_KEPT], stderr[:MAX_OUTPUT_KEPT],
                         time.time() - started, error="pytest is not installed")
    return RunResult(proc.returncode, stdout[:MAX_OUTPUT_KEPT], stderr[:MAX_OUTPUT_KEPT],
                     time.time() - started)


def resolve_task_id(explicit: Optional[str], root: Optional[str]) -> str:
    task_id = explicit or os.environ.get("SAFECODE_TASK_ID") or ""
    if not task_id:
        try:
            task_id = get_current_task(root) or ""
        except Exception:
            task_id = ""
    if not task_id:
        task_id = f"task-{time.strftime('%Y%m%d-%H%M%S')}"
        try:
            set_current_task(task_id, root)
        except Exception:
            pass
    return task_id


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="test-runner.py",
        description="Run project tests, classify failures, detect flaky tests.",
    )
    parser.add_argument("targets", nargs="*", default=[],
                        help="pytest 目标路径（默认取配置 testing.targets）")
    parser.add_argument("--no-flaky", action="store_true", help="关闭 Flaky 检测")
    parser.add_argument("--reruns", type=int, default=None,
                        help="Flaky 重跑次数（默认取配置，缺省 3）")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="单次 pytest 超时秒数（默认 1800）")
    parser.add_argument("--passthrough", default="",
                        help="额外 pytest 参数，空格分隔")
    add_common_arguments(parser)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)

    # 支持 `... -- -x -k foo` 形式的透传
    passthrough_from_argv: List[str] = []
    if "--" in raw:
        idx = raw.index("--")
        passthrough_from_argv = raw[idx + 1:]
        raw = raw[:idx]

    parser = build_parser()
    args = parser.parse_args(raw)
    reporter: Reporter = reporter_from_args(args)

    cwd = os.getcwd()
    try:
        config = load_config(args.config, cwd)
    except ConfigError as exc:
        reporter.error(f"{exc.code}: {exc.message}")
        result = make_result("FAIL", "DENY", exc.code, exc.message, category=CATEGORY_TEST)
        return reporter.emit_result(result, exit_code=EXIT_USAGE)

    root = repo_root(cwd) or cwd
    mode = resolve_mode(strict_flag=bool(args.strict), config=config)

    targets = list(args.targets)
    if not targets:
        configured = config.get("testing.targets") or []
        targets = [str(t) for t in configured]
    if not targets:
        targets = ["tests"]

    flaky_enabled = not args.no_flaky and bool(config.get("testing.flaky_detection.enabled", True))
    reruns = args.reruns if args.reruns is not None else int(config.get("testing.flaky_detection.reruns", 3) or 0)
    reruns = max(0, min(reruns, 10))

    passthrough = list(passthrough_from_argv)
    if args.passthrough:
        passthrough.extend(args.passthrough.split())
    passthrough.extend(["-q"] if "-q" not in passthrough else [])

    task_id = resolve_task_id(args.task_id, root)
    limits = config.budget_limits

    reporter.info(f"SafeCode test run: targets={targets} task_id={task_id} mode={mode}")

    # 首次运行
    first = run_pytest(targets, passthrough, args.timeout, cwd)
    runs: List[RunResult] = [first]

    if first.passed:
        passed_state: Optional[Dict[str, Any]] = None
        budget_note: Optional[str] = None
        try:
            # 通过也是一次"真实测试执行"，必须计入 test_runs —— 契约把
            # MAX_TOTAL_TEST_RUNS 定义为实际执行次数，不是失败次数。见 README
            # 「Test Budget 语义」一节。
            passed_state = record_test_run(task_id, root=root, level=L0, code=CODE_TEST_PASSED,
                                           summary="all tests passed",
                                           duration_seconds=first.duration, passed=True)
            budget_note = check_exhausted(passed_state, limits)
        except BudgetError as exc:
            reporter.warn(f"budget update failed: {exc}")
        if budget_note:
            # 已经通过，不因预算耗尽拒绝本次结果；但不能假装还有额度。
            reporter.warn(f"test budget exhausted: {budget_note}")
        message = "all tests passed"
        if budget_note:
            message = (f"all tests passed, but the test budget is exhausted ({budget_note}); "
                       "do not run further tests without a human decision")
        result = pass_result(CODE_TEST_PASSED, message,
                             category=CATEGORY_TEST,
                             metadata={
                                 "level": L0,
                                 "task_id": task_id,
                                 "mode": mode,
                                 "targets": targets,
                                 "exit_code": first.returncode,
                                 "duration_seconds": round(first.duration, 2),
                                 "runs": [r.to_dict(i + 1) for i, r in enumerate(runs)],
                                 "budget": budget_report(passed_state, limits) if passed_state else None,
                                 "budget_exhausted": bool(budget_note),
                             })
        reporter.info("tests passed")
        return reporter.emit_result(result, exit_code=EXIT_OK)

    if first.timed_out:
        result = tool_error_result(CODE_TEST_TIMEOUT,
                                   first.error or "pytest timed out",
                                   category=CATEGORY_TEST)
        result.metadata.update({"task_id": task_id, "mode": mode, "targets": targets})
        return reporter.emit_result(result, exit_code=EXIT_ENV)

    if first.error and first.returncode == EXIT_TOOL:
        result = tool_error_result(CODE_PYTEST_UNAVAILABLE, first.error,
                                   category=CATEGORY_TEST)
        result.metadata.update({"task_id": task_id, "mode": mode, "targets": targets})
        return reporter.emit_result(result, exit_code=EXIT_TOOL)

    level, code = classify_failure(first)
    budget_state = None
    budget_exhausted_reason: Optional[str] = None
    try:
        budget_state = record_test_run(task_id, root=root, level=level, code=code,
                                       summary=first.summary_line(),
                                       duration_seconds=first.duration, passed=False)
        budget_exhausted_reason = check_exhausted(budget_state, limits)
    except BudgetError as exc:
        reporter.error(f"budget update failed: {exc}")
        budget_state = None
        budget_exhausted_reason = f"budget state error: {exc}"

    # Flaky 检测
    flaky_records: List[Dict[str, Any]] = []
    category = "DETERMINISTIC_FAILURE"
    if flaky_enabled and reruns > 0 and not budget_exhausted_reason:
        for i in range(reruns):
            rerun = run_pytest(targets, passthrough, args.timeout, cwd)
            runs.append(rerun)
            flaky_records.append(rerun.to_dict(len(runs)))
            try:
                budget_state = record_flaky_rerun(
                    task_id, root=root, level=level, code=code,
                    summary=f"flaky rerun {i + 1}: {'PASS' if rerun.passed else 'FAIL'}",
                    duration_seconds=rerun.duration)
                budget_exhausted_reason = check_exhausted(budget_state, limits)
            except BudgetError as exc:
                reporter.warn(f"budget update failed on rerun: {exc}")
            if budget_exhausted_reason:
                reporter.warn(f"budget exhausted during flaky reruns: {budget_exhausted_reason}")
                break
        outcomes = {r.passed for r in runs}
        if len(outcomes) > 1:
            category = CODE_FLAKY_TEST

    failed_tests = first.failed_tests()
    locations = [{"file": t["file"], "line": 1} for t in failed_tests if t.get("file")]

    metadata: Dict[str, Any] = {
        "level": level,
        "category": category,
        "task_id": task_id,
        "mode": mode,
        "targets": targets,
        "exit_code": first.returncode,
        "duration_seconds": round(first.duration, 2),
        "failed_tests": failed_tests,
        "runs": [r.to_dict(i + 1) for i, r in enumerate(runs)],
        "flaky_detection": {
            "enabled": flaky_enabled,
            "reruns_configured": reruns,
            "reruns_performed": len(flaky_records),
            "records": flaky_records,
        },
        "environment": environment_summary(),
        "code_state": repo_head(root) or "",
        "pytest_summary": first.summary_line(),
    }
    if budget_state is not None:
        metadata["budget"] = budget_report(budget_state, limits)

    if budget_exhausted_reason:
        result = fail_deny_result(
            CODE_BUDGET_EXHAUSTED,
            f"recovery/test budget exhausted: {budget_exhausted_reason}. "
            "Stop auto-recovery, do not push, human intervention required.",
            category=CATEGORY_TEST, locations=locations, metadata=metadata)
        reporter.error(result.message)
        return reporter.emit_result(result, exit_code=EXIT_FINDING)

    if category == CODE_FLAKY_TEST:
        message = (
            f"flaky test detected ({sum(1 for r in runs if r.passed)} pass / "
            f"{sum(1 for r in runs if not r.passed)} fail over {len(runs)} runs): "
            "do NOT modify business code, fix the test or its environment instead"
        )
    else:
        message = f"tests failed ({level} / {code}); push is blocked"

    result = fail_deny_result(code if category != CODE_FLAKY_TEST else CODE_FLAKY_TEST,
                              message, category=CATEGORY_TEST,
                              locations=locations, metadata=metadata)
    reporter.error(message)
    return reporter.emit_result(result, exit_code=EXIT_FINDING)


if __name__ == "__main__":
    sys.exit(main())
