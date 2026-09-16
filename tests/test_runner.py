"""test-runner.py 的黑盒测试：失败分类、Flaky 检测、预算集成。"""

from __future__ import annotations

import json
from pathlib import Path

from conftest import (
    EXIT_FINDING,
    EXIT_OK,
    assert_result_schema,
    parse_json_output,
    run_script,
    write_file,
)

SCRIPT = "test-runner.py"

PASSING_TEST = """
def test_ok():
    assert 1 + 1 == 2
"""

FAILING_TEST = """
def test_bad():
    assert 1 == 2, "intentional failure"
"""

SYNTAX_ERROR_TEST = """
def test_broken(
    assert True
"""

IMPORT_ERROR_TEST = """
import definitely_not_a_real_module_xyz  # noqa: F401


def test_needs_missing_dep():
    assert True
"""

FLAKY_TEST = """
import pathlib

MARKER = pathlib.Path(__file__).with_name("_flaky_marker")


def test_flaky():
    if not MARKER.exists():
        MARKER.write_text("seen", encoding="utf-8")
        assert False, "first run fails, later runs pass"
    assert True
"""


def make_project(tmp_path: Path, test_body: str, *, config: str = "") -> Path:
    project = tmp_path / "project"
    write_file(project / "tests" / "test_sample.py", test_body)
    if config:
        write_file(project / ".safecode.yml", config)
    return project


def run_runner(project: Path, *args: str, env: dict | None = None):
    return run_script(SCRIPT, *args, cwd=project, env=env)


def test_passing_suite_exits_zero(tmp_path: Path) -> None:
    project = make_project(tmp_path, PASSING_TEST)
    proc = run_runner(project, "--task-id", "t-pass", "--json")
    assert proc.returncode == EXIT_OK, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["status"] == "PASS"
    assert payload["decision"] == "ALLOW"
    assert payload["code"] == "TEST_PASSED"
    assert payload["metadata"]["level"] == "L0"


def test_assertion_failure_is_l1(tmp_path: Path) -> None:
    project = make_project(tmp_path, FAILING_TEST)
    proc = run_runner(project, "--task-id", "t-l1", "--no-flaky", "--json")
    assert proc.returncode == EXIT_FINDING
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "DENY"
    assert payload["metadata"]["level"] == "L1"
    assert payload["metadata"]["category"] != "FLAKY_TEST"
    assert payload["metadata"]["failed_tests"], "failed tests should be reported"


def test_syntax_error_is_l2(tmp_path: Path) -> None:
    project = make_project(tmp_path, SYNTAX_ERROR_TEST)
    proc = run_runner(project, "--task-id", "t-l2", "--no-flaky", "--json")
    assert proc.returncode == EXIT_FINDING
    payload = parse_json_output(proc)
    assert payload["metadata"]["level"] == "L2"


def test_import_error_is_l3(tmp_path: Path) -> None:
    project = make_project(tmp_path, IMPORT_ERROR_TEST)
    proc = run_runner(project, "--task-id", "t-l3", "--no-flaky", "--json")
    assert proc.returncode == EXIT_FINDING
    payload = parse_json_output(proc)
    assert payload["metadata"]["level"] == "L3"


def test_flaky_test_detected(tmp_path: Path) -> None:
    project = make_project(tmp_path, FLAKY_TEST)
    proc = run_runner(project, "--task-id", "t-flaky", "--reruns", "3", "--json")
    assert proc.returncode == EXIT_FINDING, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["metadata"]["category"] == "FLAKY_TEST"
    assert payload["decision"] == "DENY", "flaky suite must not be treated as passing"
    flaky = payload["metadata"]["flaky_detection"]
    assert flaky["enabled"] is True
    assert flaky["reruns_performed"] >= 2
    assert len({r["passed"] for r in payload["metadata"]["runs"]}) == 2, \
        "both pass and fail outcomes must be recorded"


def test_deterministic_failure_is_not_flaky(tmp_path: Path) -> None:
    project = make_project(tmp_path, FAILING_TEST)
    proc = run_runner(project, "--task-id", "t-det", "--reruns", "2", "--json")
    payload = parse_json_output(proc)
    assert payload["metadata"]["category"] != "FLAKY_TEST"


def test_budget_exhaustion_blocks(tmp_path: Path) -> None:
    config = (
        "schema_version: \"1.0\"\n"
        "recovery:\n"
        "  max_recovery_attempts: 3\n"
        "  max_total_test_runs: 2\n"
        "  max_total_recoveries: 5\n"
        "  max_total_time: 30m\n"
    )
    project = make_project(tmp_path, FAILING_TEST, config=config)

    first = run_runner(project, "--task-id", "t-budget", "--no-flaky", "--json")
    assert first.returncode == EXIT_FINDING
    first_payload = parse_json_output(first)
    assert first_payload["code"] != "BUDGET_EXHAUSTED", "first run should still be within budget"

    second = run_runner(project, "--task-id", "t-budget", "--no-flaky", "--json")
    assert second.returncode == EXIT_FINDING
    payload = parse_json_output(second)
    assert_result_schema(payload)
    assert payload["code"] == "BUDGET_EXHAUSTED"
    assert payload["decision"] == "DENY"

    state_file = project / ".safecode" / "state" / "t-budget.json"
    assert state_file.is_file(), "persistent budget state must exist"
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state["test_runs"] == 2


def test_json_mode_keeps_stdout_clean(tmp_path: Path) -> None:
    project = make_project(tmp_path, PASSING_TEST)
    proc = run_runner(project, "--task-id", "t-json", "--json")
    assert proc.returncode == EXIT_OK
    json.loads(proc.stdout)  # 单个 JSON 对象，整体可解析
    assert proc.stderr.strip() == "", f"stderr should be silent in --json mode: {proc.stderr!r}"


def test_incomplete_check_is_not_pass(tmp_path: Path) -> None:
    """检查无法完成（目标不存在 / 未收集到测试）不得被当作通过。"""
    project = make_project(tmp_path, PASSING_TEST)
    proc = run_runner(project, "tests/does_not_exist.py", "--task-id", "t-none",
                      "--no-flaky", "--json")
    assert proc.returncode == EXIT_FINDING, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "DENY"
    assert payload["code"] != "TEST_PASSED"
