"""SafeCode Recovery / Persistent Budget 黑盒测试。

通过 subprocess 调用 scripts/recovery.py，断言 Structured JSON + 退出码，并直接检查
状态文件 / 诊断报告。覆盖 safecode_budget.py 的并发安全与计数语义。

约定：pathlib + subprocess list，不使用 shell=True，Windows 可跑。
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import (
    PYTHON,
    SCRIPTS_DIR,
    child_env,
    parse_json_output,
    assert_result_schema,
    run_script,
    write_file,
)

TASK = "task-recovery-test"


# --------------------------------------------------------------------------- #
# 1. 连续 3 次 record-failure 到上限
# --------------------------------------------------------------------------- #

def test_three_failures_exhaust(tmp_git_repo: Path):
    codes = []
    last = None
    for _ in range(3):
        proc = run_script("recovery.py", "record-failure", "--task-id", TASK, cwd=tmp_git_repo)
        codes.append(proc.returncode)
        last = proc
    assert codes == [0, 0, 1], codes
    payload = parse_json_output(last)
    assert_result_schema(payload)
    assert payload["code"] == "BUDGET_EXHAUSTED"
    assert payload["decision"] == "DENY"
    assert payload["status"] == "FAIL"

    report = tmp_git_repo / ".safecode" / "diagnostic-report.md"
    assert report.exists(), "diagnostic report must be created on exhaustion"
    text = report.read_text(encoding="utf-8")
    assert "停止" in text, "report must mention stop"
    assert "Push" in text, "report must forbid push"


# --------------------------------------------------------------------------- #
# 2. record-success 归零后再失败不立即超限
# --------------------------------------------------------------------------- #

def test_success_resets_then_failure_not_exhausted(tmp_git_repo: Path):
    run_script("recovery.py", "record-failure", "--task-id", TASK, cwd=tmp_git_repo)
    run_script("recovery.py", "record-failure", "--task-id", TASK, cwd=tmp_git_repo)
    run_script("recovery.py", "record-success", "--task-id", TASK, cwd=tmp_git_repo)

    proc = run_script("recovery.py", "record-failure", "--task-id", TASK, cwd=tmp_git_repo)
    assert proc.returncode == 0
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "ALLOW"
    assert payload["metadata"]["budget"]["exhausted"] is False
    assert payload["metadata"]["budget"]["counts"]["consecutive_failures"] == 1


# --------------------------------------------------------------------------- #
# 3. L5 立即 Hard Stop
# --------------------------------------------------------------------------- #

def test_l5_hard_stop(tmp_git_repo: Path):
    proc = run_script("recovery.py", "record-failure", "--task-id", TASK, "--level", "L5", cwd=tmp_git_repo)
    assert proc.returncode == 1
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "DENY"
    assert payload["code"] == "HARD_STOP_SECURITY"
    assert payload["status"] == "FAIL"


# --------------------------------------------------------------------------- #
# 4. L6 为 REQUIRE_APPROVAL
# --------------------------------------------------------------------------- #

def test_l6_require_approval(tmp_git_repo: Path):
    proc = run_script("recovery.py", "record-failure", "--task-id", TASK, "--level", "L6", cwd=tmp_git_repo)
    assert proc.returncode == 1
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "REQUIRE_APPROVAL"
    assert payload["code"] == "HARD_STOP_UNKNOWN"
    assert payload["status"] == "PASS"


# --------------------------------------------------------------------------- #
# 5. --max-attempts 通过 .safecode.yml 配置生效
# --------------------------------------------------------------------------- #

def test_config_max_attempts(tmp_git_repo: Path):
    write_file(tmp_git_repo / ".safecode.yml", "\n".join([
        "schema_version: \"1.0\"",
        "recovery:",
        "  max_recovery_attempts: 2",
        "  max_total_test_runs: 20",
        "  max_total_recoveries: 10",
        "  max_total_time: \"30m\"",
        "",
    ]))
    run_script("recovery.py", "record-failure", "--task-id", TASK, cwd=tmp_git_repo)
    proc = run_script("recovery.py", "record-failure", "--task-id", TASK, cwd=tmp_git_repo)
    assert proc.returncode == 1
    payload = parse_json_output(proc)
    assert payload["code"] == "BUDGET_EXHAUSTED"
    assert "max_recovery_attempts" in payload["metadata"]["budget"]["exhausted_reason"]


# --------------------------------------------------------------------------- #
# 6. max_total_test_runs 耗尽判定
# --------------------------------------------------------------------------- #

def test_max_total_test_runs(tmp_git_repo: Path):
    write_file(tmp_git_repo / ".safecode.yml", "\n".join([
        "schema_version: \"1.0\"",
        "recovery:",
        "  max_recovery_attempts: 100",
        "  max_total_test_runs: 2",
        "  max_total_recoveries: 100",
        "  max_total_time: \"30m\"",
        "",
    ]))
    run_script("recovery.py", "record-failure", "--type", "test_run", "--task-id", TASK, cwd=tmp_git_repo)
    proc = run_script("recovery.py", "record-failure", "--type", "test_run", "--task-id", TASK, cwd=tmp_git_repo)
    assert proc.returncode == 1
    payload = parse_json_output(proc)
    assert payload["code"] == "BUDGET_EXHAUSTED"
    assert "max_total_test_runs" in payload["metadata"]["budget"]["exhausted_reason"]
    # 诊断报告存在且包含停止 / Push
    report = tmp_git_repo / ".safecode" / "diagnostic-report.md"
    assert report.exists()
    text = report.read_text(encoding="utf-8")
    assert "停止" in text and "Push" in text


# --------------------------------------------------------------------------- #
# 7. 状态文件损坏（非法 JSON）→ 退出码 4
# --------------------------------------------------------------------------- #

def test_corrupt_state_exit4(tmp_git_repo: Path):
    state_dir = tmp_git_repo / ".safecode" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / f"{TASK}.json").write_text("{ this is not valid json", encoding="utf-8")

    proc = run_script("recovery.py", "status", "--task-id", TASK, cwd=tmp_git_repo)
    assert proc.returncode == 4
    payload = parse_json_output(proc)
    assert payload["code"] == "BUDGET_STATE_CORRUPT"
    assert payload["decision"] == "DENY"
    assert payload["status"] == "FAIL"


# --------------------------------------------------------------------------- #
# 8. 并发递增不丢更新（两个进程同时 record-failure，最终计数 == 2）
# --------------------------------------------------------------------------- #

def test_concurrent_increment_no_lost_update(tmp_git_repo: Path):
    env = child_env({})
    procs = []
    for _ in range(2):
        p = subprocess.Popen(
            [PYTHON, str(SCRIPTS_DIR / "recovery.py"), "record-failure", "--task-id", TASK],
            cwd=str(tmp_git_repo),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        procs.append(p)
    for p in procs:
        p.wait(timeout=60)

    state_file = tmp_git_repo / ".safecode" / "state" / f"{TASK}.json"
    assert state_file.exists(), "state file must exist after concurrent runs"
    data = json.loads(state_file.read_text(encoding="utf-8"))
    # 默认 --type recovery → recoveries +1，consecutive_failures +1（不消耗 test_runs）
    assert data["recoveries"] == 2, data
    assert data["consecutive_failures"] == 2, data
    assert data["test_runs"] == 0, data


# --------------------------------------------------------------------------- #
# 9. 每个子命令 stdout 都符合 Structured JSON
# --------------------------------------------------------------------------- #

def test_subcommands_schema(tmp_git_repo: Path):
    commands = [
        ["record-success", "--task-id", TASK],
        ["status", "--task-id", TASK],
        ["reset", "--task-id", TASK],
        ["report", "--task-id", TASK],
    ]
    for cmd in commands:
        proc = run_script("recovery.py", *cmd, cwd=tmp_git_repo)
        assert proc.returncode in (0, 1, 2, 3, 4), (cmd, proc.returncode, proc.stderr)
        payload = parse_json_output(proc)
        assert_result_schema(payload)

    # record-failure 也要符合
    proc = run_script("recovery.py", "record-failure", "--task-id", TASK, cwd=tmp_git_repo)
    assert_result_schema(parse_json_output(proc))


# --------------------------------------------------------------------------- #
# 10. --json 时 stdout 合法 JSON 且 stderr 无人类日志
# --------------------------------------------------------------------------- #

def test_json_silent_stderr(tmp_git_repo: Path):
    proc = run_script("recovery.py", "record-failure", "--task-id", TASK, "--json", cwd=tmp_git_repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.stderr.strip() == "", f"stderr must be empty with --json: {proc.stderr!r}"


# --------------------------------------------------------------------------- #
# 11. reset 清空状态
# --------------------------------------------------------------------------- #

def test_reset_clears_state(tmp_git_repo: Path):
    run_script("recovery.py", "record-failure", "--task-id", TASK, cwd=tmp_git_repo)
    run_script("recovery.py", "reset", "--task-id", TASK, cwd=tmp_git_repo)
    proc = run_script("recovery.py", "status", "--task-id", TASK, cwd=tmp_git_repo)
    payload = parse_json_output(proc)
    assert payload["metadata"]["budget"]["counts"]["recoveries"] == 0
    assert payload["metadata"]["budget"]["counts"]["consecutive_failures"] == 0
