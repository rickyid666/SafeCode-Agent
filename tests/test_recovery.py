"""recovery.py 的黑盒测试。

覆盖：连续失败达到上限返回 10 并生成诊断报告、record-success 归零、
L5 立即达上限、--max-attempts 自定义阈值、状态文件 consecutive_failures 正确。
"""

import json
from pathlib import Path

from conftest import py


def _state(repo_dir):
    p = Path(repo_dir) / ".safecode" / "recovery-state.json"
    assert p.exists(), f"状态文件缺失: {p}"
    return json.loads(p.read_text())


def test_consecutive_failures_reach_limit(recovery_script, tmp_path):
    s = str(recovery_script)
    rc1, _, _ = py([s, "record-failure", "--level", "L1"], cwd=tmp_path)
    rc2, _, _ = py([s, "record-failure", "--level", "L1"], cwd=tmp_path)
    rc3, _, _ = py([s, "record-failure", "--level", "L1"], cwd=tmp_path)

    assert rc1 == 0, f"第一次失败应记 0，实际 {rc1}"
    assert rc2 == 0, f"第二次失败应记 0，实际 {rc2}"
    assert rc3 == 10, f"第三次失败应达上限 10，实际 {rc3}"

    report = Path(tmp_path) / ".safecode" / "diagnostic-report.md"
    assert report.exists(), "达上限应生成诊断报告"
    content = report.read_text(encoding="utf-8", errors="replace")
    assert ("停止" in content) or ("Push" in content), "诊断报告应含 '停止' 或 'Push'"


def test_record_success_resets(recovery_script, tmp_path):
    s = str(recovery_script)
    py([s, "record-failure", "--level", "L1"], cwd=tmp_path)
    py([s, "record-success"], cwd=tmp_path)
    rc, out, err = py([s, "status"], cwd=tmp_path)
    assert rc == 0, f"status 应成功，实际 {rc}; err={err}"
    assert _state(tmp_path)["consecutive_failures"] == 0


def test_l5_immediate_limit(recovery_script, tmp_path):
    s = str(recovery_script)
    rc, out, err = py([s, "record-failure", "--level", "L5"], cwd=tmp_path)
    assert rc == 10, f"L5 应立即达上限 10，实际 {rc}; out={out}; err={err}"


def test_custom_max_attempts(recovery_script, tmp_path):
    s = str(recovery_script)
    rc1, _, _ = py([s, "record-failure", "--level", "L1", "--max-attempts", "2"], cwd=tmp_path)
    rc2, _, _ = py([s, "record-failure", "--level", "L1", "--max-attempts", "2"], cwd=tmp_path)
    assert rc1 == 0, f"第一次失败应记 0，实际 {rc1}"
    assert rc2 == 10, f"第二次失败应达上限 10，实际 {rc2}"


def test_state_file_consecutive_failures(recovery_script, tmp_path):
    s = str(recovery_script)
    py([s, "record-failure", "--level", "L1"], cwd=tmp_path)
    py([s, "record-failure", "--level", "L1"], cwd=tmp_path)
    state = _state(tmp_path)
    assert state["consecutive_failures"] == 2
