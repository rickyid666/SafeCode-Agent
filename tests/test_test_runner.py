"""test-runner.py 的黑盒测试。

覆盖：全绿退出 0、断言失败退出 1 且等级落在 {L1,L3,L6}、import 缺失退出 1。
等级字段按接口约定放宽到允许集合内（实现若归类不同不卡死）。
"""

import json
from pathlib import Path

from conftest import py

ALLOWED_FAILURE_LEVELS = {"L1", "L3", "L6"}


def _find_levels(obj):
    """递归收集 JSON 中所有形如 'Lx' 的等级字符串。"""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and v.startswith("L") and v[1:].isdigit():
                found.append(v)
            else:
                found.extend(_find_levels(v))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(_find_levels(v))
    return found


def _make_project(tmp_path, test_body):
    proj = tmp_path / "proj"
    tests = proj / "tests"
    tests.mkdir(parents=True)
    (tests / "test_sample.py").write_text(test_body)
    return proj


def test_passing_suite_exits_zero(test_runner_script, tmp_path):
    proj = _make_project(
        tmp_path, "def test_ok():\n    assert 1 + 1 == 2\n"
    )
    rc, out, err = py([str(test_runner_script), "--json"], cwd=proj)
    assert rc == 0, f"全绿应退出 0，实际 {rc}; out={out}; err={err}"


def test_assertion_failure_level(test_runner_script, tmp_path):
    proj = _make_project(
        tmp_path, "def test_fail():\n    assert 1 == 2\n"
    )
    rc, out, err = py([str(test_runner_script), "--json"], cwd=proj)
    assert rc == 1, f"断言失败应退出 1，实际 {rc}; out={out}; err={err}"

    data = _try_json(out, err)
    if data is not None:
        levels = _find_levels(data)
        assert levels, f"--json 应含等级字段; out={out}; err={err}"
        assert ALLOWED_FAILURE_LEVELS.intersection(levels), (
            f"失败等级应在 {ALLOWED_FAILURE_LEVELS} 内，实际 {levels}; out={out}"
        )


def test_import_error_level(test_runner_script, tmp_path):
    proj = _make_project(
        tmp_path, "import this_module_does_not_exist_xyz\n\ndef test_nothing():\n    pass\n"
    )
    rc, out, err = py([str(test_runner_script), "--json"], cwd=proj)
    assert rc == 1, f"import 缺失应退出 1，实际 {rc}; out={out}; err={err}"

    data = _try_json(out, err)
    if data is not None:
        levels = _find_levels(data)
        assert levels, f"--json 应含等级字段; out={out}; err={err}"
        assert ALLOWED_FAILURE_LEVELS.intersection(levels), (
            f"失败等级应在 {ALLOWED_FAILURE_LEVELS} 内，实际 {levels}; out={out}"
        )


def _try_json(out, err):
    for text in (out, err):
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            continue
    return None
