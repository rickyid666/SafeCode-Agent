"""schemas 与核心脚本输出的契约测试。

覆盖：
- schemas/result-1.0.json 与 schemas/config-1.0.json 本身是合法 JSON Schema 结构
  （顶层 $schema 存在，required / enum / properties 齐全）
- safecode_common.validate_result_dict 与 schema 文件一致：构造合法 / 非法样例逐一断言
- 每个核心脚本（security scan / recover status / decision，以及并行开发中暂未对齐内核的
  test run / git guard / dependency check）跑一次并断言输出符合 schema；
  未实现 / 尚未对齐内核的脚本按契约 pytest.skip
- 所有脚本在 --json 模式下 stdout 是单个合法 JSON 对象（不混入人类日志）

纯 pytest，无第三方依赖。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from conftest import (
    SCHEMAS_DIR,
    SCRIPTS_DIR,
    assert_result_schema,
    parse_json_output,
    run_script,
)

# 让测试进程也能 import scripts/ 下的共享内核
sys.path.insert(0, str(SCRIPTS_DIR))

from safecode_common import validate_result_dict  # noqa: E402


# --------------------------------------------------------------------------- #
# 1. 两个 schema 文件本身是合法 JSON Schema 结构
# --------------------------------------------------------------------------- #

def test_result_schema_structure():
    data = json.loads((SCHEMAS_DIR / "result-1.0.json").read_text(encoding="utf-8"))
    assert data.get("$schema", "").startswith("https://json-schema.org/")
    assert data.get("type") == "object"
    required = data.get("required", [])
    for field in ("schema_version", "status", "decision", "severity",
                  "category", "code", "message", "locations", "metadata"):
        assert field in required, f"result schema 缺少 required 字段: {field}"
    props = data.get("properties", {})
    assert set(props["status"]["enum"]) == {"PASS", "FAIL", "DEGRADED"}
    assert set(props["decision"]["enum"]) == {"ALLOW", "DENY", "REQUIRE_APPROVAL"}
    assert set(props["severity"]["enum"]) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert props["code"]["pattern"] == "^[A-Z0-9_]+$"
    loc_item = props["locations"]["items"]
    assert "file" in loc_item.get("required", [])
    assert props["metadata"]["type"] == "object"


def test_config_schema_structure():
    data = json.loads((SCHEMAS_DIR / "config-1.0.json").read_text(encoding="utf-8"))
    assert data.get("$schema", "").startswith("https://json-schema.org/")
    assert data.get("type") == "object"
    assert "schema_version" in data.get("required", [])
    props = data.get("properties", {})
    assert "security" in props
    sec = props["security"].get("properties", {})
    assert "ignore_paths" in sec
    ip = sec["ignore_paths"]["items"]
    assert ".git" in ip.get("pattern", "")


# --------------------------------------------------------------------------- #
# 2. validate_result_dict 与 schema 一致
# --------------------------------------------------------------------------- #

def _valid_result() -> dict:
    return {
        "schema_version": "1.0",
        "status": "PASS",
        "decision": "ALLOW",
        "severity": "LOW",
        "category": "SECURITY",
        "code": "CHECK_PASSED",
        "message": "ok",
        "locations": [],
        "metadata": {},
    }


def test_validate_result_dict_valid():
    ok, errors = validate_result_dict(_valid_result())
    assert ok, f"合法结果应校验通过: {errors}"
    assert errors == []


def test_validate_result_dict_missing_field():
    payload = _valid_result()
    del payload["code"]
    ok, errors = validate_result_dict(payload)
    assert not ok
    assert any("code" in e for e in errors)


def test_validate_result_dict_bad_status():
    payload = _valid_result()
    payload["status"] = "MAYBE"
    ok, errors = validate_result_dict(payload)
    assert not ok
    assert any("status" in e for e in errors)


def test_validate_result_dict_lowercase_code():
    payload = _valid_result()
    payload["code"] = "check_passed"
    ok, errors = validate_result_dict(payload)
    assert not ok
    assert any("code" in e for e in errors)


def test_validate_result_dict_bad_locations():
    payload = _valid_result()
    payload["locations"] = "not-an-array"
    ok, _ = validate_result_dict(payload)
    assert not ok

    payload2 = _valid_result()
    payload2["locations"] = [{"line": 1}]
    ok2, _ = validate_result_dict(payload2)
    assert not ok2

    payload3 = _valid_result()
    payload3["locations"] = [{"file": "a", "line": 0}]
    ok3, _ = validate_result_dict(payload3)
    assert not ok3


def test_validate_result_dict_metadata_not_object():
    payload = _valid_result()
    payload["metadata"] = []
    ok, _ = validate_result_dict(payload)
    assert not ok


def test_validate_result_dict_bad_severity_and_decision():
    for key, val in (("severity", "INFO"), ("decision", "YES"), ("category", "")):
        payload = _valid_result()
        payload[key] = val
        ok, errors = validate_result_dict(payload)
        assert not ok, f"{key}={val} 应无效"


# --------------------------------------------------------------------------- #
# 3. 核心脚本输出符合 schema
# --------------------------------------------------------------------------- #

# 每个路由给出"可以安全调用"的参数：断言的是输出契约，不是业务流程。
# 注意 "test run" 不能不带目标地调用——那会在测试里递归跑整个测试套件。
IMPLEMENTED_ROUTES = [
    ("security scan", ["security", "scan"]),
    ("recover status", ["recover", "status", "--task-id", "schema-test"]),
    ("decision", ["decision"]),
    ("test run (no target)", ["test", "run", "tests/__no_such_target__.py", "--no-flaky"]),
    ("git guard", ["git", "guard", "--status"]),
    ("dependency check", ["dependency", "check", "--scope", "all", "--no-external"]),
]


@pytest.mark.parametrize("label,route", IMPLEMENTED_ROUTES)
def test_core_script_schema(label, route, tmp_path):
    proc = run_script("safecode.py", *route, "--json", cwd=tmp_path)
    payload = parse_json_output(proc)
    assert_result_schema(payload)


def test_security_scan_clean_emits_schema(tmp_git_repo):
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=tmp_git_repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 0
    assert payload["status"] == "PASS"


# --------------------------------------------------------------------------- #
# 4. --json 模式下 stdout 是单个合法 JSON 对象
# --------------------------------------------------------------------------- #

def _assert_single_json(proc):
    text = proc.stdout
    stripped = text.strip()
    assert stripped, f"stdout 不应为空; stderr={proc.stderr!r}"
    obj = json.loads(stripped)
    assert isinstance(obj, dict)
    non_empty = [ln for ln in text.splitlines() if ln.strip()]
    assert len(non_empty) == 1, f"stdout 应只有一个 JSON 对象, 实际 {len(non_empty)} 行"


def test_json_only_single_object_security_scan(tmp_git_repo):
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=tmp_git_repo)
    _assert_single_json(proc)


def test_json_only_single_object_routed(tmp_path):
    proc = run_script("safecode.py", "security", "scan", "--staged", "--json",
                      "--no-external", cwd=tmp_path)
    _assert_single_json(proc)


def test_json_only_single_object_decision(tmp_path):
    proc = run_script("safecode.py", "decision", "--json", stdin_text="", cwd=tmp_path)
    _assert_single_json(proc)


def test_human_log_silenced_in_json_mode(tmp_git_repo):
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external",
                      "--verbose", cwd=tmp_git_repo)
    _assert_single_json(proc)
