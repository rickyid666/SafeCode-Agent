"""safecode_config.py 与 .safecode.yml 校验行为的测试。

覆盖两类输入：
1. YAML 子集解析器的边界（不支持的语法必须 fail-closed，不能猜值）
2. 配置校验的核心不变量（不得被项目配置静默关闭）
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from conftest import (
    EXIT_FINDING,
    EXIT_OK,
    EXIT_USAGE,
    SCRIPTS_DIR,
    parse_json_output,
    run_script,
    write_file,
)

sys.path.insert(0, str(SCRIPTS_DIR))

from safecode_config import (  # noqa: E402
    CODE_CONFIG_PARSE_ERROR,
    CODE_CONFIG_SCHEMA_INVALID,
    ConfigError,
    DEFAULT_CONFIG,
    load_config,
    parse_yaml_subset,
    validate_config,
)

VALID_CONFIG = """schema_version: "1.0"

security:
  mode: default
  native:
    enabled: true
  external_scanners:
    enabled: true
    required_in_ci: true
    tools:
      - gitleaks
      - trufflehog
      - detect-secrets
  ignore_paths:
    - docs/generated/
    - build/
  allow_list:
    - rule: EXAMPLE_TOKEN
      path: tests/fixtures/example.txt
      reason: "Non-secret fixture"
      expires: "2099-12-31"
  custom_rules: []

testing:
  flaky_detection:
    enabled: true
    reruns: 3

recovery:
  max_recovery_attempts: 3
  max_total_test_runs: 20
  max_total_recoveries: 10
  max_total_time: 30m

git:
  protected_branches:
    - main
    - master
  require_pre_push_hook: true
  require_ci: true
  allow_force_push: false
  allow_history_rewrite: false

project:
  name: "example"
  bootstrap_mode: false
  self_hosting: true
"""


# --------------------------------------------------------------------------- #
# 解析器
# --------------------------------------------------------------------------- #

def test_documented_config_parses() -> None:
    data = parse_yaml_subset(VALID_CONFIG)
    assert data["schema_version"] == "1.0"
    assert data["security"]["native"]["enabled"] is True
    assert data["security"]["ignore_paths"] == ["docs/generated/", "build/"]
    assert isinstance(data["security"]["allow_list"], list)
    entry = data["security"]["allow_list"][0]
    assert entry["rule"] == "EXAMPLE_TOKEN"
    assert entry["reason"] == "Non-secret fixture"
    assert entry["expires"] == "2099-12-31"
    assert data["security"]["external_scanners"]["tools"] == [
        "gitleaks", "trufflehog", "detect-secrets"]
    assert data["recovery"]["max_total_time"] == "30m"
    assert data["git"]["protected_branches"] == ["main", "master"]
    assert data["project"]["self_hosting"] is True
    assert validate_config(data) == []


def test_empty_flow_collections_and_comments() -> None:
    text = "schema_version: \"1.0\"\nsecurity:\n  ignore_paths: []  # none\n  custom_rules: {}\n"
    data = parse_yaml_subset(text)
    assert data["security"]["ignore_paths"] == []
    assert data["security"]["custom_rules"] == {}


@pytest.mark.parametrize("text", [
    "schema_version: \"1.0\"\n---\nsecurity: {}\n",          # 多文档
    "schema_version: \"1.0\"\nsecurity:\n  tools: [a, b]\n",  # 非空 flow 集合
    "schema_version: \"1.0\"\nbase: &anchor\n  a: 1\n",       # 锚点
    "schema_version: \"1.0\"\nref: *anchor\n",                # 别名
    "schema_version: \"1.0\"\nscript: |\n  echo hi\n",        # 块标量
])
def test_unsupported_yaml_constructs_fail_closed(text: str) -> None:
    with pytest.raises(ConfigError) as excinfo:
        parse_yaml_subset(text)
    assert excinfo.value.code == CODE_CONFIG_PARSE_ERROR


def test_tab_indentation_rejected() -> None:
    with pytest.raises(ConfigError) as excinfo:
        parse_yaml_subset("schema_version: \"1.0\"\nsecurity:\n\tmode: default\n")
    assert excinfo.value.code == CODE_CONFIG_PARSE_ERROR


# --------------------------------------------------------------------------- #
# 校验：核心不变量不得被静默关闭
# --------------------------------------------------------------------------- #

def _base(**security_overrides):
    data = {"schema_version": "1.0", "security": dict(security_overrides)}
    return data


def test_missing_schema_version_is_invalid() -> None:
    errors = validate_config({"security": {"mode": "default"}})
    assert any("schema_version" in e for e in errors)


def test_wrong_schema_version_is_invalid() -> None:
    errors = validate_config({"schema_version": "2.0"})
    assert any("unsupported schema_version" in e for e in errors)


def test_native_gate_cannot_be_disabled() -> None:
    errors = validate_config(_base(native={"enabled": False}))
    assert any("core invariant" in e for e in errors)


def test_allow_list_wildcard_rejected() -> None:
    errors = validate_config(_base(allow_list=[
        {"rule": "*", "path": "a.txt", "reason": "turn it off"}]))
    assert any("'*'" in e for e in errors)


def test_allow_list_requires_reason() -> None:
    errors = validate_config(_base(allow_list=[
        {"rule": "EXAMPLE_TOKEN", "path": "a.txt", "reason": ""}]))
    assert any("reason" in e for e in errors)


def test_allow_list_bad_expiry_rejected() -> None:
    errors = validate_config(_base(allow_list=[
        {"rule": "EXAMPLE_TOKEN", "path": "a.txt", "reason": "fixture",
         "expires": "next tuesday"}]))
    assert any("expires" in e for e in errors)


def test_ignore_paths_cannot_cover_git_or_root() -> None:
    for bad in (".git", ".git/objects", "/", "*"):
        errors = validate_config(_base(ignore_paths=[bad]))
        assert errors, f"ignore_paths entry {bad!r} must be rejected"


def test_git_invariants_cannot_be_enabled() -> None:
    errors = validate_config({"schema_version": "1.0",
                              "git": {"allow_force_push": True}})
    assert any("allow_force_push" in e for e in errors)
    errors = validate_config({"schema_version": "1.0",
                              "git": {"allow_history_rewrite": True}})
    assert any("allow_history_rewrite" in e for e in errors)


def test_type_errors_detected() -> None:
    assert validate_config({"schema_version": "1.0",
                            "recovery": {"max_total_test_runs": 0}})
    assert validate_config({"schema_version": "1.0",
                            "recovery": {"max_total_time": "half an hour"}})
    assert validate_config({"schema_version": "1.0",
                            "testing": {"flaky_detection": {"reruns": 99}}})
    assert validate_config({"schema_version": "1.0",
                            "security": {"external_scanners": {"tools": ["nope"]}}})
    assert validate_config({"schema_version": "1.0",
                            "security": {"custom_rules": [{"id": "x", "pattern": "("}]}})


def test_unknown_top_level_keys_tolerated() -> None:
    """SafeCode 允许扩展段（例如 dependencies），未知顶层键不应导致配置非法。"""
    data = {"schema_version": "1.0", "dependencies": {"require_lockfile": True}}
    assert validate_config(data) == []


# --------------------------------------------------------------------------- #
# load_config
# --------------------------------------------------------------------------- #

def test_load_config_defaults_when_missing(tmp_path: Path) -> None:
    config = load_config(None, str(tmp_path))
    assert config.loaded is False
    assert config.get("recovery.max_total_test_runs") == DEFAULT_CONFIG["recovery"]["max_total_test_runs"]
    assert config.protected_branches == ["main", "master"]


def test_load_config_reads_and_validates(tmp_path: Path) -> None:
    path = write_file(tmp_path / ".safecode.yml", VALID_CONFIG)
    config = load_config(None, str(tmp_path))
    assert config.loaded is True
    assert config.path == str(path)
    assert config.allow_list[0]["rule"] == "EXAMPLE_TOKEN"
    assert config.ignore_paths == ["docs/generated/", "build/"]
    assert config.budget_limits["max_recovery_attempts"] == 3


def test_load_config_rejects_invalid(tmp_path: Path) -> None:
    write_file(tmp_path / ".safecode.yml", "schema_version: \"1.0\"\nsecurity:\n  native:\n    enabled: false\n")
    with pytest.raises(ConfigError) as excinfo:
        load_config(None, str(tmp_path))
    assert excinfo.value.code == CODE_CONFIG_SCHEMA_INVALID


def test_load_config_explicit_missing_path(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config(str(tmp_path / "nope.yml"), str(tmp_path))
    assert excinfo.value.code == CODE_CONFIG_SCHEMA_INVALID


# --------------------------------------------------------------------------- #
# CLI 层：坏配置必须 exit 2 + DENY，而不是"忽略错误配置继续跑"
# --------------------------------------------------------------------------- #

def test_cli_rejects_broken_config(tmp_path: Path) -> None:
    bad = write_file(tmp_path / "broken.yml", "schema_version: \"1.0\"\nsecurity:\n  tools: [a]\n")
    proc = run_script("security-scan.py", "--all", "--config", str(bad), "--json",
                      cwd=tmp_path)
    assert proc.returncode == EXIT_USAGE, proc.stderr
    payload = parse_json_output(proc)
    assert payload["status"] == "FAIL"
    assert payload["decision"] == "DENY"
    assert payload["code"] in ("CONFIG_PARSE_ERROR", "CONFIG_SCHEMA_INVALID")


def test_cli_rejects_invariant_violation(tmp_path: Path) -> None:
    bad = write_file(tmp_path / "invariant.yml",
                     "schema_version: \"1.0\"\nsecurity:\n  allow_list:\n    - rule: \"*\"\n      path: \"*\"\n      reason: \"disable everything\"\n")
    proc = run_script("security-scan.py", "--all", "--config", str(bad), "--json",
                      cwd=tmp_path)
    assert proc.returncode == EXIT_USAGE
    payload = parse_json_output(proc)
    assert payload["decision"] == "DENY"


def test_cli_accepts_valid_config(tmp_path: Path) -> None:
    write_file(tmp_path / ".safecode.yml", VALID_CONFIG)
    write_file(tmp_path / "app.py", "print('hello')\n")
    proc = run_script("security-scan.py", "--all", "--no-external", "--json", cwd=tmp_path)
    assert proc.returncode == EXIT_OK, proc.stderr
    payload = parse_json_output(proc)
    assert payload["decision"] == "ALLOW"
