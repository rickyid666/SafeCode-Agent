"""dependency-guard.py 的黑盒测试：供应链门禁行为。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from conftest import (
    EXIT_FINDING,
    EXIT_OK,
    EXIT_TOOL,
    GIT_BIN_DIR,
    assert_result_schema,
    git,
    parse_json_output,
    run_script,
    write_file,
)

SCRIPT = "dependency-guard.py"

PACKAGE_JSON = """{
  "name": "demo",
  "version": "1.0.0",
  "dependencies": {
    "left-pad": "^1.0.0"
  }
}
"""

PACKAGE_LOCK = """{
  "name": "demo",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo", "dependencies": {"left-pad": "^1.0.0"}},
    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
  }
}
"""

PACKAGE_LOCK_EVIL_REGISTRY = """{
  "name": "demo",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo", "dependencies": {"left-pad": "^1.0.0"}},
    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://evil-mirror.example.com/left-pad.tgz"}
  }
}
"""


def minimal_path_env() -> dict:
    """收窄 PATH：保留 Python 与 git，但确保外部扫描器一定"不可用"。

    注意不能把 git 一起踢掉——那会让"取不到变更集"而不是"扫描器缺失"，
    测的东西就跑偏了。
    """
    parts = [str(Path(sys.executable).parent)]
    if GIT_BIN_DIR:
        parts.append(GIT_BIN_DIR)
    return {"PATH": os.pathsep.join(parts)}


def make_node_project(tmp_path: Path, *, lock: str | None = PACKAGE_LOCK,
                      config: str = "") -> Path:
    project = tmp_path / "node-project"
    write_file(project / "package.json", PACKAGE_JSON)
    if lock is not None:
        write_file(project / "package-lock.json", lock)
    if config:
        write_file(project / ".safecode.yml", config)
    return project


def test_missing_lockfile_is_denied(tmp_path: Path) -> None:
    project = make_node_project(tmp_path, lock=None)
    proc = run_script(SCRIPT, "--scope", "all", "--no-external", "--json",
                      cwd=project, env=minimal_path_env())
    assert proc.returncode == EXIT_FINDING, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "DENY"
    assert payload["code"] == "LOCKFILE_MISSING"


def test_consistent_project_passes(tmp_path: Path) -> None:
    project = make_node_project(tmp_path)
    proc = run_script(SCRIPT, "--scope", "all", "--no-external", "--json",
                      cwd=project, env=minimal_path_env())
    assert proc.returncode == EXIT_OK, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["status"] == "PASS"
    assert payload["decision"] == "ALLOW"
    assert payload["metadata"]["ecosystems_present"] == ["node"]


def test_manifest_change_without_lockfile_is_drift(tmp_path: Path) -> None:
    project = make_node_project(tmp_path)
    git(["init", "-b", "main"], project)
    git(["config", "user.email", "safecode@example.invalid"], project)
    git(["config", "user.name", "SafeCode Test"], project)
    git(["add", "-A"], project)
    git(["commit", "-m", "init"], project)

    write_file(project / "package.json", PACKAGE_JSON.replace("^1.0.0", "^9.9.9"))
    git(["add", "package.json"], project)

    proc = run_script(SCRIPT, "--scope", "staged", "--no-external", "--json",
                      cwd=project, env=minimal_path_env())
    assert proc.returncode == EXIT_FINDING
    payload = parse_json_output(proc)
    assert payload["code"] == "DEPENDENCY_DRIFT"
    assert payload["decision"] == "DENY"


def test_lockfile_changed_alone_requires_approval(tmp_path: Path) -> None:
    project = make_node_project(tmp_path)
    git(["init", "-b", "main"], project)
    git(["config", "user.email", "safecode@example.invalid"], project)
    git(["config", "user.name", "SafeCode Test"], project)
    git(["add", "-A"], project)
    git(["commit", "-m", "init"], project)

    write_file(project / "package-lock.json", PACKAGE_LOCK.replace("1.3.0", "1.3.1"))
    git(["add", "package-lock.json"], project)

    proc = run_script(SCRIPT, "--scope", "staged", "--no-external", "--json",
                      cwd=project, env=minimal_path_env())
    assert proc.returncode == EXIT_FINDING
    payload = parse_json_output(proc)
    assert payload["decision"] == "REQUIRE_APPROVAL"
    assert payload["code"] == "LOCKFILE_UNEXPECTED_CHANGE"


def test_forbidden_package_is_denied(tmp_path: Path) -> None:
    config = (
        "schema_version: \"1.0\"\n"
        "dependencies:\n"
        "  require_lockfile: true\n"
        "  forbidden_packages:\n"
        "    - left-pad\n"
    )
    project = make_node_project(tmp_path, config=config)
    proc = run_script(SCRIPT, "--scope", "all", "--no-external", "--json",
                      cwd=project, env=minimal_path_env())
    assert proc.returncode == EXIT_FINDING
    payload = parse_json_output(proc)
    assert payload["code"] == "FORBIDDEN_DEPENDENCY"


def test_disallowed_registry_is_denied(tmp_path: Path) -> None:
    config = (
        "schema_version: \"1.0\"\n"
        "dependencies:\n"
        "  allowed_registries:\n"
        "    - registry.npmjs.org\n"
    )
    project = make_node_project(tmp_path, lock=PACKAGE_LOCK_EVIL_REGISTRY, config=config)
    proc = run_script(SCRIPT, "--scope", "all", "--no-external", "--json",
                      cwd=project, env=minimal_path_env())
    assert proc.returncode == EXIT_FINDING
    payload = parse_json_output(proc)
    assert payload["code"] == "DISALLOWED_REGISTRY"


def test_scanner_unavailable_is_degraded_locally(tmp_path: Path) -> None:
    """LOCAL 非严格模式：外部扫描器缺失 -> DEGRADED，但绝不是 PASS。"""
    project = make_node_project(tmp_path)
    proc = run_script(SCRIPT, "--scope", "all", "--json",
                      cwd=project, env=minimal_path_env())
    assert proc.returncode == EXIT_OK
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["status"] == "DEGRADED"
    assert payload["code"] == "DEPENDENCY_SCANNER_UNAVAILABLE"
    assert payload["metadata"]["scanner"]["status"] == "unavailable"


def test_scanner_unavailable_is_denied_in_strict(tmp_path: Path) -> None:
    """STRICT / CI：外部扫描器缺失 -> DENY，供应链检查视为未完成。"""
    config = (
        "schema_version: \"1.0\"\n"
        "dependencies:\n"
        "  external_scanner:\n"
        "    enabled: true\n"
        "    required_in_ci: true\n"
        "    tools:\n"
        "      - osv-scanner\n"
    )
    project = make_node_project(tmp_path, config=config)
    proc = run_script(SCRIPT, "--scope", "all", "--strict", "--json",
                      cwd=project, env=minimal_path_env())
    assert proc.returncode == EXIT_TOOL, proc.stderr
    payload = parse_json_output(proc)
    assert payload["status"] == "FAIL"
    assert payload["decision"] == "DENY"
    assert payload["code"] == "DEPENDENCY_SCANNER_UNAVAILABLE"


def test_python_manifest_without_lockfile_is_denied(tmp_path: Path) -> None:
    project = tmp_path / "py-project"
    write_file(project / "pyproject.toml", "[project]\nname = \"demo\"\n")
    proc = run_script(SCRIPT, "--scope", "all", "--no-external", "--json",
                      cwd=project, env=minimal_path_env())
    payload = parse_json_output(proc)
    assert payload["code"] == "LOCKFILE_MISSING"
    assert payload["decision"] == "DENY"


def test_unknown_arguments_exit_two(tmp_path: Path) -> None:
    project = make_node_project(tmp_path)
    proc = run_script(SCRIPT, "--scope", "nonsense", "--json",
                      cwd=project, env=minimal_path_env())
    assert proc.returncode == 2
