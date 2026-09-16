"""SafeCode Dependency Guard：依赖供应链的独立 Gate。

契约要求依赖检查拥有**独立门禁**，不能因为"Secret 扫描通过了"就认为供应链安全，
也不能因为本脚本自身不可用而声称供应链检查 PASS。

检查项：

1. manifest 声明了依赖但没有 lockfile           -> DENY (LOCKFILE_MISSING)
2. manifest 变了但 lockfile 没变（版本漂移）      -> DENY (DEPENDENCY_DRIFT)
3. lockfile 变了但 manifest 没变（可疑修改）      -> REQUIRE_APPROVAL
4. 命中禁止依赖清单                              -> DENY (FORBIDDEN_DEPENDENCY)
5. lockfile 里的 registry 不在允许清单内          -> DENY (DISALLOWED_REGISTRY)
6. lockfile 顶层包未在 manifest 中声明            -> DENY (UNDECLARED_DEPENDENCY)
7. 外部漏洞扫描器可用则调用，发现漏洞 -> DENY；
   不可用 / 执行异常 -> LOCAL 降级 DEGRADED，STRICT 或 required_in_ci 时 DENY。

配置（.safecode.yml，SafeCode 对 v1.0 配置模型的扩展，默认值即下面的 DEFAULT）：

    dependencies:
      require_lockfile: true
      forbidden_packages: []
      allowed_registries: []
      external_scanner:
        enabled: true
        required_in_ci: false
        tools:
          - osv-scanner
          - pip-audit

纯 Python 标准库。Python >= 3.10。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from safecode_common import (  # noqa: E402
    CATEGORY_DEPENDENCY,
    EXIT_FINDING,
    EXIT_OK,
    EXIT_TOOL,
    EXIT_USAGE,
    Reporter,
    add_common_arguments,
    approval_result,
    degraded_result,
    fail_deny_result,
    is_git_repo,
    make_result,
    pass_result,
    repo_root,
    reporter_from_args,
    resolve_mode,
    run_git,
    tool_error_result,
)
from safecode_config import ConfigError, load_config  # noqa: E402

CODE_LOCKFILE_MISSING = "LOCKFILE_MISSING"
CODE_DEPENDENCY_DRIFT = "DEPENDENCY_DRIFT"
CODE_LOCKFILE_UNEXPECTED_CHANGE = "LOCKFILE_UNEXPECTED_CHANGE"
CODE_FORBIDDEN_DEPENDENCY = "FORBIDDEN_DEPENDENCY"
CODE_DISALLOWED_REGISTRY = "DISALLOWED_REGISTRY"
CODE_UNDECLARED_DEPENDENCY = "UNDECLARED_DEPENDENCY"
CODE_LOCKFILE_OUT_OF_SYNC = "LOCKFILE_OUT_OF_SYNC"
CODE_VULNERABLE_DEPENDENCY = "VULNERABLE_DEPENDENCY"
CODE_DEPENDENCY_SCANNER_UNAVAILABLE = "DEPENDENCY_SCANNER_UNAVAILABLE"
CODE_DEPENDENCY_SCANNER_ERROR = "DEPENDENCY_SCANNER_ERROR"
CODE_DEPENDENCY_CLEAN = "DEPENDENCY_CLEAN"
CODE_DEPENDENCY_NO_MANIFEST = "DEPENDENCY_NO_MANIFEST"

DEFAULT_DEPENDENCY_CONFIG: Dict[str, Any] = {
    "require_lockfile": True,
    "forbidden_packages": [],
    "allowed_registries": [],
    "external_scanner": {
        "enabled": True,
        "required_in_ci": False,
        "tools": ["osv-scanner", "pip-audit"],
    },
}

# 生态定义：manifest -> 可接受的 lockfile
ECOSYSTEMS: Dict[str, Dict[str, Any]] = {
    "node": {
        "manifest": "package.json",
        "lockfiles": ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"],
    },
    "python": {
        "manifest": "pyproject.toml",
        "lockfiles": ["poetry.lock", "Pipfile.lock", "uv.lock", "requirements.txt"],
    },
    "go": {
        "manifest": "go.mod",
        "lockfiles": ["go.sum"],
    },
    "rust": {
        "manifest": "Cargo.toml",
        "lockfiles": ["Cargo.lock"],
    },
}

_REGISTRY_RE = re.compile(r"https?://([A-Za-z0-9._\-]+)(?:/[^\s\"']*)?")
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
              ".pytest_cache", ".mypy_cache"}


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #

def merge_dependency_config(config: Any) -> Dict[str, Any]:
    """从 Config 读取 dependencies 段（SafeCode 扩展），与默认值合并。"""
    merged = json.loads(json.dumps(DEFAULT_DEPENDENCY_CONFIG))
    raw = config.get("dependencies")
    if isinstance(raw, dict):
        for key, value in raw.items():
            if key == "external_scanner" and isinstance(value, dict):
                merged["external_scanner"].update(value)
            else:
                merged[key] = value
    return merged


def changed_files(root: str, scope: str) -> Tuple[List[str], str, bool]:
    """按 scope 返回变更文件。

    返回 (文件列表, 错误信息, 是否为用法错误)。

    重要：拿不到变更集时不能假装"没有变更"——那会让漂移检查静默失效。
    """
    if scope == "all":
        return [], "", False
    if not is_git_repo(root):
        return [], f"not inside a git repository: {root}", True

    files: List[str] = []
    if scope == "staged":
        proc = run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMRTD"], cwd=root)
        if proc.returncode != 0:
            return [], f"git diff --cached failed: {(proc.stderr or '').strip()[:200]}", False
        files = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
    elif scope == "worktree":
        proc = run_git(["diff", "--name-only"], cwd=root)
        if proc.returncode != 0:
            return [], f"git diff failed: {(proc.stderr or '').strip()[:200]}", False
        files = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
        status = run_git(["status", "--porcelain"], cwd=root)
        if status.returncode != 0:
            return [], f"git status failed: {(status.stderr or '').strip()[:200]}", False
        files += [line[3:].strip() for line in (status.stdout or "").splitlines()
                  if line.startswith("?? ")]
    return [f.replace("\\", "/") for f in files], "", False


def read_text(root: str, relative: str) -> Optional[str]:
    path = os.path.join(root, relative)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def parse_manifest_dependencies(ecosystem: str, text: str) -> List[str]:
    """尽力解析 manifest 中的直接依赖名（不追求完整语义）。"""
    if text is None:
        return []
    names: List[str] = []
    if ecosystem == "node":
        try:
            data = json.loads(text)
        except ValueError:
            return []
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            section = data.get(key)
            if isinstance(section, dict):
                names.extend(str(k) for k in section)
    elif ecosystem == "python":
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("[") or stripped.startswith("//"):
                continue
            match = re.match(r'^["\']?([A-Za-z0-9_.\-]+)["\']?\s*[<>=!~\[;]?', stripped)
            if match and match.group(1).lower() not in (
                "name", "version", "description", "requires-python", "readme",
                "dependencies", "optional-dependencies", "build-system", "requires",
                "authors", "license", "classifiers", "urls", "keywords",
            ):
                names.append(match.group(1))
    elif ecosystem == "go":
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("module"):
                continue
            match = re.match(r"^(?:require\s+)?([A-Za-z0-9._\-/]+)\s+v?[0-9]", stripped)
            if match:
                names.append(match.group(1))
    elif ecosystem == "rust":
        in_deps = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_deps = "dependencies" in stripped
                continue
            if in_deps and "=" in stripped:
                names.append(stripped.split("=", 1)[0].strip())
    return sorted({n for n in names if n})


def _node_package_name(key: str) -> str:
    """把 lockfile v2/v3 的 packages key 归一化为包名。

    "node_modules/left-pad"                  -> "left-pad"
    "node_modules/a/node_modules/@s/b"       -> "@s/b"
    """
    raw = str(key).replace("\\", "/").strip()
    if raw in ("", "."):
        return ""
    raw = raw.split("/node_modules/")[-1]
    if raw.startswith("node_modules/"):
        raw = raw[len("node_modules/"):]
    return raw.strip("/")


def node_lock_declared_dependencies(text: str) -> Optional[Set[str]]:
    """从 lockfile 根包（packages[""]）读取"本项目声明的依赖"。

    这是唯一可靠的对照面：packages 里的其他条目全是传递依赖，
    拿它们跟 manifest 比会得到一堆假阳性。
    """
    if not text:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return None
    root = packages.get("")
    if not isinstance(root, dict):
        return None
    names: Set[str] = set()
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = root.get(section)
        if isinstance(block, dict):
            names.update(str(k) for k in block)
    return names


def parse_lock_dependencies(ecosystem: str, text: str) -> List[str]:
    """尽力解析 lockfile 中的包名（含传递依赖），用于禁止依赖等扫描。"""
    if text is None:
        return []
    names: List[str] = []
    if ecosystem == "node":
        try:
            data = json.loads(text)
        except ValueError:
            return []
        packages = data.get("packages")
        if isinstance(packages, dict):
            for key in packages:
                name = _node_package_name(key)
                if name:
                    names.append(name)
        deps = data.get("dependencies")
        if isinstance(deps, dict):
            names.extend(str(k) for k in deps)
    elif ecosystem == "python":
        for line in text.splitlines():
            match = re.match(r'^\s*["\']?([A-Za-z0-9_.\-]+)["\']?\s*(?:==|>=|~=)', line)
            if match:
                names.append(match.group(1))
            match = re.match(r'^\s*name\s*=\s*["\']([^"\']+)["\']', line)
            if match:
                names.append(match.group(1))
    elif ecosystem == "go":
        for line in text.splitlines():
            match = re.match(r"^([A-Za-z0-9._\-/]+)\s+v[0-9]", line.strip())
            if match:
                names.append(match.group(1))
    elif ecosystem == "rust":
        for line in text.splitlines():
            match = re.match(r'^name\s*=\s*"([^"]+)"', line.strip())
            if match:
                names.append(match.group(1))
    return sorted({n for n in names if n})


def registries_in(text: str) -> List[str]:
    if not text:
        return []
    return sorted({m.group(1) for m in _REGISTRY_RE.finditer(text)})


# --------------------------------------------------------------------------- #
# 外部漏洞扫描器
# --------------------------------------------------------------------------- #

def discover_scanner(tools: Sequence[str]) -> Tuple[Optional[str], Optional[str]]:
    for tool in tools:
        found = shutil.which(tool)
        if found:
            return tool, found
    return None, None


def run_external_scanner(tool: str, path: str, root: str, timeout: int) -> Dict[str, Any]:
    """运行外部依赖漏洞扫描器。不可用 / 异常一律不 PASS。"""
    if tool == "osv-scanner":
        cmd = [path, "--format", "json", "-r", "."]
    elif tool == "pip-audit":
        cmd = [path, "--format", "json"]
    else:
        cmd = [path, "--version"]
    started = time.time()
    try:
        proc = subprocess.run(cmd, cwd=root, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True,
                              errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "error", "code": CODE_DEPENDENCY_SCANNER_ERROR,
                "message": f"{tool} timed out after {timeout}s", "vulnerabilities": []}
    except OSError as exc:
        return {"status": "error", "code": CODE_DEPENDENCY_SCANNER_ERROR,
                "message": f"{tool} cannot be executed: {exc}", "vulnerabilities": []}

    duration = round(time.time() - started, 2)
    if proc.returncode not in (0, 1):
        return {"status": "error", "code": CODE_DEPENDENCY_SCANNER_ERROR,
                "message": f"{tool} exited with {proc.returncode}: "
                           f"{(proc.stderr or '')[:200]}",
                "vulnerabilities": [], "duration_seconds": duration}

    vulnerabilities: List[Dict[str, Any]] = []
    try:
        combined = (proc.stdout or "").strip()
        if combined:
            payload = json.loads(combined)
            if tool == "osv-scanner":
                for result in payload.get("results", []) or []:
                    for package in result.get("packages", []) or []:
                        for group in package.get("vulnerabilities", []) or []:
                            vulnerabilities.append({
                                "package": (package.get("package") or {}).get("name", ""),
                                "id": group.get("id", ""),
                                "summary": (group.get("summary") or "")[:200],
                            })
            elif tool == "pip-audit":
                for dep in payload.get("dependencies", []) or []:
                    for vuln in dep.get("vulns", []) or []:
                        vulnerabilities.append({
                            "package": dep.get("name", ""),
                            "id": vuln.get("id", ""),
                            "summary": (vuln.get("description") or "")[:200],
                        })
    except ValueError as exc:
        return {"status": "error", "code": CODE_DEPENDENCY_SCANNER_ERROR,
                "message": f"{tool} output is not parseable JSON: {exc}",
                "vulnerabilities": [], "duration_seconds": duration}

    return {"status": "ok", "code": "", "message": "",
            "vulnerabilities": vulnerabilities, "duration_seconds": duration}


# --------------------------------------------------------------------------- #
# 主检查
# --------------------------------------------------------------------------- #

class Finding:
    def __init__(self, code: str, message: str, severity: str,
                 path: str = "", decision: str = "DENY") -> None:
        self.code = code
        self.message = message
        self.severity = severity
        self.path = path
        self.decision = decision

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message, "severity": self.severity,
                "path": self.path, "decision": self.decision}


def check_ecosystem(root: str, ecosystem: str, scope: str,
                    changed: Sequence[str], dep_config: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    spec = ECOSYSTEMS[ecosystem]
    manifest = spec["manifest"]
    manifest_text = read_text(root, manifest)
    if manifest_text is None:
        return findings

    lockfiles = [name for name in spec["lockfiles"] if read_text(root, name) is not None]
    manifest_changed = manifest in changed
    lock_changed = any(name in changed for name in spec["lockfiles"])

    if not lockfiles:
        if dep_config.get("require_lockfile", True):
            findings.append(Finding(
                CODE_LOCKFILE_MISSING,
                f"{manifest} exists but no lockfile found "
                f"(expected one of: {', '.join(spec['lockfiles'])})",
                "HIGH", manifest))
        return findings

    if scope != "all":
        if manifest_changed and not lock_changed:
            findings.append(Finding(
                CODE_DEPENDENCY_DRIFT,
                f"{manifest} changed but lockfile ({', '.join(lockfiles)}) did not: "
                "dependency versions may drift from the manifest",
                "HIGH", manifest))
        if lock_changed and not manifest_changed:
            findings.append(Finding(
                CODE_LOCKFILE_UNEXPECTED_CHANGE,
                f"lockfile ({', '.join(lockfiles)}) changed without a manifest change: "
                "confirm this modification is intentional",
                "MEDIUM", lockfiles[0], decision="REQUIRE_APPROVAL"))

    declared = parse_manifest_dependencies(ecosystem, manifest_text)
    locked = parse_lock_dependencies(ecosystem, read_text(root, lockfiles[0]) or "")

    forbidden = {str(p).lower() for p in dep_config.get("forbidden_packages", []) or []}
    for name in declared + locked:
        if name.lower() in forbidden:
            findings.append(Finding(
                CODE_FORBIDDEN_DEPENDENCY,
                f"forbidden dependency present: {name}", "HIGH", manifest))

    allowed_registries = {str(r).lower() for r in dep_config.get("allowed_registries", []) or []}
    if allowed_registries:
        for name in lockfiles:
            text = read_text(root, name) or ""
            for host in registries_in(text):
                if host.lower() not in allowed_registries:
                    findings.append(Finding(
                        CODE_DISALLOWED_REGISTRY,
                        f"registry not in allow list: {host} (from {name})",
                        "HIGH", name))

    if declared and locked:
        # 只在能拿到"lockfile 根包声明的依赖"时做精确比对（Node lockfile v2/v3）。
        # 拿传递依赖去跟 manifest 比会得到大量假阳性，所以拿不到就不猜。
        lock_declared: Optional[Set[str]] = None
        if ecosystem == "node":
            lock_declared = node_lock_declared_dependencies(read_text(root, lockfiles[0]) or "")

        if lock_declared is not None:
            declared_norm = {d.lower().replace("_", "-") for d in declared}
            lock_norm = {d.lower().replace("_", "-") for d in lock_declared}
            for name in sorted(lock_norm - declared_norm):
                findings.append(Finding(
                    CODE_UNDECLARED_DEPENDENCY,
                    f"{name} is declared in {lockfiles[0]} but not in {manifest}",
                    "MEDIUM", lockfiles[0]))
            for name in sorted(declared_norm - lock_norm):
                findings.append(Finding(
                    CODE_LOCKFILE_OUT_OF_SYNC,
                    f"{name} is declared in {manifest} but missing from {lockfiles[0]}",
                    "MEDIUM", manifest))

    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dependency-guard.py",
        description="SafeCode dependency / supply chain gate.",
    )
    parser.add_argument("--scope", default="staged",
                        choices=["staged", "worktree", "all"])
    parser.add_argument("--no-external", action="store_true",
                        help="跳过外部漏洞扫描器")
    parser.add_argument("--timeout", type=int, default=120)
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
        result = make_result("FAIL", "DENY", exc.code, exc.message,
                             category=CATEGORY_DEPENDENCY)
        return reporter.emit_result(result, exit_code=EXIT_USAGE)

    root = repo_root(cwd) or cwd
    mode = resolve_mode(strict_flag=bool(args.strict), config=config)
    dep_config = merge_dependency_config(config)

    changed, change_error, change_is_usage = changed_files(root, args.scope)
    if change_error:
        # 检查无法完成 ≠ 通过
        code = "DEPENDENCY_NOT_A_GIT_REPO" if change_is_usage else "DEPENDENCY_GIT_UNAVAILABLE"
        result = tool_error_result(
            code,
            f"cannot determine changed files ({change_error}): dependency check incomplete",
            category=CATEGORY_DEPENDENCY)
        result.metadata.update({"scope": args.scope, "root": root, "mode": mode})
        reporter.error(result.message)
        return reporter.emit_result(result, exit_code=EXIT_USAGE if change_is_usage else EXIT_TOOL)

    ecosystems_present = sorted(
        eco for eco, spec in ECOSYSTEMS.items()
        if read_text(root, spec["manifest"]) is not None)

    if not ecosystems_present:
        # 没有 manifest 就没有供应链对象可查：这是一次空检查，不是"跳过检查"。
        result = pass_result(
            CODE_DEPENDENCY_NO_MANIFEST,
            "no dependency manifest found in this repository; nothing to verify",
            category=CATEGORY_DEPENDENCY,
            metadata={"mode": mode, "scope": args.scope, "root": root,
                      "ecosystems_present": [], "findings": []})
        reporter.info(result.message)
        return reporter.emit_result(result, exit_code=EXIT_OK)

    findings: List[Finding] = []
    for ecosystem in ECOSYSTEMS:
        findings.extend(check_ecosystem(root, ecosystem, args.scope, changed, dep_config))

    scanner_info: Dict[str, Any] = {"enabled": bool(
        dep_config.get("external_scanner", {}).get("enabled", True)) and not args.no_external,
        "tool": None, "status": "skipped", "vulnerabilities": []}

    scanner_required = bool(
        dep_config.get("external_scanner", {}).get("required_in_ci", False))

    if scanner_info["enabled"]:
        tools = dep_config.get("external_scanner", {}).get("tools", []) or []
        tool, path = discover_scanner([str(t) for t in tools])
        if tool is None:
            scanner_info["status"] = "unavailable"
            if scanner_required or mode == "STRICT":
                result = fail_deny_result(
                    CODE_DEPENDENCY_SCANNER_UNAVAILABLE,
                    f"external dependency scanner unavailable (tried: {', '.join(map(str, tools))}) "
                    "and it is required in this mode: supply chain check incomplete",
                    severity="MEDIUM", category=CATEGORY_DEPENDENCY,
                    metadata={"scanner": scanner_info, "mode": mode,
                              "findings": [f.to_dict() for f in findings]})
                reporter.error(result.message)
                return reporter.emit_result(result, exit_code=EXIT_TOOL)
            scanner_info["message"] = "external scanner unavailable, native checks only"
        else:
            scanner_info["tool"] = tool
            outcome = run_external_scanner(tool, path or tool, root, args.timeout)
            scanner_info["status"] = outcome["status"]
            scanner_info["message"] = outcome.get("message", "")
            scanner_info["vulnerabilities"] = outcome.get("vulnerabilities", [])
            scanner_info["duration_seconds"] = outcome.get("duration_seconds")
            if outcome["status"] == "error":
                if mode == "STRICT" or scanner_required:
                    result = fail_deny_result(
                        CODE_DEPENDENCY_SCANNER_ERROR,
                        f"dependency scanner failed: {outcome['message']}",
                        severity="MEDIUM", category=CATEGORY_DEPENDENCY,
                        metadata={"scanner": scanner_info, "mode": mode})
                    reporter.error(result.message)
                    return reporter.emit_result(result, exit_code=EXIT_TOOL)
                scanner_info["degraded"] = True
            elif outcome["vulnerabilities"]:
                for vuln in outcome["vulnerabilities"]:
                    findings.append(Finding(
                        CODE_VULNERABLE_DEPENDENCY,
                        f"known vulnerability {vuln.get('id')} in {vuln.get('package')}: "
                        f"{vuln.get('summary', '')[:120]}",
                        "HIGH", ""))

    metadata: Dict[str, Any] = {
        "mode": mode,
        "scope": args.scope,
        "root": root,
        "changed_files": changed,
        "findings": [f.to_dict() for f in findings],
        "scanner": scanner_info,
        "ecosystems_present": ecosystems_present,
    }

    blocking = [f for f in findings if f.decision == "DENY"]
    approval = [f for f in findings if f.decision == "REQUIRE_APPROVAL"]

    if blocking:
        result = fail_deny_result(
            blocking[0].code,
            f"dependency check failed ({len(blocking)} blocking finding(s)): "
            + "; ".join(f.message for f in blocking[:3]),
            severity=blocking[0].severity, category=CATEGORY_DEPENDENCY,
            locations=[{"file": f.path} for f in blocking if f.path],
            metadata=metadata)
        reporter.error(result.message)
        return reporter.emit_result(result, exit_code=EXIT_FINDING)

    if approval:
        result = approval_result(
            approval[0].code,
            "; ".join(f.message for f in approval[:3]),
            severity=approval[0].severity, category=CATEGORY_DEPENDENCY,
            locations=[{"file": f.path} for f in approval if f.path],
            metadata=metadata)
        reporter.warn(result.message)
        return reporter.emit_result(result, exit_code=EXIT_FINDING)

    if scanner_info.get("status") == "unavailable" or scanner_info.get("degraded"):
        result = degraded_result(
            CODE_DEPENDENCY_SCANNER_UNAVAILABLE,
            "native dependency checks passed but external vulnerability scanner is not available; "
            "this is NOT a full supply chain verification",
            category=CATEGORY_DEPENDENCY, metadata=metadata)
        reporter.warn(result.message)
        return reporter.emit_result(result, exit_code=EXIT_OK)

    result = pass_result(CODE_DEPENDENCY_CLEAN, "dependency checks passed",
                         category=CATEGORY_DEPENDENCY, metadata=metadata)
    reporter.info("dependency checks passed")
    return reporter.emit_result(result, exit_code=EXIT_OK)


if __name__ == "__main__":
    sys.exit(main())
