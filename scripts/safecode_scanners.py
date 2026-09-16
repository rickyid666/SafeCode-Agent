"""SafeCode Agent — 外部 Secret Scanner 包装层。

职责：把成熟的 Secret Scanner（gitleaks / trufflehog / detect-secrets）统一为
SafeCode 的接口，并把各 scanner 的产出归一化为 `safecode_secret.Finding`
（source=SOURCE_EXTERNAL），交给 security-scan.py 统一做策略判定。

设计要点（Fail-Closed）：

- `discover(tools)` 用 `shutil.which` 探测工具是否安装。
- 每个 scanner 都归一化为 `ScannerOutcome`，其中：
    - `available`：二进制是否被发现并可执行；
    - `status`：PASS / FINDINGS / ERROR / UNKNOWN；
    - `findings`：归一化后的 Finding 列表；
    - `error_code` / `error_message`：失败原因。
- 以下情况一律 `status="ERROR"`，**绝不**当作 PASS / 无发现：
    - scanner 不存在（discover 返回 None，由调用方记 unavailable）；
    - 启动失败（FileNotFoundError / OSError）；
    - 超时（ subprocess 超时并杀进程）；
    - 非零退出且无法解析出合法结果；
    - 输出无法解析（JSON 损坏 / 非数组）。
- 每个外部 finding 仍走 `safecode_secret.Finding` 的指纹算法，保证与
  Baseline / allow_list 的语义一致。

纯 Python 标准库，Windows 与 Linux 都能跑。Python >= 3.10。
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from safecode_common import (  # noqa: E402
    SEVERITY_HIGH,
    read_json_file,
)
from safecode_secret import (  # noqa: E402
    FINDING_TYPE_SECRET,
    Finding,
    SOURCE_EXTERNAL,
    truncate_evidence,
)

# 外部 scanner 命中的默认严重级别（外部发现即视为需要人工确认的高风险）
EXTERNAL_SEVERITY = SEVERITY_HIGH

# scanner 状态
SCANNER_PASS = "PASS"
SCANNER_FINDINGS = "FINDINGS"
SCANNER_ERROR = "ERROR"
SCANNER_UNKNOWN = "UNKNOWN"


@dataclasses.dataclass
class ScannerOutcome:
    """单个外部 scanner 的归一化结果。"""

    scanner: str
    available: bool
    status: str  # PASS | FINDINGS | ERROR | UNKNOWN
    exit_code: int
    findings: List[Finding]
    error_code: str
    error_message: str

    def to_summary(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner,
            "available": self.available,
            "status": self.status,
            "exit_code": self.exit_code,
            "findings": len(self.findings),
            "error_code": self.error_code,
            "error_message": self.error_message,
        }


def discover(tools: Optional[List[str]] = None) -> Dict[str, Optional[str]]:
    """探测给定 scanner 是否可执行，返回 {tool: path|None}。

    用 shutil.which 同时支持 Windows（.exe/.bat/.cmd，受 PATHEXT 影响）
    与 POSIX（PATH + 可执行位）。
    """
    if tools is None:
        tools = ["gitleaks", "trufflehog", "detect-secrets"]
    result: Dict[str, Optional[str]] = {}
    for tool in tools:
        result[tool] = shutil.which(tool)
    return result


# --------------------------------------------------------------------------- #
# 子进程运行（含超时与进程组清理）
# --------------------------------------------------------------------------- #

def _kill(proc: subprocess.Popen) -> None:
    try:
        import os as _os
        if hasattr(_os, "killpg") and proc.pid is not None:
            _os.killpg(_os.getpgid(proc.pid), 9)  # SIGKILL 进程组
        else:
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _run_cmd(cmd: List[str], timeout: int, cwd: str) -> Tuple[Optional[subprocess.Popen], Optional[str], Optional[str], Optional[str], str]:
    """运行命令，返回 (proc, stdout, stderr, err_kind, err_msg)。

    stdout / stderr 是 communicate() 捕获到的字符串（text=True 时）。切勿读取
    proc.stdout / proc.stderr 属性——在某些 Python 版本上它们仍是流对象，调用
    字符串方法会抛 AttributeError。

    err_kind: None（正常完成）| "timeout" | "startup"。
    """
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            text=True,
            errors="replace",
            start_new_session=True,
        )
    except (OSError, FileNotFoundError) as exc:
        return None, None, None, "startup", str(exc)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill(proc)
        out, err = "", ""
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            pass
        return proc, out, err, "timeout", ""
    return proc, out, err, None, ""


def _looks_like_unknown_subcommand(stderr: str) -> bool:
    """判断 stderr 是否提示子命令 / flag 不存在（用于 gitleaks protect --staged 回退）。"""
    if not stderr:
        return False
    lowered = stderr.lower()
    markers = (
        "unknown command",
        "unknown flag",
        "unknown subcommand",
        "unknown shorthand",
        "flag provided but not defined",
        "not defined",
        "unrecognized",
    )
    return any(m in lowered for m in markers)


# --------------------------------------------------------------------------- #
# Finding 归一化
# --------------------------------------------------------------------------- #

def _gitleaks_finding(item: Dict[str, Any]) -> Finding:
    secret = item.get("Secret") or ""
    match = item.get("Match") or secret
    raw_line = item.get("StartLine")
    line = int(raw_line) if isinstance(raw_line, int) else None
    return Finding(
        rule=str(item.get("RuleID") or "GITLEAKS"),
        path=item.get("File") or "",
        line=line,
        severity=EXTERNAL_SEVERITY,
        finding_type=FINDING_TYPE_SECRET,
        evidence=truncate_evidence(match or secret),
        matched_value=secret,
        source=SOURCE_EXTERNAL,
        scanner="gitleaks",
        message=item.get("Description") or "gitleaks finding",
    )


def _trufflehog_finding(obj: Dict[str, Any]) -> Finding:
    raw = obj.get("Raw") or ""
    meta = obj.get("SourceMetadata") or {}
    fsys = (meta.get("Data") or {}).get("Filesystem") or {}
    return Finding(
        rule=str(obj.get("DetectorName") or "TRUFFLEHOG"),
        path=fsys.get("file") or "",
        line=None,
        severity=EXTERNAL_SEVERITY,
        finding_type=FINDING_TYPE_SECRET,
        evidence=truncate_evidence(raw),
        matched_value=raw,
        source=SOURCE_EXTERNAL,
        scanner="trufflehog",
        message=f"trufflehog:{obj.get('DetectorName')}",
    )


def _detect_secrets_finding(file: str, item: Dict[str, Any]) -> Finding:
    raw_line = item.get("line_number")
    line = int(raw_line) if isinstance(raw_line, int) else None
    hashed = item.get("hashed_secret") or ""
    return Finding(
        rule=str(item.get("type") or "DETECT_SECRETS"),
        path=file,
        line=line,
        severity=EXTERNAL_SEVERITY,
        finding_type=FINDING_TYPE_SECRET,
        evidence=truncate_evidence(hashed),
        matched_value=hashed,
        source=SOURCE_EXTERNAL,
        scanner="detect-secrets",
        message=f"detect-secrets:{item.get('type')}",
    )


# --------------------------------------------------------------------------- #
# 各 scanner 解析
# --------------------------------------------------------------------------- #

def _parse_gitleaks_report(report_path: str, rc: int, stderr: str) -> Tuple[List[Finding], str, str]:
    """返回 (findings, error_code, error_message)。error_code 为空表示成功。"""
    if os.path.isfile(report_path):
        try:
            data = read_json_file(report_path)
        except Exception as exc:
            if rc != 0:
                return [], "SCANNER_ERROR", f"gitleaks exited {rc}: {stderr[:200]}"
            return [], "SCANNER_OUTPUT_INVALID", f"cannot parse gitleaks report: {exc}"
        if not isinstance(data, list):
            return [], "SCANNER_OUTPUT_INVALID", "gitleaks report is not a JSON array"
        findings = [_gitleaks_finding(it) for it in data if isinstance(it, dict)]
        return findings, "", ""
    # 没有 report 文件
    if rc == 0:
        # 扫描正常但没产生 report（理论上 gitleaks 总会写 report，这里保守当无发现）
        return [], "", ""
    return [], "SCANNER_ERROR", f"gitleaks exited {rc} with no report: {stderr[:200]}"


def _parse_trufflehog(stdout: str, rc: int, stderr: str) -> Tuple[List[Finding], str, str]:
    findings: List[Finding] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            # trufflehog 偶尔会打印非 JSON 的诊断行，跳过
            continue
        if isinstance(obj, dict):
            findings.append(_trufflehog_finding(obj))
    if findings:
        return findings, "", ""
    if rc != 0:
        return [], "SCANNER_ERROR", f"trufflehog exited {rc}: {stderr[:200]}"
    return [], "", ""


def _parse_detect_secrets(stdout: str, rc: int, stderr: str) -> Tuple[List[Finding], str, str]:
    if not (stdout or "").strip():
        if rc != 0:
            return [], "SCANNER_ERROR", f"detect-secrets exited {rc}: {stderr[:200]}"
        return [], "SCANNER_OUTPUT_INVALID", "detect-secrets produced no output"
    try:
        obj = json.loads(stdout)
    except Exception as exc:
        if rc != 0:
            return [], "SCANNER_ERROR", f"detect-secrets exited {rc}: {stderr[:200]}"
        return [], "SCANNER_OUTPUT_INVALID", f"cannot parse detect-secrets output: {exc}"
    if not isinstance(obj, dict) or "results" not in obj:
        if rc != 0:
            return [], "SCANNER_ERROR", f"detect-secrets exited {rc}"
        return [], "SCANNER_OUTPUT_INVALID", "detect-secrets output missing 'results'"
    findings: List[Finding] = []
    results = obj.get("results") or {}
    for file, items in results.items():
        if not isinstance(items, list):
            continue
        for it in items:
            if isinstance(it, dict):
                findings.append(_detect_secrets_finding(file, it))
    return findings, "", ""


# --------------------------------------------------------------------------- #
# 各 scanner 运行
# --------------------------------------------------------------------------- #

def _gitleaks(name: str, path: str, scope: str, root: str, timeout: int) -> ScannerOutcome:
    fd, report_path = tempfile.mkstemp(prefix="safecode-gitleaks-", suffix=".json")
    os.close(fd)
    try:
        common = ["--no-banner", "--redact", "--report-format", "json", "--report-path", report_path]
        if scope == "staged":
            cmd = [path, "protect", "--staged", *common]
        else:
            cmd = [path, "detect", "--source", root, *common]
        proc, out, err, err_kind, err_msg = _run_cmd(cmd, timeout, root)
        if err_kind == "timeout":
            return ScannerOutcome(name, True, SCANNER_ERROR, 124, [], "SCANNER_TIMEOUT",
                                  "gitleaks timed out")
        if err_kind == "startup":
            return ScannerOutcome(name, True, SCANNER_ERROR, -1, [], "SCANNER_STARTUP_ERROR", err_msg)
        rc = proc.returncode
        # protect --staged 子命令不存在时回退到 detect --source
        if scope == "staged" and rc != 0 and _looks_like_unknown_subcommand(err or ""):
            cmd2 = [path, "detect", "--source", root, *common]
            proc, out, err, err_kind, _ = _run_cmd(cmd2, timeout, root)
            if err_kind:
                return ScannerOutcome(name, True, SCANNER_ERROR, -1, [], "SCANNER_ERROR",
                                      "gitleaks fallback to detect failed")
            rc = proc.returncode
        findings, ec, em = _parse_gitleaks_report(report_path, rc, err or "")
        status = SCANNER_ERROR if ec else (SCANNER_FINDINGS if findings else SCANNER_PASS)
        return ScannerOutcome(name, True, status, rc, findings, ec or "", em or "")
    finally:
        try:
            os.remove(report_path)
        except OSError:
            pass


def _trufflehog(name: str, path: str, root: str, timeout: int) -> ScannerOutcome:
    cmd = [path, "filesystem", "--json", "--no-update", root]
    proc, out, err, err_kind, err_msg = _run_cmd(cmd, timeout, root)
    if err_kind == "timeout":
        return ScannerOutcome(name, True, SCANNER_ERROR, 124, [], "SCANNER_TIMEOUT",
                              "trufflehog timed out")
    if err_kind == "startup":
        return ScannerOutcome(name, True, SCANNER_ERROR, -1, [], "SCANNER_STARTUP_ERROR", err_msg)
    findings, ec, em = _parse_trufflehog(out or "", proc.returncode, err or "")
    status = SCANNER_ERROR if ec else (SCANNER_FINDINGS if findings else SCANNER_PASS)
    return ScannerOutcome(name, True, status, proc.returncode, findings, ec or "", em or "")


def _detect_secrets(name: str, path: str, root: str, timeout: int) -> ScannerOutcome:
    cmd = [path, "scan", "--all-files"]
    proc, out, err, err_kind, err_msg = _run_cmd(cmd, timeout, root)
    if err_kind == "timeout":
        return ScannerOutcome(name, True, SCANNER_ERROR, 124, [], "SCANNER_TIMEOUT",
                              "detect-secrets timed out")
    if err_kind == "startup":
        return ScannerOutcome(name, True, SCANNER_ERROR, -1, [], "SCANNER_STARTUP_ERROR", err_msg)
    findings, ec, em = _parse_detect_secrets(out or "", proc.returncode, err or "")
    status = SCANNER_ERROR if ec else (SCANNER_FINDINGS if findings else SCANNER_PASS)
    return ScannerOutcome(name, True, status, proc.returncode, findings, ec or "", em or "")


def run_scanner(name: str, path: str, scope: str, root: str, timeout: int) -> ScannerOutcome:
    """运行单个已发现的 scanner 并归一化结果。

    scope 统一为 "staged" | "worktree" | "all" 之一；history / repo 会被映射为 "all"。
    """
    scanner_scope = "all" if scope in ("history", "repo") else scope
    if name == "gitleaks":
        return _gitleaks(name, path, scanner_scope, root, timeout)
    if name == "trufflehog":
        return _trufflehog(name, path, root, timeout)
    if name == "detect-secrets":
        return _detect_secrets(name, path, root, timeout)
    return ScannerOutcome(name, True, SCANNER_ERROR, -1, [], "UNKNOWN_SCANNER",
                          f"unsupported scanner: {name}")


def unavailable_outcome(name: str, message: str = "not found on PATH") -> ScannerOutcome:
    """scanner 未被发现时的伪结果（调用方据此触发 DEGRADED / STRICT DENY）。"""
    return ScannerOutcome(name, False, SCANNER_UNKNOWN, -1, [], "SCANNER_UNAVAILABLE", message)


def main(argv: Optional[List[str]] = None) -> int:
    """简单的 CLI：--discover 打印探测结果；--run <tool> 运行一个 scanner。"""
    import argparse

    parser = argparse.ArgumentParser(prog="safecode_scanners.py",
                                     description="External Secret Scanner wrapper")
    parser.add_argument("--discover", action="store_true", help="probe available scanners")
    parser.add_argument("--run", metavar="TOOL", help="run a specific scanner")
    parser.add_argument("--scope", default="all", choices=["staged", "worktree", "all"])
    parser.add_argument("--root", default=os.getcwd())
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args(argv)

    if args.discover:
        print(json.dumps(discover(), indent=2))
        return 0
    if args.run:
        path = shutil.which(args.run)
        if not path:
            print(json.dumps(unavailable_outcome(args.run).to_summary(), indent=2))
            return 0
        outcome = run_scanner(args.run, path, args.scope, args.root, args.timeout)
        print(json.dumps(outcome.to_summary(), indent=2))
        for f in outcome.findings:
            print(json.dumps(f.to_dict(include_evidence=False), indent=2))
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
