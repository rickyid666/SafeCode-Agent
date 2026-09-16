"""SafeCode 统一 CLI 入口。

契约里的命令对应关系（子命令 -> 实际脚本）：

    safecode security scan      -> scripts/security-scan.py
    safecode security baseline  -> scripts/security-scan.py --write-baseline
    safecode dependency check   -> scripts/dependency-guard.py
    safecode test run           -> scripts/test-runner.py
    safecode recover            -> scripts/recovery.py
    safecode git guard          -> scripts/git-guard.py
    safecode pre-push           -> scripts/pre-push.py
    safecode hook install|verify|update -> scripts/hook-manager.py
    safecode approve            -> scripts/git-guard.py approve
    safecode decision           -> scripts/decision-resolver.py

这一层只做参数路由，不重复实现任何检查逻辑：子进程继承 stdio，
stdout 上的 Structured JSON 与退出码原样传给调用方。
所有检查类脚本仍然可以独立执行（CI 里往往直接调用单个脚本）。

未知子命令一律 exit 2 + DENY —— 不认识的命令不允许被当作"通过"。
纯 Python 标准库。Python >= 3.10。
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from safecode_common import EXIT_ENV, EXIT_USAGE, Reporter, make_result  # noqa: E402

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

# 子命令路由表：命令元组 -> (脚本名, 前置参数)
ROUTES: Dict[Tuple[str, ...], Tuple[str, List[str]]] = {
    ("security", "scan"): ("security-scan.py", []),
    ("security", "baseline"): ("security-scan.py", ["--write-baseline"]),
    ("dependency", "check"): ("dependency-guard.py", []),
    ("test", "run"): ("test-runner.py", []),
    ("recover",): ("recovery.py", []),
    ("git", "guard"): ("git-guard.py", []),
    ("pre-push",): ("pre-push.py", []),
    ("hook", "install"): ("hook-manager.py", ["install"]),
    ("hook", "verify"): ("hook-manager.py", ["verify"]),
    ("hook", "update"): ("hook-manager.py", ["update"]),
    ("approve",): ("git-guard.py", ["approve"]),
    ("decision",): ("decision-resolver.py", []),
}

MAX_COMMAND_PARTS = max(len(key) for key in ROUTES)


def usage_text() -> str:
    lines = ["SafeCode Agent CLI", "", "usage: safecode <command> [options]", "", "commands:"]
    for key, (script, prefix) in sorted(ROUTES.items()):
        lines.append(f"  {' '.join(key):<24} -> {script} {' '.join(prefix)}".rstrip())
    lines += [
        "",
        "common options (passed through to the target script):",
        "  --config PATH  --json  --strict  --quiet  --verbose",
        "  --baseline PATH  --task-id ID",
    ]
    return "\n".join(lines)


def resolve_route(argv: Sequence[str]) -> Tuple[Optional[Tuple[str, ...]], List[str]]:
    """从 argv 前缀解析子命令，返回 (命令元组, 剩余参数)。"""
    for size in range(min(MAX_COMMAND_PARTS, len(argv)), 0, -1):
        candidate = tuple(argv[:size])
        if candidate in ROUTES:
            return candidate, list(argv[size:])
    return None, list(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    reporter = Reporter()

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(usage_text())
        return 0 if argv else EXIT_USAGE

    command, rest = resolve_route(argv)
    if command is None:
        reporter.error(f"unknown command: {' '.join(argv[:MAX_COMMAND_PARTS])}")
        print(usage_text(), file=sys.stderr)
        result = make_result("FAIL", "DENY", "UNKNOWN_COMMAND",
                             f"unknown safecode command: {' '.join(argv)}")
        reporter.emit_result(result, exit_code=EXIT_USAGE)
        return EXIT_USAGE

    script, prefix = ROUTES[command]
    script_path = os.path.join(SCRIPTS_DIR, script)
    if not os.path.isfile(script_path):
        reporter.error(f"implementation script not found: {script_path}")
        result = make_result("FAIL", "DENY", "SCRIPT_NOT_FOUND",
                             f"script not found: {script}")
        reporter.emit_result(result, exit_code=EXIT_ENV)
        return EXIT_ENV

    cmd = [sys.executable, script_path, *prefix, *rest]
    reporter.debug(f"exec: {' '.join(cmd)}")
    try:
        completed = subprocess.run(cmd, cwd=os.getcwd())
    except OSError as exc:
        reporter.error(f"cannot execute {script}: {exc}")
        result = make_result("FAIL", "DENY", "SCRIPT_EXEC_ERROR", str(exc))
        reporter.emit_result(result, exit_code=EXIT_ENV)
        return EXIT_ENV
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main())
