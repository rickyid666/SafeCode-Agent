#!/usr/bin/env python3
"""SafeCode Agent — pre-push 总编排（Push 前门禁）。

按顺序执行一系列安全检查，任一环节拒绝（退出码 1 / 10）即中止并提示禁止 Push：

    1. 工作区状态检查（git status --porcelain 非空 -> 警告；SAFECODE_STRICT=1 时阻断）
    2. 当前分支
    3. git-guard.py --check-diff（暂存区危险命令）
    4. security-scan.py --staged（凭据泄露）
    5. 若 stdin 有 pre-push 数据 -> 透传 git-guard.py --pre-push（强推/分支保护/删除分支）

每步打印标题与耗时。全部通过输出：
    SAFECODE: all gates passed, push allowed

退出码：
    0  全部通过，允许 Push
    1  某个门禁拒绝（recovery 上限之外的一般拒绝）
    10 某个门禁返回 10（recovery 上限语义，同样拒绝）
    2  用法错误 / 内部错误
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

import safecode_common as sc

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def run_step(name: str, args: list, stdin: str | None = None) -> tuple:
    """运行一个子脚本，返回 (returncode, duration_seconds)。"""
    print(sc.colorize(f"\n=== [{name}] ===", "bold"))
    start = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, os.path.join(SCRIPT_DIR, args[0])] + args[1:],
        stdin=(subprocess.PIPE if stdin is not None else None),
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True,
        input=stdin,
    )
    duration = time.perf_counter() - start
    print(sc.colorize(f"--- 耗时: {duration:.2f}s | 退出码: {proc.returncode} ---", "blue"))
    return proc.returncode, duration


def step_workspace_status() -> tuple:
    """工作区状态检查。返回 (block, returncode)。"""
    print(sc.colorize("\n=== [工作区状态检查] ===", "bold"))
    start = time.perf_counter()
    proc = sc.run_git(["status", "--porcelain"])
    duration = time.perf_counter() - start
    if proc.returncode != 0:
        print("无法获取 git 状态（可能不在仓库内）。", file=sys.stderr)
        return True, sc.EXIT_GATE_REJECT
    out = proc.stdout.strip()
    if out:
        print(sc.colorize("警告: 工作区存在未提交内容：", "yellow"))
        for line in out.splitlines()[:20]:
            print(f"  {line}")
        if len(out.splitlines()) > 20:
            print("  ...")
        if os.environ.get("SAFECODE_STRICT", "") == "1":
            print(sc.colorize("SAFECODE_STRICT=1：未提交内容阻断 Push。", "red"))
            print(f"--- 耗时: {duration:.2f}s | 退出码: {sc.EXIT_GATE_REJECT} ---")
            return True, sc.EXIT_GATE_REJECT
        print("（默认仅警告，不阻断。需用 SAFECODE_STRICT=1 强制阻断。）")
    else:
        print(sc.colorize("工作区干净。", "green"))
    print(sc.colorize(f"--- 耗时: {duration:.2f}s | 退出码: {sc.EXIT_PASS} ---", "blue"))
    return False, sc.EXIT_PASS


def step_current_branch() -> tuple:
    """打印当前分支。"""
    print(sc.colorize("\n=== [当前分支] ===", "bold"))
    start = time.perf_counter()
    proc = sc.run_git(["branch", "--show-current"])
    duration = time.perf_counter() - start
    branch = proc.stdout.strip() or "(detached HEAD)"
    print(f"当前分支: {branch}")
    print(sc.colorize(f"--- 耗时: {duration:.2f}s ---", "blue"))
    return False, sc.EXIT_PASS


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pre-push.py",
        description="SafeCode pre-push 总编排（Push 前门禁）",
    )
    parser.parse_args(argv)  # 当前无额外参数，保留以便扩展

    # 读取 stdin（git pre-push hook 会传入；终端运行时避免阻塞）
    stdin_data = ""
    if not sys.stdin.isatty():
        stdin_data = sys.stdin.read()

    print(sc.colorize("SafeCode pre-push gate", "bold"))
    print("=" * 60)

    # 1. 工作区状态
    blocked, code = step_workspace_status()
    worst_code = code

    # 2. 当前分支
    step_current_branch()

    # 3. git-guard --check-diff
    rc, _ = run_step("git-guard --check-diff", ["git-guard.py", "--check-diff"])
    worst_code = max(worst_code, rc, key=lambda c: _code_rank(c))

    # 4. security-scan --staged
    rc, _ = run_step("security-scan --staged", ["security-scan.py", "--staged"])
    worst_code = max(worst_code, rc, key=lambda c: _code_rank(c))

    # 5. git-guard --pre-push（若有 stdin 数据）
    if stdin_data.strip():
        rc, _ = run_step("git-guard --pre-push", ["git-guard.py", "--pre-push"], stdin=stdin_data)
        worst_code = max(worst_code, rc, key=lambda c: _code_rank(c))
    else:
        print(sc.colorize("\n=== [git-guard --pre-push] ===", "bold"))
        print("（无 pre-push stdin 数据，跳过远程分支强推/分支保护检查。）")

    print("=" * 60)
    if worst_code in (sc.EXIT_GATE_REJECT, sc.EXIT_RECOVERY_LIMIT):
        print(sc.colorize("SAFECODE: 门禁未通过，禁止 Push。", "red"))
        print("请修复上述问题后重新运行本检查；若为 recovery 上限，请人工介入。")
        return worst_code  # 1 或 10

    print(sc.colorize("SAFECODE: all gates passed, push allowed", "green"))
    return sc.EXIT_PASS


def _code_rank(code: int) -> int:
    """用于 max 比较：10 > 2 > 1 > 0。"""
    return {0: 0, 1: 1, 2: 2, 10: 3}.get(code, 0)


if __name__ == "__main__":
    sys.exit(main())
