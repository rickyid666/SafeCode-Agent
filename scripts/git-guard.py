#!/usr/bin/env python3
"""SafeCode Agent — Git 安全门禁。

两个子能力：

1) --pre-push：读取 git pre-push hook 的 stdin，每行
       local_ref local_sha remote_ref remote_sha
   检测：
     a) 强推：remote_sha 非全零 且 `git merge-base --is-ancestor remote_sha local_sha`
        失败 -> 判定为 force push，拒绝；
     b) 危险分支保护：目标 remote_ref 为 refs/heads/main 或 master，且环境变量
        SAFECODE_ALLOW_MAIN 未设为 1 -> 拒绝；
     c) 删除远程分支（local_sha 全零）-> 默认拒绝。

2) --check-diff：扫描 git 暂存区新增行中的危险命令，命中即拒绝：
       git push --force / -f
       git reset --hard
       git filter-branch / filter-repo
       git rebase（改写历史）
       rm -rf 作用于仓库根
       DROP DATABASE / TRUNCATE TABLE

退出码：
    0  通过
    1  拒绝（门禁发现风险）
    2  用法错误 / 内部错误
"""

from __future__ import annotations

import argparse
import os
import re
import sys

import safecode_common as sc

ZERO_SHA = "0" * 40

# 受保护分支
PROTECTED_BRANCHES = ("refs/heads/main", "refs/heads/master")

# --check-diff 危险模式
DANGEROUS_PATTERNS = [
    ("git-force-push", re.compile(r'git\s+push\s+(--force|-f\b|.*\s--force\b)')),
    ("git-reset-hard", re.compile(r'git\s+reset\s+(--hard|-[a-zA-Z]*h)')),
    ("git-filter-branch", re.compile(r'git\s+filter-branch')),
    ("git-filter-repo", re.compile(r'git\s+filter-repo')),
    ("git-rebase", re.compile(r'git\s+rebase\b')),
    ("rm-rf-repo-root", re.compile(r'\brm\s+-[a-zA-Z]*rf\b\s+(--\s+)?(\.|/?\b\w*\.git\b|\$)')),
    ("drop-database", re.compile(r'\bDROP\s+DATABASE\b', re.IGNORECASE)),
    ("truncate-table", re.compile(r'\bTRUNCATE\s+TABLE\b', re.IGNORECASE)),
]


def check_pre_push(stdin_text: str) -> list:
    """处理 pre-push 输入，返回拒绝原因列表（空列表表示通过）。"""
    rejections = []

    for raw_line in stdin_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 4:
            # 格式不符，跳过（不阻断，避免误伤）
            continue
        local_ref, local_sha, remote_ref, remote_sha = parts[0], parts[1], parts[2], parts[3]

        # c) 删除远程分支：local_sha 全零
        if local_sha == ZERO_SHA:
            rejections.append(
                f"拒绝删除远程分支: 本地 {local_ref} 为删除操作 (local_sha={local_sha})。"
                f"如需删除请人工执行 `git push {remote_ref.replace('refs/heads/', '')} --delete` "
                f"并确认。"
            )
            continue

        # b) 危险分支保护
        if remote_ref in PROTECTED_BRANCHES:
            if os.environ.get("SAFECODE_ALLOW_MAIN", "") != "1":
                rejections.append(
                    f"拒绝推送到受保护分支 {remote_ref}（强推/直接推送 main|master 被禁止）。"
                    f"如需临时允许，请设置环境变量 SAFECODE_ALLOW_MAIN=1 并人工确认风险。"
                )
                # 分支保护优先，不再做强推判断
                continue

        # a) 强推检测
        if remote_sha != ZERO_SHA:
            proc = sc.run_git(["merge-base", "--is-ancestor", remote_sha, local_sha])
            if proc.returncode != 0:
                rejections.append(
                    f"拒绝强推: {local_ref} -> {remote_ref}。"
                    f"remote_sha({remote_sha[:10]}…) 不是 local_sha({local_sha[:10]}…) 的祖先，"
                    f"将改写远程历史。如需强推，请人工执行 `git push --force-with-lease` 并确认。"
                )

    return rejections


def check_diff_dangerous() -> list:
    """扫描暂存区新增行，返回危险命令命中列表（空列表表示通过）。"""
    hits = []
    proc = sc.run_git(["diff", "--cached", "-U0", "--no-color"])
    if proc.returncode != 0 or not proc.stdout:
        return hits

    added = []
    new_lineno = 0
    in_hunk = False
    cur_file = None
    for line in proc.stdout.split("\n"):
        if line.startswith("diff --git"):
            in_hunk = False
            m = re.search(r" b/(.+)$", line)
            cur_file = m.group(1) if m else None
        elif line.startswith("@@"):
            in_hunk = True
            m = re.search(r"\+(\d+)", line)
            new_lineno = int(m.group(1)) if m else 0
        elif in_hunk:
            if line.startswith("+") and not line.startswith("+++"):
                added.append((cur_file, new_lineno, line[1:]))
                new_lineno += 1
            elif line.startswith(" "):
                new_lineno += 1

    for rel, lineno, text in added:
        for name, pat in DANGEROUS_PATTERNS:
            if pat.search(text):
                loc = f"{rel}:{lineno}" if rel else f"line {lineno}"
                hits.append(f"{name} @ {loc}: {sc.truncate_evidence(text, 100)}")
    return hits


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="git-guard.py",
        description="SafeCode Git 安全门禁",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pre-push", action="store_true",
                       help="读取 git pre-push hook stdin 进行强推/分支保护/删除分支检测")
    group.add_argument("--check-diff", action="store_true",
                       help="扫描暂存区新增行中的危险命令")
    args = parser.parse_args(argv)

    try:
        if args.pre_push:
            if sys.stdin.isatty():
                stdin_text = ""
            else:
                stdin_text = sys.stdin.read()
            rejections = check_pre_push(stdin_text)
            if rejections:
                print(sc.colorize("SafeCode git-guard: PRE-PUSH 被拒绝", "red"))
                for r in rejections:
                    print(f"  - {r}")
                return sc.EXIT_GATE_REJECT
            print(sc.colorize("git-guard: pre-push 检查通过。", "green"))
            return sc.EXIT_PASS

        if args.check_diff:
            hits = check_diff_dangerous()
            if hits:
                print(sc.colorize("SafeCode git-guard: 暂存区包含危险操作，已拒绝", "red"))
                for h in hits:
                    print(f"  - {h}")
                print("如需继续，请移除上述命令后重新暂存；确属必要操作请人工执行。")
                return sc.EXIT_GATE_REJECT
            print(sc.colorize("git-guard: 暂存区危险命令检查通过。", "green"))
            return sc.EXIT_PASS
    except Exception as exc:  # noqa: BLE001
        print(f"错误: git-guard 内部错误: {exc}", file=sys.stderr)
        return sc.EXIT_USAGE

    return sc.EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
