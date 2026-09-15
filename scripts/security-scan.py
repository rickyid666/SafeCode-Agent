#!/usr/bin/env python3
"""SafeCode Agent — 安全扫描（Secret 泄露检测）。

扫描本次准备提交 / 工作区中的凭据泄露：API Key、Access Token、GitHub Token、
Cookie、Session、密码、私钥、.env/.pem/.key、数据库连接串、Bilibili 会话凭据等。

结合白名单与测试文件判定进行误报降级：
- 占位符 / 示例值不报
- 测试 / 示例文件中的疑似真实凭据降为 info 级并提示人工确认
- 其他真实凭据报 high / medium

用法：
    python scripts/security-scan.py [--staged|--worktree|--all] [--json]
                                    [--path <额外路径>...]

退出码：
    0  干净，或仅有 info 级发现（建议人工确认，不阻断）
    1  存在 high / medium 级发现（门禁应拒绝）
    2  用法错误 / 内部错误
"""

from __future__ import annotations

import argparse
import os
import re
import sys

import safecode_common as sc


# 扫描模式
MODE_STAGED = "staged"
MODE_WORKTREE = "worktree"
MODE_ALL = "all"

# --all 模式跳过的目录与文件
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".idea", ".vscode"}
_MAX_FILE_BYTES = 1 * 1024 * 1024  # 1 MB


def collect_diff_added_lines(diff_text: str) -> list:
    """解析 `git diff` 输出，返回 [(相对路径, 新文件行号, 行文本), ...]（仅新增行）。"""
    results = []
    cur_file = None
    new_lineno = 0
    in_hunk = False
    for line in diff_text.split("\n"):
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
                results.append((cur_file, new_lineno, line[1:]))
                new_lineno += 1
            elif line.startswith(" "):
                new_lineno += 1
            # 以 '\' 开头的 "no newline" 标记忽略
    return results


def iter_file_lines(path: str):
    """逐行读取文件，yield (行号, 文本)。读取失败时跳过。"""
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            return
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, raw in enumerate(fh, start=1):
                line = raw.rstrip("\n").rstrip("\r")
                yield i, line
    except (OSError, UnicodeDecodeError):
        return


def is_binary_file(path: str) -> bool:
    """通过前 8KB 是否含 NUL 字节判断是否为二进制文件。"""
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(8192)
        return b"\x00" in chunk
    except OSError:
        return True


def walk_all_files(root: str):
    """遍历 root 下所有文件，跳过忽略目录与二进制 / 超大文件。yield 文件路径。"""
    for dirpath, dirnames, filenames in os.walk(root):
        # 原地修改 dirnames 以跳过
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if is_binary_file(full):
                continue
            yield full, rel


def gather_lines(mode: str, extra_paths: list, repo_base: str) -> list:
    """收集待扫描的 (相对路径, 行号, 文本, 是否文件级) 列表。"""
    lines = []  # (rel_path, lineno, text)

    if mode == MODE_ALL:
        base = repo_base or os.getcwd()
        for _full, rel in walk_all_files(base):
            for ln, text in iter_file_lines(_full):
                lines.append((rel, ln, text))
    else:
        # staged / worktree：解析 git diff 新增行
        diff_arg = "--cached" if mode == MODE_STAGED else ""
        args = ["diff", "-U0", "--no-color"]
        if diff_arg:
            args.append(diff_arg)
        proc = sc.run_git(args)
        if proc.returncode == 0 and proc.stdout:
            lines.extend(collect_diff_added_lines(proc.stdout))
        # worktree 额外扫描未跟踪文件
        if mode == MODE_WORKTREE:
            ls = sc.run_git(["ls-files", "--others", "--exclude-standard"])
            if ls.returncode == 0:
                for rel in ls.stdout.splitlines():
                    rel = rel.strip()
                    if not rel:
                        continue
                    full = os.path.join(repo_base or os.getcwd(), rel)
                    if is_binary_file(full):
                        continue
                    for ln, text in iter_file_lines(full):
                        lines.append((rel, ln, text))

    # 额外路径
    for p in extra_paths or []:
        if os.path.isdir(p):
            for _full, rel in walk_all_files(p):
                for ln, text in iter_file_lines(_full):
                    lines.append((rel, ln, text))
        elif os.path.isfile(p):
            for ln, text in iter_file_lines(p):
                lines.append((os.path.basename(p), ln, text))
    return lines


def downgrade_for_test_file(base_severity: str) -> str:
    """测试 / 示例文件中的真实凭据降为 info。"""
    return sc.SEVERITY_INFO if base_severity in (sc.SEVERITY_HIGH, sc.SEVERITY_MEDIUM) else base_severity


def run_scan(mode: str, extra_paths: list, repo_base: str) -> list:
    """执行扫描，返回 Finding 列表。"""
    findings: list = []
    seen = set()  # 去重：(file, line, rule)
    lines = gather_lines(mode, extra_paths, repo_base)

    for rel, lineno, text in lines:
        # 文件级：敏感文件本身
        if sc.is_sensitive_file(rel):
            key = (rel, 0, "sensitive-file")
            if key not in seen:
                seen.add(key)
                base = sc.SEVERITY_HIGH
                sev = downgrade_for_test_file(base) if sc.is_test_or_example_file(rel) else base
                hint = ""
                if sc.is_test_or_example_file(rel):
                    hint = "测试/示例文件中的敏感文件，请人工确认是否应提交"
                findings.append(sc.Finding(
                    severity=sev, rule="sensitive-file", file=rel, line=0,
                    evidence=os.path.basename(rel), hint=hint,
                ))

        # 行级：Secret 规则
        for rule_name, base_sev, captured in sc.scan_text_for_secrets(text):
            key = (rel, lineno, rule_name)
            if key in seen:
                continue
            seen.add(key)
            is_test = sc.is_test_or_example_file(rel)
            if is_test:
                sev = downgrade_for_test_file(base_sev)
                hint = "测试/示例文件中的疑似真实凭据，请人工确认"
            else:
                sev = base_sev
                hint = ""
            findings.append(sc.Finding(
                severity=sev, rule=rule_name, file=rel, line=lineno,
                evidence=sc.truncate_evidence(captured), hint=hint,
            ))
    return findings


def print_human_report(findings: list, mode: str) -> None:
    print(sc.colorize("SafeCode 安全扫描", "bold"))
    print(f"模式: {mode}")
    if not findings:
        print(sc.colorize("未发现凭据泄露。", "green"))
        return
    # 按严重级别分组
    groups = {sc.SEVERITY_HIGH: [], sc.SEVERITY_MEDIUM: [], sc.SEVERITY_INFO: []}
    for f in findings:
        groups.setdefault(f.severity, []).append(f)
    counts = {
        sc.SEVERITY_HIGH: len(groups.get(sc.SEVERITY_HIGH, [])),
        sc.SEVERITY_MEDIUM: len(groups.get(sc.SEVERITY_MEDIUM, [])),
        sc.SEVERITY_INFO: len(groups.get(sc.SEVERITY_INFO, [])),
    }
    print(f"发现 {len(findings)} 处: "
          f"{sc.colorize(f'high={counts[sc.SEVERITY_HIGH]}', 'red')} "
          f"{sc.colorize(f'medium={counts[sc.SEVERITY_MEDIUM]}', 'yellow')} "
          f"{sc.colorize(f'info={counts[sc.SEVERITY_INFO]}', 'blue')}")
    print("-" * 60)
    for sev in (sc.SEVERITY_HIGH, sc.SEVERITY_MEDIUM, sc.SEVERITY_INFO):
        for f in groups.get(sev, []):
            loc = f"{f.file}:{f.line}" if f.line else f.file
            print(f"{sc.severity_label(f.severity)} {f.rule}")
            print(f"   位置: {loc}")
            print(f"   证据: {f.evidence}")
            if f.hint:
                print(f"   提示: {f.hint}")
    print("-" * 60)
    if counts[sc.SEVERITY_HIGH] or counts[sc.SEVERITY_MEDIUM]:
        print(sc.colorize("存在高风险凭据泄露，禁止 Push。请移除或轮换凭据后重新扫描。", "red"))
    elif counts[sc.SEVERITY_INFO]:
        print(sc.colorize("仅有 info 级发现（疑似凭据），建议人工确认。", "blue"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="security-scan.py",
        description="SafeCode 凭据泄露安全扫描",
    )
    mode_grp = parser.add_mutually_exclusive_group()
    mode_grp.add_argument("--staged", action="store_const", const=MODE_STAGED, dest="mode",
                          help="扫描 git 暂存区（git diff --cached + 新增文件），默认值")
    mode_grp.add_argument("--worktree", action="store_const", const=MODE_WORKTREE, dest="mode",
                          help="扫描 git 工作区改动（git diff + 未跟踪文件）")
    mode_grp.add_argument("--all", action="store_const", const=MODE_ALL, dest="mode",
                          help="扫描工作区全部文件（跳过 .git/node_modules/__pycache__/二进制/>1MB）")
    parser.add_argument("--json", action="store_true", help="输出结构化 JSON 结果")
    parser.add_argument("--path", action="append", default=[], metavar="PATH",
                        help="额外扫描的文件或目录（可多次指定）")
    args = parser.parse_args(argv)

    mode = args.mode or MODE_STAGED
    repo_base = sc.repo_root()

    # 非 git 仓库且默认 staged 时，回退为扫描当前目录（--all 语义）
    if mode in (MODE_STAGED, MODE_WORKTREE) and not repo_base:
        print("警告: 当前不在 git 仓库内，回退为扫描当前目录全部文件。", file=sys.stderr)
        mode = MODE_ALL

    try:
        findings = run_scan(mode, args.path, repo_base or ".")
    except Exception as exc:  # noqa: BLE001
        print(f"错误: 扫描过程中发生内部错误: {exc}", file=sys.stderr)
        return sc.EXIT_USAGE

    if args.json:
        payload = {
            "tool": "security-scan",
            "mode": mode,
            "summary": {
                "total": len(findings),
                "high": sum(1 for f in findings if f.severity == sc.SEVERITY_HIGH),
                "medium": sum(1 for f in findings if f.severity == sc.SEVERITY_MEDIUM),
                "info": sum(1 for f in findings if f.severity == sc.SEVERITY_INFO),
            },
            "findings": [f.to_dict() for f in findings],
        }
        sc.write_json_report(payload)
    else:
        print_human_report(findings, mode)

    has_blocking = any(f.severity in (sc.SEVERITY_HIGH, sc.SEVERITY_MEDIUM) for f in findings)
    return sc.EXIT_GATE_REJECT if has_blocking else sc.EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
