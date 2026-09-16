#!/usr/bin/env python3
"""SafeCode Agent — Hook 生命周期管理（install / verify / update）。

职责：
  - install：写 .githooks/pre-push（POSIX sh，调用 `python scripts/pre-push.py`），
    设 git config core.hooksPath .githooks。
  - verify：检查 core.hooksPath / hook 存在 / 可执行（Windows 下降级为"文件存在 + 内容校验"
    并注明 DEGRADED）/ 版本标记 / 是否被替换。
  - update：刷新为当前版本（保留备份 .safecode/backup/pre-push.<ts>）。

重要：客户端 hook 不是唯一安全边界。--no-verify 可绕过本地 hook；CI Required Check 与
分支保护是独立防线。该说明会出现在所有子命令的输出里。

纯标准库，跨平台。Python >= 3.10。
"""

from __future__ import annotations

import os
import sys

# 契约要求：CLI 脚本顶部先把自身目录加入 sys.path，再 import 共享内核。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import shutil
from datetime import datetime, timezone

import safecode_common as sc

HOOK_VERSION = "1.0"
HOOK_FILENAME = "pre-push"
HOOKS_DIR = ".githooks"
MARKER = f"# SAFECODE_HOOK_VERSION: {HOOK_VERSION}"
SAFECODE_MARKER_PREFIX = "# SAFECODE_HOOK_VERSION:"

BOUNDARY_NOTE = (
    "客户端 hook 不是唯一安全边界：--no-verify 可绕过本地 hook；"
    "CI Required Check 与分支保护是独立防线。"
)


def hook_script_content() -> str:
    return (
        "#!/bin/sh\n"
        f"{MARKER}\n"
        "# SafeCode managed pre-push hook. Client-side gate only; not the sole boundary.\n"
        "# CI Required Checks + Branch Protection are independent defenses.\n"
        'HOOK_DIR=$(cd "$(dirname "$0")" && pwd)\n'
        'REPO_ROOT=$(cd "$HOOK_DIR/.." && pwd)\n'
        "# 探测可用的 Python 解释器；找不到就阻断（fail-closed，绝不静默放行）\n"
        'if [ -n "$SAFECODE_PYTHON" ] && command -v "$SAFECODE_PYTHON" >/dev/null 2>&1; then\n'
        '  exec "$SAFECODE_PYTHON" "$REPO_ROOT/scripts/pre-push.py" "$@"\n'
        "fi\n"
        "for candidate in python3 python; do\n"
        '  if command -v "$candidate" >/dev/null 2>&1; then\n'
        '    exec "$candidate" "$REPO_ROOT/scripts/pre-push.py" "$@"\n'
        "  fi\n"
        "done\n"
        'if command -v py >/dev/null 2>&1; then\n'
        '  exec py -3 "$REPO_ROOT/scripts/pre-push.py" "$@"\n'
        "fi\n"
        'echo "SafeCode: no python interpreter found, blocking push (fail-closed)" >&2\n'
        "exit 1\n"
    )


def _repo(cwd):
    return sc.repo_root(cwd) or (cwd or os.getcwd())


def _hook_path(repo):
    return os.path.join(repo, HOOKS_DIR, HOOK_FILENAME)


def _set_hooks_path(repo):
    proc = sc.run_git(["config", "core.hooksPath", HOOKS_DIR], cwd=repo)
    return proc.returncode == 0


def _read_hooks_path(repo):
    proc = sc.run_git(["config", "core.hooksPath"], cwd=repo)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _version_of(content):
    for line in content.splitlines():
        if line.startswith(SAFECODE_MARKER_PREFIX):
            return line.split(":", 1)[1].strip()
    return None


def _is_windows():
    return os.name == "nt"


def _write_hook(repo):
    path = _hook_path(repo)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(hook_script_content())
    try:
        os.chmod(path, 0o755)
    except OSError:
        pass
    return path


# --------------------------------------------------------------------------- #
# 子命令
# --------------------------------------------------------------------------- #

def cmd_install(reporter, cwd) -> int:
    if not sc.is_git_repo(cwd):
        return _emit(reporter, sc.env_error_result("NOT_A_GIT_REPO", "not a git repository"))
    repo = _repo(cwd)
    path = _hook_path(repo)

    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
        ver = _version_of(content)
        if ver is not None:
            if ver == HOOK_VERSION:
                _set_hooks_path(repo)
                return _emit(reporter, sc.pass_result(
                    "HOOK_ALREADY_INSTALLED", "SafeCode hook already installed at current version",
                    category=sc.CATEGORY_GIT,
                    metadata=_meta(repo, path, action="already_installed"),
                ))
            return _emit(reporter, sc.fail_deny_result(
                "HOOK_OUTDATED",
                f"existing SafeCode hook is version {ver}; run `hook-manager.py update`",
                category=sc.CATEGORY_GIT,
                metadata=_meta(repo, path, action="outdated"),
            ))
        return _emit(reporter, sc.fail_deny_result(
            "HOOK_FOREIGN",
            "refusing to overwrite a non-SafeCode pre-push hook; remove it manually if intended",
            category=sc.CATEGORY_GIT,
            metadata=_meta(repo, path, action="foreign"),
        ))

    written = _write_hook(repo)
    if not _set_hooks_path(repo):
        return _emit(reporter, sc.env_error_result(
            "GIT_CONFIG_FAILED", "cannot set core.hooksPath",
            metadata=_meta(repo, written, action="install"),
        ))
    return _emit(reporter, sc.pass_result(
        "HOOK_INSTALLED", "SafeCode pre-push hook installed",
        category=sc.CATEGORY_GIT,
        metadata=_meta(repo, written, action="installed"),
    ))


def cmd_verify(reporter, cwd) -> int:
    if not sc.is_git_repo(cwd):
        return _emit(reporter, sc.env_error_result("NOT_A_GIT_REPO", "not a git repository"))
    repo = _repo(cwd)
    path = _hook_path(repo)

    hooks_path = _read_hooks_path(repo)
    if hooks_path != HOOKS_DIR:
        return _emit(reporter, sc.fail_deny_result(
            "HOOK_HOOKSPATH_MISMATCH",
            f"core.hooksPath is {hooks_path!r}, expected {HOOKS_DIR!r}",
            category=sc.CATEGORY_GIT,
            metadata=_meta(repo, path, action="verify", hooks_path=hooks_path),
        ))

    if not os.path.isfile(path):
        return _emit(reporter, sc.fail_deny_result(
            "HOOK_MISSING", f"hook file not found: {path}",
            category=sc.CATEGORY_GIT,
            metadata=_meta(repo, path, action="verify"),
        ))

    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read()
    ver = _version_of(content)
    if ver is None:
        return _emit(reporter, sc.fail_deny_result(
            "HOOK_REPLACED", "hook content has no SafeCode version marker (replaced)",
            category=sc.CATEGORY_GIT,
            metadata=_meta(repo, path, action="verify"),
        ))
    if ver != HOOK_VERSION:
        return _emit(reporter, sc.fail_deny_result(
            "HOOK_OUTDATED", f"hook version {ver} != current {HOOK_VERSION}; run update",
            category=sc.CATEGORY_GIT,
            metadata=_meta(repo, path, action="verify"),
        ))

    # 可执行性检查：Windows 上可执行位不可靠 -> 降级为文件存在 + 内容校验
    executable_ok = True
    exec_note = "checked"
    if _is_windows():
        exec_note = "degraded: executable bit unreliable on Windows; verified file + content only"
    else:
        executable_ok = os.access(path, os.X_OK)
        exec_note = "executable bit set" if executable_ok else "not executable"

    if not executable_ok:
        return _emit(reporter, sc.fail_deny_result(
            "HOOK_NOT_EXECUTABLE", f"hook is not executable: {path}",
            category=sc.CATEGORY_GIT,
            metadata=_meta(repo, path, action="verify", executable=exec_note),
        ))

    return _emit(reporter, sc.pass_result(
        "HOOK_VERIFIED", "SafeCode pre-push hook verified",
        category=sc.CATEGORY_GIT,
        metadata=_meta(repo, path, action="verify", executable=exec_note, verified=True),
    ))


def cmd_update(reporter, cwd) -> int:
    if not sc.is_git_repo(cwd):
        return _emit(reporter, sc.env_error_result("NOT_A_GIT_REPO", "not a git repository"))
    repo = _repo(cwd)
    path = _hook_path(repo)

    backup_path = None
    if os.path.isfile(path):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_dir = os.path.join(repo, ".safecode", "backup")
        os.makedirs(backup_dir, exist_ok=True)
        backup_path = os.path.join(backup_dir, f"{HOOK_FILENAME}.{ts}")
        try:
            shutil.copyfile(path, backup_path)
        except OSError:
            backup_path = None

    written = _write_hook(repo)
    if not _set_hooks_path(repo):
        return _emit(reporter, sc.env_error_result(
            "GIT_CONFIG_FAILED", "cannot set core.hooksPath",
            metadata=_meta(repo, written, action="update", backup=backup_path),
        ))
    return _emit(reporter, sc.pass_result(
        "HOOK_UPDATED", "SafeCode pre-push hook updated to current version",
        category=sc.CATEGORY_GIT,
        metadata=_meta(repo, written, action="update", backup=backup_path, version=HOOK_VERSION),
    ))


def _meta(repo, path, action, **extra):
    meta = {
        "core_hooks_path": HOOKS_DIR,
        "hook_path": path,
        "version": HOOK_VERSION,
        "action": action,
        "boundary_note": BOUNDARY_NOTE,
    }
    meta.update(extra)
    return meta


def _emit(reporter, result):
    code = sc.exit_code_for(result)
    reporter.emit_result(result, exit_code=code)
    return code


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="hook-manager.py", description="SafeCode Hook 生命周期管理")
    sc.add_common_arguments(parser)
    parser.add_argument("--cwd", default=None, help="仓库根目录（默认当前工作目录）")
    sub = parser.add_subparsers(dest="cmd", required=True)
    # 子解析器同样接受公共参数（suppress_defaults 保证不会覆盖写在子命令之前的同名参数）
    for name, help_text in (
        ("install", "安装 SafeCode pre-push hook"),
        ("verify", "校验 hook 是否就位且未被替换"),
        ("update", "更新为当前版本（保留备份）"),
    ):
        child = sub.add_parser(name, help=help_text)
        sc.add_common_arguments(child, suppress_defaults=True)
    args = parser.parse_args(argv)

    reporter = sc.reporter_from_args(args)
    cwd = getattr(args, "cwd", None)

    if args.cmd == "install":
        return cmd_install(reporter, cwd)
    if args.cmd == "verify":
        return cmd_verify(reporter, cwd)
    if args.cmd == "update":
        return cmd_update(reporter, cwd)
    return _emit(reporter, sc.usage_error_result("USAGE", "unknown command"))


if __name__ == "__main__":
    sys.exit(main())
