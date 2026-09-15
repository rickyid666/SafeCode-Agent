"""公共 pytest fixtures 与 helpers。

所有测试都通过 subprocess 以黑盒方式调用 scripts/ 下的 CLI，
不直接 import 脚本内部函数，以便对接口约定做直接验证。

scripts/ 由其他人并行实现，测试环境里可能尚未就绪。
若某个测试依赖的脚本文件不存在，用 pytest.skip 跳过而不是报错，
保证在 CI 中脚本齐备时才真正验证。
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


def _locate_git_dir():
    """找到 git 可执行文件所在目录，补进子进程 PATH。

    部分运行环境（如某些 PowerShell 启动的 pytest）的 PATH 里没有 git，
    而脚本通过子进程调用 git。这里尽量定位 git，保证测试可在这些环境跑通；
    CI（ubuntu/windows-latest runner）默认 PATH 含 git，自然也可用。
    """
    g = shutil.which("git")
    if g:
        return os.path.dirname(g)
    candidates = [
        r"C:\Program Files\Git\cmd",
        r"C:\Program Files\Git\bin",
        r"C:\Program Files (x86)\Git\cmd",
        "/usr/bin",
        "/usr/local/bin",
    ]
    for d in candidates:
        exe = os.path.join(d, "git.exe")
        if os.path.exists(exe):
            return d
        if os.path.exists(os.path.join(d, "git")):
            return d
    return None


GIT_DIR = _locate_git_dir()

# 仓库根目录（本 conftest 位于 <repo>/tests/ 下，向上一级即为仓库根）。
# 在 Windows 与 ubuntu CI 下都能正确解析到 SafeCode-Agent 根目录。
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"


def run(cmd, cwd=None, stdin_text=None, env=None):
    """跑一条命令，返回 (returncode, stdout, stderr)。

    cmd 必须是 list（不使用 shell=True），保证在 Windows / Linux 均可移植。
    env 可选，传入则在当前环境基础上追加/覆盖。
    """
    if env is None:
        env = os.environ.copy()
    if GIT_DIR is not None:
        # 确保子进程（git 命令或会调用 git 的脚本）能找到 git
        existing = env.get("PATH", "")
        if GIT_DIR not in existing.split(os.pathsep):
            env["PATH"] = GIT_DIR + os.pathsep + existing
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        input=stdin_text,
        capture_output=True,
        text=True,
        env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


def py(cmd_args, cwd=None, stdin_text=None, env=None):
    """用当前 Python 解释器跑脚本，cmd_args 为脚本路径及其参数。"""
    return run([sys.executable, *cmd_args], cwd=cwd, stdin_text=stdin_text, env=env)


def require_script(name):
    """若 scripts/<name> 不存在则跳过当前测试。"""
    path = SCRIPTS / name
    if not path.exists():
        pytest.skip(f"{name} 尚未实现（并行开发中），跳过")
    return path


@pytest.fixture
def security_scan_script():
    return require_script("security-scan.py")


@pytest.fixture
def git_guard_script():
    return require_script("git-guard.py")


@pytest.fixture
def test_runner_script():
    return require_script("test-runner.py")


@pytest.fixture
def recovery_script():
    return require_script("recovery.py")


@pytest.fixture
def pre_push_script():
    return require_script("pre-push.py")


@pytest.fixture
def tmp_git_repo(tmp_path):
    """在 tmp_path 下建一个最小 git 仓库，含一个干净的初始 commit。

    返回仓库路径（Path）。
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    run(["git", "init", "-q", str(repo)])
    run(["git", "config", "user.email", "test@example.com"], cwd=repo)
    run(["git", "config", "user.name", "Test User"], cwd=repo)
    run(["git", "config", "commit.gpgsign", "false"], cwd=repo)

    (repo / "clean.txt").write_text("this is a clean file\n")
    run(["git", "add", "clean.txt"], cwd=repo)
    run(["git", "commit", "-q", "-m", "initial commit"], cwd=repo)

    return repo
