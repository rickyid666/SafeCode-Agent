"""SafeCode 测试公共设施。

约定：

- 所有测试以黑盒为主：通过 subprocess 调用 CLI，断言 Structured JSON + 退出码，
  而不是 import 脚本内部函数。这样测试直接验证"契约"，而不是验证实现细节。
- 被测试脚本尚未实现时 pytest.skip，避免并行开发期互相阻塞。
- 每个脚本都以 PYTHONPATH=scripts 运行，保证能 import 到 safecode_common 等模块。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
SCHEMAS_DIR = REPO_ROOT / "schemas"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

PYTHON = sys.executable

# 退出码契约
EXIT_OK = 0
EXIT_FINDING = 1
EXIT_USAGE = 2
EXIT_TOOL = 3
EXIT_ENV = 4


def _git_bin_dir() -> Optional[str]:
    """返回 git 可执行文件所在目录（用于把 git 注入子进程 PATH）。"""
    found = shutil.which("git")
    if found:
        return str(Path(found).parent)
    candidates = [
        Path.home() / ".workbuddy" / "binaries" / "PortableGit" / "versions",
        Path("C:/Program Files/Git/cmd"),
        Path("/usr/bin"),
    ]
    for base in candidates:
        if not base.exists():
            continue
        if base.name == "versions":
            for version in sorted(base.iterdir(), reverse=True):
                for rel in ("bin", "cmd", "mingw64/bin"):
                    candidate = version / rel / "git.exe"
                    if candidate.exists():
                        return str(candidate.parent)
        else:
            for rel in ("git.exe", "git"):
                candidate = base / rel
                if candidate.exists():
                    return str(candidate.parent)
    return None


GIT_BIN_DIR = _git_bin_dir()


def child_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """构造子进程环境：注入 PYTHONPATH、git 路径，清除外部 SafeCode 模式变量。"""
    env = dict(os.environ)
    pythonpath = [str(SCRIPTS_DIR)]
    if env.get("PYTHONPATH"):
        pythonpath.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pythonpath)
    if GIT_BIN_DIR:
        env["PATH"] = GIT_BIN_DIR + os.pathsep + env.get("PATH", "")
    for key in ("SAFECODE_STRICT", "SAFECODE_ALLOW_MAIN", "SAFECODE_APPROVAL_TOKEN",
                "SAFECODE_TASK_ID", "CI", "GITHUB_ACTIONS"):
        env.pop(key, None)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    if extra:
        env.update({k: str(v) for k, v in extra.items()})
    return env


def run_cmd(cmd: Sequence[str], *, cwd: Optional[Path] = None,
            stdin_text: Optional[str] = None,
            env: Optional[Dict[str, str]] = None,
            timeout: int = 300) -> subprocess.CompletedProcess:
    """运行任意命令。"""
    return subprocess.run(
        list(cmd),
        cwd=str(cwd) if cwd else None,
        input=stdin_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        env=child_env(env),
        timeout=timeout,
    )


def script_exists(name: str) -> bool:
    return (SCRIPTS_DIR / name).is_file()


def run_script(name: str, *args: str, cwd: Optional[Path] = None,
               stdin_text: Optional[str] = None,
               env: Optional[Dict[str, str]] = None,
               timeout: int = 300, require: bool = True) -> subprocess.CompletedProcess:
    """运行 scripts/ 下的脚本；脚本不存在且 require=True 时 pytest.skip。"""
    path = SCRIPTS_DIR / name
    if not path.is_file():
        if require:
            pytest.skip(f"script not implemented yet: {name}")
        raise FileNotFoundError(str(path))
    return run_cmd([PYTHON, str(path), *[str(a) for a in args]],
                   cwd=cwd, stdin_text=stdin_text, env=env, timeout=timeout)


def safecode_cli(*args: str, cwd: Optional[Path] = None,
                 stdin_text: Optional[str] = None,
                 env: Optional[Dict[str, str]] = None,
                 timeout: int = 300) -> subprocess.CompletedProcess:
    """通过统一入口 scripts/safecode.py 调用。"""
    return run_script("safecode.py", *args, cwd=cwd, stdin_text=stdin_text,
                      env=env, timeout=timeout)


def parse_json_output(proc: subprocess.CompletedProcess) -> Dict[str, Any]:
    """解析 stdout 上的 Structured JSON。

    约定：stdout 上只有机器 JSON，人类日志都在 stderr。
    实现允许输出单个 JSON 对象（可能多行），因此优先整体解析，失败再逐行尝试。
    """
    text = (proc.stdout or "").strip()
    assert text, f"stdout is empty; stderr={proc.stderr!r}"
    try:
        payload = json.loads(text)
    except ValueError:
        payload = None
        for line in reversed(text.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
                break
            except ValueError:
                continue
        assert payload is not None, f"stdout is not parseable as JSON: {text[:400]!r}"
    assert isinstance(payload, dict), f"expected a JSON object, got {type(payload).__name__}"
    return payload


def assert_result_schema(payload: Dict[str, Any]) -> None:
    """就地校验 Structured JSON 必填字段与枚举（不依赖 jsonschema 库）。"""
    required = ("schema_version", "status", "decision", "severity",
                "category", "code", "message", "locations", "metadata")
    for key in required:
        assert key in payload, f"missing required field: {key} (got {sorted(payload)})"
    assert payload["schema_version"] == "1.0"
    assert payload["status"] in ("PASS", "FAIL", "DEGRADED")
    assert payload["decision"] in ("ALLOW", "DENY", "REQUIRE_APPROVAL")
    assert payload["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert isinstance(payload["category"], str) and payload["category"]
    assert isinstance(payload["code"], str) and payload["code"]
    assert payload["code"] == payload["code"].upper() or all(
        ch.isupper() or ch.isdigit() or ch == "_" for ch in payload["code"]
    ), f"code must match ^[A-Z0-9_]+$: {payload['code']!r}"
    assert isinstance(payload["message"], str)
    assert isinstance(payload["locations"], list)
    assert isinstance(payload["metadata"], dict)


def git(args: Sequence[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    """在指定仓库运行 git。"""
    proc = run_cmd(["git", *args], cwd=cwd)
    if check:
        assert proc.returncode == 0, f"git {' '.join(args)} failed: {proc.stderr}"
    return proc


@pytest.fixture()
def tmp_git_repo(tmp_path: Path) -> Path:
    """初始化一个可用的临时 git 仓库（含一次初始提交）。"""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(["init", "-b", "main"], repo)
    git(["config", "user.email", "safecode@example.invalid"], repo)
    git(["config", "user.name", "SafeCode Test"], repo)
    git(["config", "commit.gpgsign", "false"], repo)
    (repo / "README.md").write_text("safe baseline\n", encoding="utf-8")
    git(["add", "README.md"], repo)
    git(["commit", "-m", "init"], repo)
    return repo


@pytest.fixture()
def safe_env() -> Dict[str, str]:
    """本地非严格模式的环境变量集合。"""
    return {"SAFECODE_STRICT": "0"}


@pytest.fixture()
def strict_env() -> Dict[str, str]:
    """STRICT 模式。"""
    return {"SAFECODE_STRICT": "1"}


def write_file(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
