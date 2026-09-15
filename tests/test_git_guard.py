"""git-guard.py 的黑盒测试。

覆盖：
- --check-diff：暂存区含危险命令（git push --force）被拦（1），干净改动放行（0）
- --pre-push：强推/分支删除被拦（1），合法祖先关系放行（0）
"""

import os
import subprocess

from conftest import run, py


def _sha(repo, ref="HEAD"):
    rc, out, err = run(["git", "rev-parse", ref], cwd=repo)
    assert rc == 0, err
    return out.strip()


def _commit(repo, name, content):
    (repo / name).write_text(content)
    run(["git", "add", name], cwd=repo)
    run(["git", "commit", "-q", "-m", f"commit {name}"], cwd=repo)


def test_check_diff_dangerous_command_blocked(git_guard_script, tmp_git_repo):
    repo = tmp_git_repo
    (repo / "deploy.sh").write_text("#!/bin/bash\ngit push --force origin main\n")
    run(["git", "add", "deploy.sh"], cwd=repo)

    rc, out, err = py([str(git_guard_script), "--check-diff"], cwd=repo)
    assert rc == 1, f"暂存区含强推命令应被拦，期望 1，实际 {rc}; out={out}; err={err}"


def test_check_diff_clean_change_allowed(git_guard_script, tmp_git_repo):
    repo = tmp_git_repo
    (repo / "notes.txt").write_text("just a normal change\n")
    run(["git", "add", "notes.txt"], cwd=repo)

    rc, out, err = py([str(git_guard_script), "--check-diff"], cwd=repo)
    assert rc == 0, f"干净改动应放行，期望 0，实际 {rc}; out={out}; err={err}"


def test_pre_push_force_detected(git_guard_script, tmp_git_repo):
    repo = tmp_git_repo
    # 在 main 上做一个新提交 A
    _commit(repo, "a.txt", "A")
    # 从初始提交切出 dev 分支并做提交 B，使 A 与 B 互不为祖先
    run(["git", "checkout", "-q", "HEAD~1"], cwd=repo)
    run(["git", "checkout", "-q", "-b", "dev"], cwd=repo)
    _commit(repo, "b.txt", "B")
    sha_b = _sha(repo, "HEAD")
    # 回到 main 拿到 A 的 sha，模拟把 main(A) 强推到 remote(B)
    run(["git", "checkout", "-q", "main"], cwd=repo)
    sha_a = _sha(repo, "HEAD")

    line = f"refs/heads/main {sha_a} refs/heads/main {sha_b}\n"
    rc, out, err = py([str(git_guard_script), "--pre-push"], cwd=repo, stdin_text=line)
    assert rc == 1, f"非祖先关系（强推）应被拦，期望 1，实际 {rc}; out={out}; err={err}"


def test_pre_push_branch_deletion_detected(git_guard_script, tmp_git_repo):
    repo = tmp_git_repo
    sha = _sha(repo, "HEAD")
    # 全零 local_sha 表示删除远程分支
    zero = "0" * 40
    line = f"refs/heads/feature {zero} refs/heads/feature {sha}\n"
    rc, out, err = py([str(git_guard_script), "--pre-push"], cwd=repo, stdin_text=line)
    assert rc == 1, f"删除远程分支应被拦，期望 1，实际 {rc}; out={out}; err={err}"


def test_pre_push_valid_ancestor_allowed(git_guard_script, tmp_git_repo):
    repo = tmp_git_repo
    # 在 main 上多做一个提交，使 HEAD 的父（初始提交）是其祖先
    _commit(repo, "c.txt", "C")
    local_sha = _sha(repo, "HEAD")
    remote_sha = _sha(repo, "HEAD~1")

    env = dict(os.environ)
    env["SAFECODE_ALLOW_MAIN"] = "1"
    line = f"refs/heads/main {local_sha} refs/heads/main {remote_sha}\n"
    rc, out, err = py([str(git_guard_script), "--pre-push"], cwd=repo, stdin_text=line, env=env)
    assert rc == 0, f"合法祖先关系应放行，期望 0，实际 {rc}; out={out}; err={err}"
