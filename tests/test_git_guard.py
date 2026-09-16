"""git-guard.py / safecode_approval.py / hook-manager.py 的黑盒 + 单元回归测试。

覆盖：
- --check-diff：拦下含 git push --force / git reset --hard / filter-branch / DROP DATABASE 的
  暂存改动（exit 1 + code 合理）；干净改动放行（exit 0）；--no-verify 记录 events.jsonl 并拒绝。
- --pre-push：拦强推（构造非祖先关系）/ 删除远程分支（local_sha 全零）/ 受保护分支拒绝；
  合法祖先关系放行（配 SAFECODE_ALLOW_MAIN=1 规避 main 保护）。
- --preflight：对 git push --force 返回 REQUIRE_APPROVAL 且 metadata 含 operation_fingerprint；
  安全命令放行；--no-verify 拒绝。
- Approval 全流程：无 token 拒绝 -> issue -> 带有效 token 放行 -> 重复同一 token 被拒（TOKEN_REPLAYED）
  -> 过期 token 被拒 -> 指纹不匹配（换 command / target / repo）被拒。
- Hook 生命周期：install -> verify 通过 -> 篡改内容后 verify 失败 -> update 修复。
- 所有 git-guard / hook-manager 输出均经 assert_result_schema 校验；--json 时 stdout 干净。
"""

import os
import shutil
import sys

import pytest

# 让本测试可直接 import scripts/safecode_approval
SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS_DIR))

from conftest import (  # noqa: E402
    run_cmd,
    run_script,
    parse_json_output,
    assert_result_schema,
    git,
)

import safecode_approval as sa  # noqa: E402


def _rev(repo, ref="HEAD"):
    return git(["rev-parse", ref], cwd=repo).stdout.strip()


def _commit(repo, name, content):
    (repo / name).write_text(content, encoding="utf-8")
    git(["add", name], cwd=repo)
    git(["commit", "-q", "-m", f"commit {name}"], cwd=repo)


# --------------------------------------------------------------------------- #
# --check-diff
# --------------------------------------------------------------------------- #

def test_check_diff_force_push_blocked(tmp_git_repo):
    repo = tmp_git_repo
    (repo / "deploy.sh").write_text("#!/bin/bash\ngit push --force origin main\n", encoding="utf-8")
    git(["add", "deploy.sh"], cwd=repo)

    proc = run_script("git-guard.py", "--json", "--check-diff", cwd=repo)
    assert proc.returncode == 1, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "DENY"
    assert payload["code"] == "GIT_FORCE_PUSH"


def test_check_diff_reset_hard_blocked(tmp_git_repo):
    repo = tmp_git_repo
    (repo / "fix.sh").write_text("git reset --hard\n", encoding="utf-8")
    git(["add", "fix.sh"], cwd=repo)
    proc = run_script("git-guard.py", "--json", "--check-diff", cwd=repo)
    assert proc.returncode == 1
    assert parse_json_output(proc)["code"] == "GIT_RESET_HARD"


def test_check_diff_filter_branch_blocked(tmp_git_repo):
    repo = tmp_git_repo
    (repo / "rewrite.sh").write_text("git filter-branch --tree-filter 'rm secret' HEAD\n", encoding="utf-8")
    git(["add", "rewrite.sh"], cwd=repo)
    proc = run_script("git-guard.py", "--json", "--check-diff", cwd=repo)
    assert proc.returncode == 1
    assert parse_json_output(proc)["code"] == "GIT_HISTORY_REWRITE"


def test_check_diff_drop_database_blocked(tmp_git_repo):
    repo = tmp_git_repo
    (repo / "schema.sql").write_text("DROP DATABASE production;\n", encoding="utf-8")
    git(["add", "schema.sql"], cwd=repo)
    proc = run_script("git-guard.py", "--json", "--check-diff", cwd=repo)
    assert proc.returncode == 1
    assert parse_json_output(proc)["code"] == "DATA_DROP"


def test_check_diff_clean_allowed(tmp_git_repo):
    repo = tmp_git_repo
    (repo / "notes.txt").write_text("just a normal change\n", encoding="utf-8")
    git(["add", "notes.txt"], cwd=repo)
    proc = run_script("git-guard.py", "--json", "--check-diff", cwd=repo)
    assert proc.returncode == 0, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "ALLOW"


def test_check_diff_no_verify_recorded_and_rejected(tmp_git_repo):
    repo = tmp_git_repo
    (repo / "push.sh").write_text("git push --no-verify origin main\n", encoding="utf-8")
    git(["add", "push.sh"], cwd=repo)
    proc = run_script("git-guard.py", "--json", "--check-diff", cwd=repo)
    assert proc.returncode == 1
    payload = parse_json_output(proc)
    assert payload["code"] == "BYPASS_NO_VERIFY"
    events = repo / ".safecode" / "events.jsonl"
    assert events.is_file(), "bypass event must be recorded"
    assert "bypass_attempt" in events.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# --pre-push
# --------------------------------------------------------------------------- #

def test_pre_push_force_detected(tmp_git_repo):
    repo = tmp_git_repo
    _commit(repo, "a.txt", "A")
    git(["checkout", "-q", "HEAD~1"], cwd=repo)
    git(["checkout", "-q", "-b", "dev"], cwd=repo)
    _commit(repo, "b.txt", "B")
    sha_b = _rev(repo, "HEAD")
    git(["checkout", "-q", "main"], cwd=repo)
    sha_a = _rev(repo, "HEAD")

    line = f"refs/heads/main {sha_a} refs/heads/main {sha_b}\n"
    proc = run_script("git-guard.py", "--json", "--pre-push", cwd=repo,
                      stdin_text=line, env={"SAFECODE_ALLOW_MAIN": "1"})
    assert proc.returncode == 1, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "REQUIRE_APPROVAL"


def test_pre_push_branch_deletion_detected(tmp_git_repo):
    repo = tmp_git_repo
    sha = _rev(repo, "HEAD")
    zero = "0" * 40
    line = f"refs/heads/feature {zero} refs/heads/feature {sha}\n"
    proc = run_script("git-guard.py", "--json", "--pre-push", cwd=repo, stdin_text=line)
    assert proc.returncode == 1
    assert parse_json_output(proc)["code"] == "BRANCH_DELETE_REJECTED"


def test_pre_push_valid_ancestor_allowed(tmp_git_repo):
    repo = tmp_git_repo
    _commit(repo, "c.txt", "C")
    local_sha = _rev(repo, "HEAD")
    remote_sha = _rev(repo, "HEAD~1")
    line = f"refs/heads/main {local_sha} refs/heads/main {remote_sha}\n"
    proc = run_script("git-guard.py", "--json", "--pre-push", cwd=repo,
                      stdin_text=line, env={"SAFECODE_ALLOW_MAIN": "1"})
    assert proc.returncode == 0, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "ALLOW"


def test_pre_push_protected_branch_rejected(tmp_git_repo):
    repo = tmp_git_repo
    _commit(repo, "c.txt", "C")
    local_sha = _rev(repo, "HEAD")
    remote_sha = _rev(repo, "HEAD~1")
    line = f"refs/heads/main {local_sha} refs/heads/main {remote_sha}\n"
    proc = run_script("git-guard.py", "--json", "--pre-push", cwd=repo, stdin_text=line)
    assert proc.returncode == 1
    assert parse_json_output(proc)["code"] == "PROTECTED_BRANCH_REJECTED"


# --------------------------------------------------------------------------- #
# --preflight
# --------------------------------------------------------------------------- #

def test_preflight_force_push_requires_approval(tmp_git_repo):
    repo = tmp_git_repo
    proc = run_script("git-guard.py", "--json", "--preflight",
                      "--command", "git push --force origin main", cwd=repo)
    assert proc.returncode == 1, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "REQUIRE_APPROVAL"
    assert "operation_fingerprint" in payload["metadata"]
    assert payload["metadata"]["operation_fingerprint"].startswith("sha256:")


def test_preflight_safe_command_allowed(tmp_git_repo):
    repo = tmp_git_repo
    proc = run_script("git-guard.py", "--json", "--preflight",
                      "--command", "git status", cwd=repo)
    assert proc.returncode == 0, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "ALLOW"


def test_preflight_no_verify_recorded_and_rejected(tmp_git_repo):
    repo = tmp_git_repo
    proc = run_script("git-guard.py", "--json", "--preflight",
                      "--command", "git push --no-verify origin main", cwd=repo)
    assert proc.returncode == 1
    payload = parse_json_output(proc)
    assert payload["code"] == "BYPASS_NO_VERIFY"
    events = repo / ".safecode" / "events.jsonl"
    assert events.is_file()
    assert "bypass_attempt" in events.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Approval Token 全流程
# --------------------------------------------------------------------------- #

def test_approval_cli_flow(tmp_git_repo):
    repo = tmp_git_repo
    op = "git push --force origin main"

    # 1) 无 token：拒绝（REQUIRE_APPROVAL）
    proc = run_script("git-guard.py", "--json", "--preflight", "--command", op, cwd=repo)
    assert proc.returncode == 1
    assert parse_json_output(proc)["decision"] == "REQUIRE_APPROVAL"

    # 2) issue token
    token = sa.issue_token(op, cwd=str(repo))
    token_path = sa.approval_record_path(token["nonce"], cwd=str(repo))
    assert os.path.isfile(token_path)

    # 3) 带有效 token：放行
    proc = run_script("git-guard.py", "--json", "--preflight", "--command", op, cwd=repo,
                      env={"SAFECODE_APPROVAL_TOKEN": token_path})
    assert proc.returncode == 0, proc.stderr
    payload = parse_json_output(proc)
    assert payload["decision"] == "ALLOW"
    assert payload["metadata"]["token_nonce"] == token["nonce"]
    assert payload["metadata"]["approved_by"] == "human"

    # 4) 重复同一 token：被拒（TOKEN_REPLAYED）
    proc = run_script("git-guard.py", "--json", "--preflight", "--command", op, cwd=repo,
                      env={"SAFECODE_APPROVAL_TOKEN": token_path})
    assert proc.returncode == 1
    assert parse_json_output(proc)["code"] == "TOKEN_REPLAYED"


def _make_repo(base):
    """在 base 下初始化一个独立 git 仓库（绕过 tmp_git_repo 的 fixture 缓存）。"""
    base.mkdir(parents=True, exist_ok=True)
    git(["init", "-b", "main"], cwd=base)
    git(["config", "user.email", "safecode@example.invalid"], cwd=base)
    git(["config", "user.name", "SafeCode Test"], cwd=base)
    git(["config", "commit.gpgsign", "false"], cwd=base)
    (base / "R.md").write_text("x\n", encoding="utf-8")
    git(["add", "R.md"], cwd=base)
    git(["commit", "-qm", "init"], cwd=base)
    return base


def test_approval_verify_codes(tmp_git_repo, tmp_path):
    repo = tmp_git_repo
    op = "git push --force origin main"
    token = sa.issue_token(op, target="main", cwd=str(repo))

    # 过期 token
    expired = dict(token)
    expired["expires_at"] = "2000-01-01T00:00:00Z"
    with pytest.raises(sa.ApprovalError) as ei:
        sa.verify_token(expired, operation=op, target="main", cwd=str(repo))
    assert ei.value.code == sa.TOKEN_EXPIRED

    # operation 不匹配
    with pytest.raises(sa.ApprovalError) as ei:
        sa.verify_token(token, operation="git push --force origin dev", target="main", cwd=str(repo))
    assert ei.value.code == sa.TOKEN_OPERATION_MISMATCH

    # target / fingerprint 不匹配（operation 相同，target 不同）
    with pytest.raises(sa.ApprovalError) as ei:
        sa.verify_token(token, operation=op, target="other", cwd=str(repo))
    assert ei.value.code == sa.TOKEN_FINGERPRINT_MISMATCH

    # 仓库不匹配（独立仓库，路径不同 -> repository_identity 不同）
    repo2 = _make_repo(tmp_path / "repo2")
    with pytest.raises(sa.ApprovalError) as ei:
        sa.verify_token(token, operation=op, target="main", cwd=str(repo2))
    assert ei.value.code == sa.TOKEN_REPO_MISMATCH

    # 正常核销 + 二次使用被拒
    sa.consume_token(token, operation=op, target="main", cwd=str(repo))
    with pytest.raises(sa.ApprovalError) as ei:
        sa.verify_token(token, operation=op, target="main", cwd=str(repo))
    assert ei.value.code == sa.TOKEN_REPLAYED


# --------------------------------------------------------------------------- #
# approve 子命令
# --------------------------------------------------------------------------- #

def test_approve_subcommand_and_replay(tmp_git_repo):
    repo = tmp_git_repo
    op = "git push --force origin main"
    token = sa.issue_token(op, cwd=str(repo))
    token_path = sa.approval_record_path(token["nonce"], cwd=str(repo))

    proc = run_script("git-guard.py", "--json", "approve", "--token", token_path, cwd=repo)
    assert proc.returncode == 0, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "ALLOW"
    assert payload["metadata"]["token_nonce"] == token["nonce"]

    # 二次核销被拒
    proc = run_script("git-guard.py", "--json", "approve", "--token", token_path, cwd=repo)
    assert proc.returncode == 1
    assert parse_json_output(proc)["code"] == "TOKEN_REPLAYED"


# --------------------------------------------------------------------------- #
# Hook 生命周期
# --------------------------------------------------------------------------- #

def test_hook_lifecycle(tmp_git_repo):
    repo = tmp_git_repo

    # install
    proc = run_script("hook-manager.py", "--json", "install", cwd=repo)
    assert proc.returncode == 0, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["decision"] == "ALLOW"

    hook = repo / ".githooks" / "pre-push"
    assert hook.is_file()
    hook_content = hook.read_text(encoding="utf-8")
    assert "# SAFECODE_HOOK_VERSION:" in hook_content
    assert "scripts/pre-push.py" in hook_content

    # verify 通过
    proc = run_script("hook-manager.py", "--json", "verify", cwd=repo)
    assert proc.returncode == 0, proc.stderr
    assert parse_json_output(proc)["code"] == "HOOK_VERIFIED"

    # 篡改 hook 内容
    hook.write_text("#!/bin/sh\n# tampered by attacker\nexec rm -rf /\n", encoding="utf-8")

    # verify 失败
    proc = run_script("hook-manager.py", "--json", "verify", cwd=repo)
    assert proc.returncode == 1
    assert parse_json_output(proc)["code"] == "HOOK_REPLACED"

    # update 修复
    proc = run_script("hook-manager.py", "--json", "update", cwd=repo)
    assert proc.returncode == 0, proc.stderr
    payload = parse_json_output(proc)
    assert payload["code"] == "HOOK_UPDATED"
    assert payload["metadata"].get("backup")

    # verify 再次通过
    proc = run_script("hook-manager.py", "--json", "verify", cwd=repo)
    assert proc.returncode == 0, proc.stderr
    assert parse_json_output(proc)["code"] == "HOOK_VERIFIED"


def test_hook_survives_git_positional_args(tmp_git_repo):
    """回归：git 会以 `<remote-name> <remote-url>` 调用 hook。

    早期实现把 "$@" 原样转交给 pre-push.py，于是每次推送都被 argparse 判成
    用法错误而拦下——fail-closed 生效了，但拦错了对象。这里锁住行为：
    带着 git 的位置参数调用 hook，必须仍然正常跑完流水线。
    """
    repo = tmp_git_repo
    # hook 会把仓库根下的 scripts/ 当成 SafeCode 实现来调用，所以先把脚本放进去
    shutil.copytree(os.path.abspath(SCRIPTS_DIR), repo / "scripts")
    install = run_script("hook-manager.py", "--json", "install", cwd=repo)
    assert install.returncode == 0, install.stderr

    hook = repo / ".githooks" / "pre-push"
    assert hook.is_file()
    content = hook.read_text(encoding="utf-8")
    assert '"$@"' not in content, "hook 不能把 git 的位置参数转发给 SafeCode 脚本"

    sh = shutil.which("sh")
    if sh is None:
        pytest.skip("sh not available")

    env = {"SAFECODE_PYTHON": sys.executable,
           "SAFECODE_PREPUSH_ARGS": "--dry-run --skip-tests"}
    proc = run_cmd([sh, str(hook), "origin", "https://example.invalid/repo.git"],
                   cwd=repo, env=env)
    assert "unrecognized arguments" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["code"] == "PIPELINE_PASSED"
