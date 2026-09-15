"""security-scan.py 的黑盒测试。

覆盖：真实凭据被拦截（退出码 1 + JSON 含 rule）、占位符放行（0）、
tests/ 目录下疑似凭据降级为 info（0）、二进制文件不误报（0）。
"""

import json
from pathlib import Path

from conftest import py, run, SCRIPTS


def _json_has_rule(obj):
    """递归判断解析后的 JSON 中是否出现含 'rule' 键的对象。"""
    if isinstance(obj, dict):
        if "rule" in obj:
            return True
        return any(_json_has_rule(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_json_has_rule(v) for v in obj)
    return False


def _write_real_creds(repo):
    """写一个含多种真实样式凭据的文件集合并 git add。"""
    creds_py = repo / "config.py"
    creds_py.write_text(
        'api_key = "sk-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"\n'
        'github_token = "ghp_' + "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8" + '"\n'
        'SESSDATA = "abcdef0123456789abcdef01234567890xyz"\n'
    )
    pem = repo / "private.pem"
    pem.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEogIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    env = repo / ".env"
    env.write_text('DB_PASSWORD="supersecretpassword123"\n')
    run(["git", "add", "config.py", "private.pem", ".env"], cwd=repo)


def test_real_credential_detected_staged(security_scan_script, tmp_git_repo):
    repo = tmp_git_repo
    _write_real_creds(repo)

    rc, out, err = py([str(security_scan_script), "--staged"], cwd=repo)
    assert rc == 1, f"期望退出码 1，实际 {rc}; stderr={err}"


def test_real_credential_json_has_rule(security_scan_script, tmp_git_repo):
    repo = tmp_git_repo
    _write_real_creds(repo)

    rc, out, err = py([str(security_scan_script), "--staged", "--json"], cwd=repo)
    assert rc == 1, f"期望退出码 1，实际 {rc}; stderr={err}"
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        # 部分实现把 JSON 混在 stderr，再试一次
        data = json.loads(err)
    assert _json_has_rule(data), f"--json 输出应含 'rule' 字段; out={out}; err={err}"


def test_placeholder_allowed(security_scan_script, tmp_git_repo):
    repo = tmp_git_repo
    (repo / "placeholder.py").write_text('api_key = "YOUR_API_KEY_HERE"\n')
    run(["git", "add", "placeholder.py"], cwd=repo)

    rc, out, err = py([str(security_scan_script), "--staged"], cwd=repo)
    assert rc == 0, f"占位符应放行，期望 0，实际 {rc}; out={out}; err={err}"


def test_tests_dir_downgraded_to_info(security_scan_script, tmp_git_repo):
    repo = tmp_git_repo
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    (tests_dir / "sample.py").write_text(
        'api_key = "sk-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"\n'
    )
    run(["git", "add", "tests/sample.py"], cwd=repo)

    rc, out, err = py([str(security_scan_script), "--staged"], cwd=repo)
    assert rc == 0, f"tests/ 下疑似凭据应降级为 info（退出码 0），实际 {rc}; out={out}; err={err}"


def test_binary_file_not_false_positive(security_scan_script, tmp_git_repo):
    repo = tmp_git_repo
    binary = repo / "image.png"
    binary.write_bytes(b"\x00\x01\x02\x03\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    # 即便写入一段像凭据的字符串也不应把二进制误报
    binary.write_bytes(binary.read_bytes() + b"sk-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")
    run(["git", "add", "image.png"], cwd=repo)

    rc, out, err = py([str(security_scan_script), "--staged"], cwd=repo)
    assert rc == 0, f"二进制文件不应误报，期望 0，实际 {rc}; out={out}; err={err}"
