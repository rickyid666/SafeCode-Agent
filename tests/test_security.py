"""security-scan.py 的黑盒测试（整体替换旧实现）。

覆盖：
- 各类凭据检测（AWS / GitHub / JWT / PEM / db 连接串 / SESSDATA / bili_jct / 高熵 generic）
- 占位符放行
- allow_list 命中放行 / rule 不匹配不放行
- baseline：NEW→DENY、写入后 known→放行、篡改指纹(同rule同path换值)→DENY、
  路径变化→DENY、baseline 损坏→DENY、过期→DENY
- ignore_paths 生效且不得覆盖 .git
- 敏感文件被跟踪报 HIGH
- shallow 仓库 fail-closed（完整扫描 DENY exit 3；diff 扫描允许但 incomplete_history）
- 外部 scanner 用 PATH 桩：合法 JSON findings / exit 非零 / 垃圾文本 三版本，
  验证 findings 合并、ERROR 当作失败不是通过、STRICT 下 DENY

凭据样例在运行期拼接，避免仓库自身 tests/ 出现真实格式字面量导致 CI 误报。

所有输出都用 assert_result_schema 校验。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from conftest import (
    assert_result_schema,
    child_env,
    git,
    parse_json_output,
    run_script,
    write_file,
)

# --------------------------------------------------------------------------- #
# 凭据样例（运行期拼接，不写真实格式字面量到源码）
# --------------------------------------------------------------------------- #

def _aws() -> str:
    return "AKIA" + "X" * 16


def _gh() -> str:
    return "ghp_" + "a" * 36


def _jwt() -> str:
    return (
        "eyJ" + "hbGciOiJIUzI1NiJ9"
        + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0"
        + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )


def _pem() -> str:
    # 拼接以避免源码里出现完整 PEM 头字面量
    return "-----BEGIN " + "RSA " + "PRIVATE KEY-----"


def _db() -> str:
    # 拼接以避免源码里出现完整连接串字面量：SafeCode 自己也要过自己的门禁
    return "postgresql://" + "user" + ":" + "password" + "@localhost:5432/app"


def _sess() -> str:
    return "SESSDATA=" + "abcdef0123456789ABCDEF0123456789"


def _jct() -> str:
    return "bili_jct=" + "abcdef0123456789abcd"


def _gen() -> str:
    return 'api_key="' + "K7mP9qW2xL5nB8vC3jR6tY1u" + '"'


def _write_real_creds(repo: Path) -> Path:
    """写一份包含多种真实格式凭据的文件并 git add（staged）。"""
    content = "\n".join([
        f'aws_key = "{_aws()}"',
        f'gh_token = "{_gh()}"',
        f'jwt = "{_jwt()}"',
        f'pem = "{_pem()}"',
        f'db = "{_db()}"',
        f'{_sess()}',
        f'{_jct()}',
        f'{_gen()}',
        "",
    ])
    p = repo / "config.py"
    write_file(p, content)
    git(["add", "config.py"], cwd=repo)
    return p


EXPECTED_RULES = [
    "aws-access-key-id",
    "github-token",
    "jwt",
    "pem-private-key-block",
    "db-connection-string",
    "bilibili-sessdata",
    "bilibili-bili-jct",
    "generic-secret-assignment",
]


# --------------------------------------------------------------------------- #
# 外部 scanner PATH 桩
# --------------------------------------------------------------------------- #

_STUB_PY = '''import sys, os, json
MODE = "{mode}"
FINDING_PATH = "{fp}"
args = sys.argv[1:]
rp = None
for i, a in enumerate(args):
    if a == "--report-path" and i + 1 < len(args):
        rp = args[i + 1]
if MODE == "valid":
    data = [{{"RuleID": "GITLEAKS_FAKE", "File": FINDING_PATH, "StartLine": 1,
              "Secret": "fakesecretvalue1234567890",
              "Match": "fakesecretvalue1234567890",
              "Description": "fake gitleaks finding for testing"}}]
    if rp:
        with open(rp, "w", encoding="utf-8") as f:
            json.dump(data, f)
    sys.exit(0)
elif MODE == "nonzero":
    sys.exit(1)
else:
    if rp:
        with open(rp, "w", encoding="utf-8") as f:
            f.write("not a json <<<")
    sys.exit(0)
'''

_BAT_WRAPPER = '@echo off\r\n"%SAFECODE_TEST_PYTHON%" "%~dp0gitleaks_stub.py" %*\r\n'


def _make_gitleaks_stub(tmp_path: Path, mode: str, finding_path: str = "external_leak.txt") -> Path:
    bindir = tmp_path / f"gitleaks_{mode}_{os.getpid()}"
    bindir.mkdir(parents=True, exist_ok=True)
    (bindir / "gitleaks_stub.py").write_text(_STUB_PY.format(mode=mode, fp=finding_path), encoding="utf-8")
    if os.name == "nt":
        for ext in (".bat", ".cmd"):
            (bindir / f"gitleaks{ext}").write_text(_BAT_WRAPPER, encoding="utf-8")
    else:
        (bindir / "gitleaks").write_text(
            "#!/usr/bin/env python3\n" + _STUB_PY.format(mode=mode, fp=finding_path), encoding="utf-8"
        )
        os.chmod(bindir / "gitleaks", 0o755)
    return bindir


def _ext_env(bindir: Path) -> dict:
    env = child_env({"SAFECODE_TEST_PYTHON": sys.executable})
    env["PATH"] = str(bindir) + os.pathsep + env["PATH"]
    return env


# --------------------------------------------------------------------------- #
# 检测类测试
# --------------------------------------------------------------------------- #

def test_all_credential_types_detected(tmp_git_repo):
    repo = tmp_git_repo
    _write_real_creds(repo)
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 1, f"期望退出码 1, 实际 {proc.returncode}; stderr={proc.stderr}"
    assert payload["decision"] == "DENY"
    assert payload["code"] == "SECRET_DETECTED"
    found_rules = {f["rule"] for f in payload["metadata"]["findings"]}
    for rule in EXPECTED_RULES:
        assert rule in found_rules, f"未检出规则 {rule}; 实际规则: {sorted(found_rules)}"


def test_aws_key_detected(tmp_git_repo):
    repo = tmp_git_repo
    write_file(repo / "a.py", f'k = "{_aws()}"\n')
    git(["add", "a.py"], cwd=repo)
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 1
    assert any(f["rule"] == "aws-access-key-id" for f in payload["metadata"]["findings"])


def test_placeholder_allowed(tmp_git_repo):
    repo = tmp_git_repo
    write_file(
        repo / "placeholder.py",
        'api_key = "YOUR_API_KEY_HERE"\n'
        'token = "example-token"\n'
        'secret = "test-secret"\n'
        'password = "example"\n',
    )
    git(["add", "placeholder.py"], cwd=repo)
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 0, f"占位符应放行, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["status"] == "PASS"
    assert payload["decision"] == "ALLOW"


# --------------------------------------------------------------------------- #
# allow_list
# --------------------------------------------------------------------------- #

def _write_config(repo: Path, text: str) -> None:
    write_file(repo / ".safecode.yml", text)


def test_allow_list_match_allows(tmp_git_repo):
    repo = tmp_git_repo
    _write_config(repo, (
        'schema_version: "1.0"\n'
        'security:\n'
        '  allow_list:\n'
        '    - rule: aws-access-key-id\n'
        '      path: config.py\n'
        '      reason: "known test fixture"\n'
    ))
    # 仅写入与 allow_list 命中规则匹配的凭据：应整体放行
    write_file(repo / "config.py", f'aws_key = "{_aws()}"\n')
    git(["add", "config.py"], cwd=repo)
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 0, f"allow_list 命中应放行, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["decision"] == "ALLOW"
    # 该 rule+path 被放行；其余规则仍应阻断
    aws_blocked = any(
        f["rule"] == "aws-access-key-id" and f["classification"] == "new"
        for f in payload["metadata"]["findings"]
    )
    assert not aws_blocked


def test_allow_list_rule_mismatch_blocks(tmp_git_repo):
    repo = tmp_git_repo
    _write_config(repo, (
        'schema_version: "1.0"\n'
        'security:\n'
        '  allow_list:\n'
        '    - rule: github-token\n'
        '      path: config.py\n'
        '      reason: "wrong rule"\n'
    ))
    _write_real_creds(repo)
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 1, f"rule 不匹配不应放行, 实际 {proc.returncode}"
    assert payload["decision"] == "DENY"


# --------------------------------------------------------------------------- #
# Baseline
# --------------------------------------------------------------------------- #

def test_baseline_new_then_known(tmp_git_repo):
    repo = tmp_git_repo
    _write_real_creds(repo)

    # 第一次：NEW → DENY
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 1 and payload["decision"] == "DENY"

    # 写入 baseline
    proc = run_script("security-scan.py", "--staged", "--write-baseline",
                      "--reason", "accept for test", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 0 and payload["code"] == "BASELINE_WRITTEN"

    # 第二次：known → 不再阻断
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 0, f"baseline known 应放行, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["decision"] == "ALLOW"
    assert payload["metadata"]["baseline"]["known"] >= 1
    assert payload["metadata"]["baseline"]["new"] == 0


def test_baseline_tamper_fingerprint_denies(tmp_git_repo):
    repo = tmp_git_repo
    p = _write_real_creds(repo)

    proc = run_script("security-scan.py", "--staged", "--write-baseline",
                      "--reason", "accept", "--no-external", cwd=repo)
    assert proc.returncode == 0

    # 篡改：同 rule 同 path 换值
    write_file(p, f'aws_key = "{_aws().replace("X", "Y")}"\n')
    git(["add", "config.py"], cwd=repo)
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 1, f"指纹变更应重新 DENY, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["decision"] == "DENY"


def test_baseline_path_change_denies(tmp_git_repo):
    repo = tmp_git_repo
    _write_real_creds(repo)

    proc = run_script("security-scan.py", "--staged", "--write-baseline",
                      "--reason", "accept", "--no-external", cwd=repo)
    assert proc.returncode == 0

    # 同值换到新路径
    write_file(repo / "config2.py", f'aws_key = "{_aws()}"\n')
    git(["add", "config2.py"], cwd=repo)
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 1, f"路径变化应 DENY, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["decision"] == "DENY"


def test_baseline_expired_denies(tmp_git_repo):
    repo = tmp_git_repo
    _write_real_creds(repo)

    # 写入带过期时间的 baseline
    proc = run_script("security-scan.py", "--staged", "--write-baseline",
                      "--reason", "accept", "--expires", "2000-01-01",
                      "--no-external", cwd=repo)
    assert proc.returncode == 0

    # 重新扫描：baseline 已过期 → DENY
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 1, f"过期 baseline 应 DENY, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["decision"] == "DENY"
    assert payload["code"] == "BASELINE_EXPIRED"


def test_baseline_corrupt_denies(tmp_git_repo):
    repo = tmp_git_repo
    _write_real_creds(repo)

    # 损坏 baseline 文件
    baseline_path = repo / ".safecode" / "baseline.json"
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text("{ this is not valid json ", encoding="utf-8")

    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 1, f"损坏 baseline 应 DENY, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["decision"] == "DENY"
    assert payload["code"] == "BASELINE_INVALID"


# --------------------------------------------------------------------------- #
# ignore_paths
# --------------------------------------------------------------------------- #

def test_ignore_paths_effective(tmp_git_repo):
    repo = tmp_git_repo
    _write_config(repo, (
        'schema_version: "1.0"\n'
        'security:\n'
        '  ignore_paths:\n'
        '    - config.py\n'
    ))
    _write_real_creds(repo)
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 0, f"ignore_paths 应忽略, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["decision"] == "ALLOW"


def test_ignore_paths_cannot_cover_git(tmp_git_repo):
    repo = tmp_git_repo
    _write_config(repo, (
        'schema_version: "1.0"\n'
        'security:\n'
        '  ignore_paths:\n'
        '    - .git\n'
    ))
    _write_real_creds(repo)
    # 配置非法 → 配置错误 exit 2 + DENY
    proc = run_script("security-scan.py", "--staged", "--json", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 2, f"非法 ignore_paths 应 exit 2, 实际 {proc.returncode}"
    assert payload["decision"] == "DENY"
    assert payload["code"] in ("CONFIG_INVALID", "CONFIG_SCHEMA_INVALID", "CONFIG_INVARIANT_VIOLATION")


# --------------------------------------------------------------------------- #
# 敏感文件
# --------------------------------------------------------------------------- #

def test_sensitive_file_tracked_high(tmp_git_repo):
    repo = tmp_git_repo
    write_file(repo / ".env", 'DB_PASSWORD=hello\n')
    git(["add", ".env"], cwd=repo)
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 1, f"敏感文件应阻断, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["decision"] == "DENY"
    sens = [f for f in payload["metadata"]["findings"] if f["rule"] == "sensitive-file"]
    assert sens, "应报告 sensitive-file finding"
    assert sens[0]["severity"] == "HIGH"


def test_sensitive_file_example_excluded(tmp_git_repo):
    repo = tmp_git_repo
    write_file(repo / ".env.example", 'DB_PASSWORD=hello\n')
    git(["add", ".env.example"], cwd=repo)
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 0, f".env.example 应排除, 实际 {proc.returncode}; out={proc.stdout}"


# --------------------------------------------------------------------------- #
# Shallow
# --------------------------------------------------------------------------- #

def _make_shallow(repo: Path) -> None:
    git_dir_out = git(["rev-parse", "--git-dir"], cwd=repo)
    gd = git_dir_out.stdout.strip()
    if not os.path.isabs(gd):
        gd = str(repo / gd)
    with open(os.path.join(gd, "shallow"), "w", encoding="utf-8") as fh:
        fh.write("")


def test_shallow_full_scan_fail_closed(tmp_git_repo):
    repo = tmp_git_repo
    _make_shallow(repo)
    proc = run_script("security-scan.py", "--all", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 3, f"shallow 完整扫描应 exit 3, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["decision"] == "DENY"
    assert payload["code"] == "SHALLOW_HISTORY"


def test_shallow_diff_scan_allowed_but_incomplete(tmp_git_repo):
    repo = tmp_git_repo
    _make_shallow(repo)
    write_file(repo / "clean.py", "x = 1\n")
    git(["add", "clean.py"], cwd=repo)
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 0
    assert payload["metadata"]["shallow"] is True
    assert payload["metadata"]["incomplete_history"] is True


# --------------------------------------------------------------------------- #
# History
# --------------------------------------------------------------------------- #

def test_history_scan_detects_committed_secret(tmp_git_repo):
    repo = tmp_git_repo
    write_file(repo / "leaked.py", f'aws_key = "{_aws()}"\n')
    git(["add", "leaked.py"], cwd=repo)
    git(["commit", "-m", "leak"], cwd=repo)
    proc = run_script("security-scan.py", "--history", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 1, f"history 应检出, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["decision"] == "DENY"
    assert any(f.get("commit_sha") for f in payload["metadata"]["findings"])


# --------------------------------------------------------------------------- #
# 外部 scanner PATH 桩
# --------------------------------------------------------------------------- #

def test_external_valid_findings_merged(tmp_git_repo, tmp_path):
    repo = tmp_git_repo
    bindir = _make_gitleaks_stub(tmp_path, "valid", "external_leak.txt")
    write_file(repo / "external_leak.txt", 'placeholder = "YOUR_API_KEY_HERE"\n')
    git(["add", "external_leak.txt"], cwd=repo)
    env = _ext_env(bindir)
    proc = run_script("security-scan.py", "--staged", "--json", cwd=repo, env=env)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 1, f"外部 scanner 发现应阻断, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["decision"] == "DENY"
    ext = [f for f in payload["metadata"]["findings"]
           if f.get("source") == "external" and f.get("scanner") == "gitleaks"]
    assert ext, "应合并外部 scanner finding"
    assert payload["metadata"]["scanners"]["gitleaks"]["available"] is True


def test_external_no_external_is_clean(tmp_git_repo, tmp_path):
    repo = tmp_git_repo
    bindir = _make_gitleaks_stub(tmp_path, "valid", "external_leak.txt")
    write_file(repo / "external_leak.txt", 'placeholder = "YOUR_API_KEY_HERE"\n')
    git(["add", "external_leak.txt"], cwd=repo)
    # 显式跳过外部 scanner
    proc = run_script("security-scan.py", "--staged", "--json", "--no-external", cwd=repo)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert proc.returncode == 0, f"--no-external 应干净, 实际 {proc.returncode}; out={proc.stdout}"


def test_external_error_not_passed_locally(tmp_git_repo, tmp_path):
    repo = tmp_git_repo
    bindir = _make_gitleaks_stub(tmp_path, "nonzero", "external_leak.txt")
    write_file(repo / "clean.py", "x = 1\n")
    git(["add", "clean.py"], cwd=repo)
    env = _ext_env(bindir)
    proc = run_script("security-scan.py", "--staged", "--json", cwd=repo, env=env)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    # 关键不变量：外部 scanner 出错绝不能声称 PASS
    assert payload["status"] != "PASS", f"外部报错时不得 PASS; 实际 {payload['status']}"
    assert payload["status"] == "DEGRADED"
    assert payload["decision"] == "ALLOW"
    assert payload["code"] == "EXTERNAL_SCANNER_ERROR"
    assert proc.returncode == 0


def test_external_garbage_not_passed_locally(tmp_git_repo, tmp_path):
    repo = tmp_git_repo
    bindir = _make_gitleaks_stub(tmp_path, "garbage", "external_leak.txt")
    write_file(repo / "clean.py", "x = 1\n")
    git(["add", "clean.py"], cwd=repo)
    env = _ext_env(bindir)
    proc = run_script("security-scan.py", "--staged", "--json", cwd=repo, env=env)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    assert payload["status"] != "PASS"
    assert payload["status"] == "DEGRADED"
    assert proc.returncode == 0


def test_external_error_strict_denies(tmp_git_repo, tmp_path):
    repo = tmp_git_repo
    bindir = _make_gitleaks_stub(tmp_path, "nonzero", "external_leak.txt")
    write_file(repo / "clean.py", "x = 1\n")
    git(["add", "clean.py"], cwd=repo)
    env = _ext_env(bindir)
    proc = run_script("security-scan.py", "--staged", "--json", "--strict", cwd=repo, env=env)
    payload = parse_json_output(proc)
    assert_result_schema(payload)
    # STRICT 下外部 scanner 异常 → DENY
    assert proc.returncode == 3, f"STRICT 外部异常应 exit 3, 实际 {proc.returncode}; out={proc.stdout}"
    assert payload["decision"] == "DENY"
    assert payload["status"] == "FAIL"
