"""SafeCode Secret 检测基元：规则集、占位符过滤、指纹与 Baseline。

职责边界（重要）：

- 这里提供 **SafeCode Native Rules** —— 即 SafeCode 自己拥有的核心检测能力，
  以及指纹 / Baseline / ignore_paths / allow_list 这些协议级判定。
- 成熟 Secret Scanner（gitleaks / trufflehog / detect-secrets）的调用与输出解析
  在 safecode_scanners.py，不在这里重复实现。

关于严重级别与"测试文件降级"的取舍：

v1 实现把测试 / 示例文件里的疑似凭据降级为 info 并放过。v7 契约要求
"NEW finding -> DENY" 且例外必须显式、可审计，因此这里改为：

    占位符形态的值（YOUR_API_KEY_HERE 等）-> 不是 finding
    其余一切命中                          -> 真实 finding，默认 DENY
    需要例外的                              -> 必须写进 allow_list 或 baseline

即不再有"自动降级为不阻断"的中间态。is_test_or_example_file() 仅用于报告提示。

纯 Python 标准库。Python >= 3.10。
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import math
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Pattern, Sequence, Tuple

from safecode_common import (
    CATEGORY_SECURITY,
    Location,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    now_utc_iso,
    read_json_file,
)

SCHEMA_VERSION = "1.0"

CODE_SECRET_DETECTED = "SECRET_DETECTED"
CODE_BASELINE_INVALID = "BASELINE_INVALID"
CODE_BASELINE_EXPIRED = "BASELINE_EXPIRED"

# finding 类型（进入指纹计算，发生变化即视为 NEW finding）
FINDING_TYPE_SECRET = "secret"
FINDING_TYPE_SENSITIVE_FILE = "sensitive_file"

SOURCE_NATIVE = "native"
SOURCE_EXTERNAL = "external"


# --------------------------------------------------------------------------- #
# 占位符与熵
# --------------------------------------------------------------------------- #

PLACEHOLDER_VALUES = {
    "",
    "your_api_key_here",
    "your-token-here",
    "your-key-here",
    "your_secret_here",
    "your_token_here",
    "example-token",
    "example-key",
    "example-secret",
    "test-secret",
    "test-token",
    "test",
    "password",
    "changeme",
    "change-me",
    "dummy",
    "dummy-key",
    "xxx",
    "xxxx",
    "xxxxxx",
    "sk-test-example-xxxx",
    "sk-xxxx",
    "sk-xxxxxx",
    "sk-placeholder",
    "<your-key-here>",
    "<your-token-here>",
    "<your-secret-here>",
    "replace-me",
    "replace_with_real_key",
    "placeholder",
    "sample",
    "example",
    "todo",
    "fixme",
    "null",
    "none",
    "undefined",
    "na",
    "n/a",
}

_PLACEHOLDER_HINTS = ("your", "example", "sample", "placeholder", "changeme",
                      "change-me", "replace", "dummy", "todo", "fixme")
_CREDENTIAL_HINTS = ("key", "token", "secret", "pass", "pwd", "cookie", "session")


def is_placeholder_value(value: Optional[str]) -> bool:
    """判断是否为明显的占位符 / 示例值（不算泄露）。"""
    if value is None:
        return True
    v = value.strip().strip("\"'`").strip()
    if v == "":
        return True
    if len(v) < 8:
        return True
    low = v.lower()
    if low in PLACEHOLDER_VALUES:
        return True
    if len(set(v)) == 1:
        return True
    if all(ch in "x0*?-._" for ch in v):
        return True
    if any(h in low for h in _PLACEHOLDER_HINTS) and any(k in low for k in _CREDENTIAL_HINTS):
        return True
    if low in ("true", "false", "null", "none"):
        return True
    return False


def shannon_entropy(s: str) -> float:
    """Shannon 熵（比特 / 字符）。"""
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def is_high_entropy(s: Optional[str], threshold: float = 3.5, min_len: int = 16) -> bool:
    """判断字符串是否高熵（大概率是随机生成的真实凭据）。"""
    if s is None:
        return False
    v = s.strip().strip("\"'`")
    if len(v) < min_len:
        return False
    return shannon_entropy(v) >= threshold


# --------------------------------------------------------------------------- #
# 路径判定
# --------------------------------------------------------------------------- #

_TEST_DIR_FRAGMENTS = (
    "test", "tests", "example", "examples", "sample", "samples",
    "doc", "docs", "mock", "mocks", "fixture", "fixtures",
)

SENSITIVE_FILE_EXTS = (".env", ".pem", ".key", ".p12", ".pfx")


def normalize_path(path: str, root: Optional[str] = None) -> str:
    """归一化路径：统一 / 分隔符，尽量转为相对仓库根的路径。"""
    p = str(path).replace("\\", "/")
    if root:
        root_norm = str(root).replace("\\", "/").rstrip("/")
        if root_norm and p.lower().startswith(root_norm.lower() + "/"):
            p = p[len(root_norm) + 1:]
        elif os.path.isabs(p):
            try:
                p = os.path.relpath(p, root)
                p = p.replace("\\", "/")
            except ValueError:
                pass
    while p.startswith("./"):
        p = p[2:]
    return p


def is_test_or_example_file(path: str) -> bool:
    """路径是否位于测试 / 示例 / 文档 / mock / fixtures 区域（仅用于报告提示）。"""
    if not path:
        return False
    norm = normalize_path(path).lower()
    base = os.path.basename(norm)
    if "conftest" in base:
        return True
    parts = [p for p in norm.split("/") if p]
    return any(frag in parts for frag in _TEST_DIR_FRAGMENTS)


def is_sensitive_file(path: str) -> bool:
    """文件本身是否高敏感（.env / .pem / .key / .p12 等）。"""
    if not path:
        return False
    lower = os.path.basename(path).lower()
    if lower.startswith(".env"):
        return True
    _, ext = os.path.splitext(lower)
    return ext in SENSITIVE_FILE_EXTS


def is_ignored_path(path: str, ignore_paths: Sequence[str]) -> bool:
    """判断路径是否落在 ignore_paths 中（前缀匹配，已归一化）。"""
    norm = normalize_path(path).lower()
    for raw in ignore_paths or []:
        pattern = normalize_path(str(raw)).lower().rstrip("/")
        if not pattern:
            continue
        if norm == pattern or norm.startswith(pattern + "/"):
            return True
    return False


# --------------------------------------------------------------------------- #
# Native 规则集
# --------------------------------------------------------------------------- #
#   name              规则 id（进入指纹）
#   pattern           编译后的正则
#   severity          基础严重级别
#   capture_idx       取值做占位符 / 高熵判定的捕获组
#   check_entropy     是否要求高熵
#   check_placeholder 是否应用占位符过滤

NATIVE_SECRET_RULES: List[Dict[str, Any]] = [
    {
        "name": "aws-access-key-id",
        "pattern": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "severity": SEVERITY_CRITICAL,
        "capture_idx": 1,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "aws-secret-access-key",
        "pattern": re.compile(r"(?i)aws_?secret_?access_?key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"),
        "severity": SEVERITY_CRITICAL,
        "capture_idx": 1,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "github-token",
        "pattern": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"),
        "severity": SEVERITY_CRITICAL,
        "capture_idx": 1,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "jwt",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "severity": SEVERITY_HIGH,
        "capture_idx": 0,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "pem-private-key-block",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP |[A-Z]+ )?PRIVATE KEY-----"),
        "severity": SEVERITY_CRITICAL,
        "capture_idx": 0,
        "check_entropy": False,
        "check_placeholder": False,
    },
    {
        "name": "db-connection-string",
        "pattern": re.compile(
            r"(?i)\b(mysql|postgres|postgresql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@[^\s/]+"
        ),
        "severity": SEVERITY_HIGH,
        "capture_idx": 0,
        "check_entropy": False,
        "check_placeholder": False,
    },
    {
        "name": "bilibili-sessdata",
        "pattern": re.compile(r"(?i)\bSESSDATA\s*[=:]\s*[\"']?([A-Za-z0-9%_.-]{8,})"),
        "severity": SEVERITY_CRITICAL,
        "capture_idx": 1,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "bilibili-bili-jct",
        "pattern": re.compile(r"(?i)\bbili_jct\s*[=:]\s*[\"']?([A-Za-z0-9]{16,})"),
        "severity": SEVERITY_CRITICAL,
        "capture_idx": 1,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "slack-token",
        "pattern": re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        "severity": SEVERITY_HIGH,
        "capture_idx": 1,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "openai-style-key",
        "pattern": re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b"),
        "severity": SEVERITY_HIGH,
        "capture_idx": 1,
        "check_entropy": True,
        "check_placeholder": True,
    },
    {
        "name": "generic-secret-assignment",
        "pattern": re.compile(
            r"(?i)\b(api[_-]?key|secret|password|passwd|pwd|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|cookie|session[_-]?id)\b"
            r"\s*[=:]\s*[\"']([^\"'\s]{8,})[\"']"
        ),
        "severity": SEVERITY_MEDIUM,
        "capture_idx": 2,
        "check_entropy": True,
        "check_placeholder": True,
    },
]


def build_rules(custom_rules: Optional[Sequence[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """合并 Native 规则与项目自定义规则。自定义规则非法时抛 ValueError。"""
    rules: List[Dict[str, Any]] = list(NATIVE_SECRET_RULES)
    for raw in (custom_rules or []):
        rule_id = str(raw.get("id", "")).strip()
        pattern = raw.get("pattern")
        if not rule_id or not pattern:
            raise ValueError(f"invalid custom rule: {raw!r}")
        rules.append({
            "name": rule_id,
            "pattern": re.compile(pattern),
            "severity": raw.get("severity") or SEVERITY_HIGH,
            "capture_idx": int(raw.get("capture_idx", 0)),
            "check_entropy": bool(raw.get("check_entropy", False)),
            "check_placeholder": bool(raw.get("check_placeholder", True)),
            "custom": True,
        })
    return rules


# --------------------------------------------------------------------------- #
# Finding 与指纹
# --------------------------------------------------------------------------- #

def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def normalized_match_identity(matched_value: str) -> str:
    """把命中内容归一化为不含明文标识。

    绝不把完整 Secret 明文写入 Baseline —— 只存归一化后的哈希前缀。
    """
    norm = (matched_value or "").strip().strip("\"'`")
    return _sha256_hex(norm)[:16]


def compute_fingerprint(rule_id: str, path: str, finding_type: str,
                        match_identity: str) -> str:
    """fingerprint = sha256(rule_id + normalized_path + finding_type + normalized_match_identity)"""
    payload = "\n".join([
        rule_id or "",
        normalize_path(path),
        finding_type or "",
        match_identity or "",
    ])
    return "sha256:" + _sha256_hex(payload)


def truncate_evidence(text: str, limit: int = 80) -> str:
    """截断证据，避免报告里泄露过多内容本身。"""
    if text is None:
        return ""
    text = text.replace("\r", "").replace("\n", " ").strip()
    return text[:limit] + "..." if len(text) > limit else text


@dataclasses.dataclass
class Finding:
    """归一化后的安全 finding。"""

    rule: str
    path: str
    line: Optional[int] = None
    column: Optional[int] = None
    severity: str = SEVERITY_HIGH
    finding_type: str = FINDING_TYPE_SECRET
    evidence: str = ""
    matched_value: str = ""
    source: str = SOURCE_NATIVE
    scanner: str = ""
    message: str = ""

    @property
    def match_identity(self) -> str:
        return normalized_match_identity(self.matched_value or self.evidence)

    @property
    def fingerprint(self) -> str:
        return compute_fingerprint(self.rule, self.path, self.finding_type, self.match_identity)

    def location(self) -> Location:
        return Location(file=normalize_path(self.path), line=self.line, column=self.column)

    def to_dict(self, *, include_evidence: bool = True) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "rule": self.rule,
            "finding_type": self.finding_type,
            "path": normalize_path(self.path),
            "severity": self.severity,
            "source": self.source,
            "fingerprint": self.fingerprint,
        }
        if self.line is not None:
            out["line"] = int(self.line)
        if self.column is not None:
            out["column"] = int(self.column)
        if self.scanner:
            out["scanner"] = self.scanner
        if self.message:
            out["message"] = self.message
        if include_evidence and self.evidence:
            out["evidence"] = truncate_evidence(self.evidence)
        if is_test_or_example_file(self.path):
            out["in_test_or_example_path"] = True
        return out


def scan_line_for_secrets(line: str, rules: Sequence[Dict[str, Any]]) -> List[Tuple[str, str, str]]:
    """对单行文本运行全部规则，返回 [(rule, severity, captured), ...]。"""
    results: List[Tuple[str, str, str]] = []
    for rule in rules:
        pattern: Pattern[str] = rule["pattern"]
        for match in pattern.finditer(line):
            idx = rule.get("capture_idx", 0)
            groups = match.re.groups
            if idx and idx <= groups:
                captured = match.group(idx) or ""
            else:
                captured = match.group(0) or ""
            if rule.get("check_placeholder", False) and is_placeholder_value(captured):
                continue
            if rule.get("check_entropy", False) and not is_high_entropy(captured):
                continue
            results.append((rule["name"], rule["severity"], captured))
    return results


def scan_text_for_findings(text: str, path: str, rules: Sequence[Dict[str, Any]],
                           *, base_line: int = 1) -> List[Finding]:
    """扫描文本内容，返回 Finding 列表。base_line 用于 diff 场景的行号偏移。"""
    findings: List[Finding] = []
    for offset, line in enumerate(text.splitlines()):
        for rule_name, severity, captured in scan_line_for_secrets(line, rules):
            findings.append(Finding(
                rule=rule_name,
                path=path,
                line=base_line + offset,
                severity=severity,
                finding_type=FINDING_TYPE_SECRET,
                evidence=truncate_evidence(line.strip()),
                matched_value=captured,
            ))
    return findings


def sensitive_file_finding(path: str) -> Finding:
    """文件本身敏感（.env / .pem / .key 等）时的 finding。"""
    return Finding(
        rule="sensitive-file",
        path=path,
        line=None,
        severity=SEVERITY_HIGH,
        finding_type=FINDING_TYPE_SENSITIVE_FILE,
        evidence=os.path.basename(path),
        matched_value=os.path.basename(path),
        message="sensitive file type tracked by git",
    )


# --------------------------------------------------------------------------- #
# Baseline
# --------------------------------------------------------------------------- #

class BaselineError(Exception):
    """Baseline 文件不可用。调用方必须 DENY。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def default_baseline_path(root: Optional[str] = None) -> str:
    base = root or os.getcwd()
    return os.path.join(base, ".safecode", "baseline.json")


def _parse_date(value: str) -> Optional[datetime.date]:
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.datetime.strptime(value, fmt).date()
        except (ValueError, TypeError):
            continue
    return None


class Baseline:
    """已审计、明确接受的历史结果的集合。

    Baseline 不是关闭安全检查：只有指纹完全匹配、未过期、且带 reason 的条目才算已知。
    """

    def __init__(self, entries: Optional[Sequence[Dict[str, Any]]] = None,
                 path: Optional[str] = None) -> None:
        self.entries: List[Dict[str, Any]] = [dict(e) for e in (entries or [])]
        self.path = path
        self._by_fingerprint: Dict[str, Dict[str, Any]] = {}
        for entry in self.entries:
            fp = str(entry.get("fingerprint", "")).strip()
            if fp:
                self._by_fingerprint[fp] = entry

    @staticmethod
    def load(path: Optional[str] = None, *, root: Optional[str] = None) -> "Baseline":
        """加载 Baseline。文件不存在返回空 Baseline；文件损坏则抛 BaselineError。"""
        target = path or default_baseline_path(root)
        if not os.path.isfile(target):
            return Baseline([], target)
        try:
            data = read_json_file(target)
        except (OSError, ValueError) as exc:
            raise BaselineError(CODE_BASELINE_INVALID,
                                f"baseline unreadable: {target}: {exc}") from exc

        if not isinstance(data, dict):
            raise BaselineError(CODE_BASELINE_INVALID, "baseline must be a JSON object")
        if data.get("schema_version") != SCHEMA_VERSION:
            raise BaselineError(
                CODE_BASELINE_INVALID,
                f"baseline schema_version must be '{SCHEMA_VERSION}', got {data.get('schema_version')!r}",
            )
        entries = data.get("entries")
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise BaselineError(CODE_BASELINE_INVALID, "baseline.entries must be an array")

        for entry in entries:
            if not isinstance(entry, dict):
                raise BaselineError(CODE_BASELINE_INVALID, "baseline entries must be objects")
            fp = str(entry.get("fingerprint", "")).strip()
            if not fp.startswith("sha256:"):
                raise BaselineError(
                    CODE_BASELINE_INVALID,
                    f"baseline entry with invalid fingerprint: {fp!r}",
                )
            if not str(entry.get("reason", "")).strip():
                raise BaselineError(
                    CODE_BASELINE_INVALID,
                    f"baseline entry {fp} is missing a reason",
                )
        return Baseline(entries, target)

    def status_for(self, finding: Finding, *, today: Optional[datetime.date] = None) -> str:
        """返回 "known" / "expired" / "new"。"""
        entry = self._by_fingerprint.get(finding.fingerprint)
        if entry is None:
            return "new"
        expires = entry.get("expires")
        if expires:
            parsed = _parse_date(str(expires))
            if parsed is None:
                return "new"
            if parsed < (today or datetime.date.today()):
                return "expired"
        return "known"

    def entry_for(self, finding: Finding) -> Optional[Dict[str, Any]]:
        return self._by_fingerprint.get(finding.fingerprint)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "entries": [dict(e) for e in self.entries],
        }

    def save(self, path: Optional[str] = None) -> str:
        from safecode_common import write_json_file
        target = path or self.path or default_baseline_path()
        write_json_file(target, self.to_dict())
        self.path = target
        return target


def make_baseline_entry(finding: Finding, reason: str,
                        expires: Optional[str] = None) -> Dict[str, Any]:
    """从 finding 生成 Baseline 条目（不含 Secret 明文）。"""
    entry: Dict[str, Any] = {
        "fingerprint": finding.fingerprint,
        "rule": finding.rule,
        "path": normalize_path(finding.path),
        "finding_type": finding.finding_type,
        "reason": reason,
        "created_at": now_utc_iso(),
    }
    if expires:
        entry["expires"] = expires
    return entry


# --------------------------------------------------------------------------- #
# allow_list
# --------------------------------------------------------------------------- #

def allow_list_match(finding: Finding, entries: Sequence[Dict[str, Any]],
                     *, today: Optional[datetime.date] = None) -> Optional[Dict[str, Any]]:
    """判断 finding 是否命中 allow_list。返回命中的条目或 None。

    必须 rule + path 同时匹配；带 fingerprint 时还需指纹一致。
    """
    today = today or datetime.date.today()
    norm_path = normalize_path(finding.path)
    for entry in entries or []:
        rule = str(entry.get("rule", "")).strip()
        path = normalize_path(str(entry.get("path", ""))).strip()
        if rule != finding.rule or not path:
            continue
        if not (norm_path == path or norm_path.startswith(path.rstrip("/") + "/")):
            continue
        fp = entry.get("fingerprint")
        if fp and str(fp) != finding.fingerprint:
            continue
        expires = entry.get("expires")
        if expires:
            parsed = _parse_date(str(expires))
            if parsed is None or parsed < today:
                continue
        return entry
    return None
