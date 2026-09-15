"""SafeCode Agent 共享库。

提供所有脚本共用的：
- 错误等级常量 L0..L6 及其人类可读含义
- Secret 检测正则集合
- 占位符（误报）白名单与判定
- 高熵判断（Shannon 熵）
- 测试 / 示例文件判定
- 统一的 finding 数据结构与 JSON 报告输出助手

纯 Python 标准库，跨平台（Windows / Linux / macOS）。Python >= 3.10。
"""

from __future__ import annotations

import dataclasses
import json
import math
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# 错误等级（ErrorLevel）
# --------------------------------------------------------------------------- #

L0 = "L0"
L1 = "L1"
L2 = "L2"
L3 = "L3"
L4 = "L4"
L5 = "L5"
L6 = "L6"

ERROR_LEVELS = (L0, L1, L2, L3, L4, L5, L6)

ERROR_LEVEL_MEANING: Dict[str, str] = {
    L0: "正常，继续",
    L1: "普通测试失败，自动修复",
    L2: "编译 / 构建失败，自动定位并修复",
    L3: "环境 / 依赖异常，尝试恢复",
    L4: "工作区异常，停止并恢复 checkpoint",
    L5: "安全风险，立即停止",
    L6: "无法确定，停止并请求人工确认",
}

# 需要立即停止 / 请求确认，不允许 Agent 自行猜测后继续的等级
STOP_LEVELS = (L4, L5, L6)


def error_level_meaning(level: str) -> str:
    """返回某错误等级的含义描述。"""
    return ERROR_LEVEL_MEANING.get(level, f"未知等级 {level}")


# --------------------------------------------------------------------------- #
# 退出码约定
# --------------------------------------------------------------------------- #

EXIT_PASS = 0          # 通过
EXIT_GATE_REJECT = 1   # 有发现 / 门禁拒绝
EXIT_USAGE = 2         # 用法或内部错误
EXIT_RECOVERY_LIMIT = 10  # recovery.py 达到自救上限

# 严重级别（扫描用）
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_INFO = "info"
SEVERITY_ORDER = {SEVERITY_INFO: 0, SEVERITY_MEDIUM: 1, SEVERITY_HIGH: 2}


# --------------------------------------------------------------------------- #
# 占位符白名单（不算泄露）
# --------------------------------------------------------------------------- #

# 常见的占位符 / 示例值（大小写不敏感比较）
PLACEHOLDER_VALUES = {
    "",
    "your_api_key_here",
    "your-token-here",
    "your-key-here",
    "your_secret_here",
    "example-token",
    "example-key",
    "example-secret",
    "test-secret",
    "test-token",
    "changeme",
    "change-me",
    "dummy",
    "dummy-key",
    "xxx",
    "xxxx",
    "xxxxxx",
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

# 出现这些关键词且像占位符时直接忽略
PLACEHOLDER_HINTS = ("your", "example", "sample", "placeholder", "changeme", "replace", "dummy")


def is_placeholder_value(value: str) -> bool:
    """判断一个值是否为明显的占位符 / 示例值（不算泄露）。

    判定规则：
    - 为空
    - 长度 < 8（太短，不可能是真实高强度凭据）
    - 全部由同一种字符组成（如全 x / 全 0）
    - 全部由 x/0/*/?/- 组成
    - 命中白名单（大小写不敏感）
    - 包含 your/example/placeholder 等提示词且带 key/token/secret
    """
    if value is None:
        return True
    v = value.strip().strip('"\'`').strip()
    if v == "":
        return True
    if len(v) < 8:
        return True
    low = v.lower()
    if low in PLACEHOLDER_VALUES:
        return True
    # 全部相同字符
    if len(set(v)) == 1:
        return True
    # 全部为 x/0/*/?/-
    if all(ch in "x0*?-" for ch in v):
        return True
    # 带提示词的疑似占位
    if any(h in low for h in ("your", "example", "placeholder", "changeme", "replace", "dummy")):
        if any(k in low for k in ("key", "token", "secret", "pass", "pwd", "cookie", "session")):
            return True
    return False


# --------------------------------------------------------------------------- #
# 高熵判断（Shannon 熵）
# --------------------------------------------------------------------------- #

def shannon_entropy(s: str) -> float:
    """计算字符串的 Shannon 熵（比特 / 字符）。"""
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


def is_high_entropy(s: str, threshold: float = 3.5, min_len: int = 16) -> bool:
    """判断字符串是否高熵（大概率是随机生成的真实凭据）。"""
    if s is None:
        return False
    v = s.strip().strip('"\'`')
    if len(v) < min_len:
        return False
    return shannon_entropy(v) >= threshold


# --------------------------------------------------------------------------- #
# 测试 / 示例文件判定
# --------------------------------------------------------------------------- #

# 路径中出现这些目录片段（独立目录名）时视为测试 / 示例文件
_TEST_DIR_FRAGMENTS = (
    "test", "tests",
    "example", "examples",
    "sample", "samples",
    "doc", "docs",
    "mock", "mocks",
    "fixture", "fixtures",
)


def is_test_or_example_file(path: str) -> bool:
    """判断路径是否位于测试 / 示例 / 文档 / mock / fixtures 区域。

    规则：路径片段包含 test/tests/example/examples/sample/doc/docs/mock/fixtures，
    或文件名包含 conftest。
    """
    if not path:
        return False
    norm = path.replace(os.sep, "/").lower()
    base = os.path.basename(norm)
    if "conftest" in base:
        return True
    parts = [p for p in norm.split("/") if p]
    for frag in _TEST_DIR_FRAGMENTS:
        if frag in parts:
            return True
    return False


# --------------------------------------------------------------------------- #
# 敏感文件判定（按文件名 / 扩展名）
# --------------------------------------------------------------------------- #

SENSITIVE_FILE_EXTS = (".env", ".pem", ".key", ".p12", ".pfx")


def is_sensitive_file(path: str) -> bool:
    """判断文件本身是否为高敏感文件（.env / .pem / .key / .p12 等）。"""
    if not path:
        return False
    base = os.path.basename(path)
    lower = base.lower()
    if lower.startswith(".env"):
        return True
    _, ext = os.path.splitext(lower)
    return ext in SENSITIVE_FILE_EXTS


# --------------------------------------------------------------------------- #
# 统一的 finding 数据结构
# --------------------------------------------------------------------------- #

@dataclasses.dataclass
class Finding:
    severity: str          # high / medium / info
    rule: str              # 规则名
    file: str              # 文件路径
    line: int = 0          # 行号（0 表示未知 / 文件级）
    evidence: str = ""     # 命中证据（已截断）
    hint: str = ""         # 可选的人工确认提示

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "rule": self.rule,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "hint": self.hint,
        }


def truncate_evidence(text: str, limit: int = 80) -> str:
    """截断证据字符串，避免报告中泄露过多内容本身。"""
    if text is None:
        return ""
    text = text.replace("\r", "").replace("\n", " ")
    text = text.strip()
    if len(text) > limit:
        return text[:limit] + "..."
    return text


# --------------------------------------------------------------------------- #
# 输出助手
# --------------------------------------------------------------------------- #

def write_json_report(obj: Any) -> None:
    """以 JSON 形式输出结构化报告到 stdout。"""
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def colorize(text: str, color: str) -> str:
    """简单的 ANSI 颜色（非 TTY 时原样返回）。"""
    import sys
    if not sys.stdout.isatty():
        return text
    codes = {
        "red": "31", "green": "32", "yellow": "33", "blue": "34",
        "bold": "1", "reset": "0",
    }
    c = codes.get(color, "0")
    return f"\033[{c}m{text}\033[0m"


def severity_label(severity: str) -> str:
    """返回带颜色的严重级别标签。"""
    color = {
        SEVERITY_HIGH: "red",
        SEVERITY_MEDIUM: "yellow",
        SEVERITY_INFO: "blue",
    }.get(severity, "reset")
    return colorize(f"[{severity.upper()}]", color)


# --------------------------------------------------------------------------- #
# Secret 检测规则集合
# --------------------------------------------------------------------------- #
# 每条规则：
#   name         规则名
#   pattern      编译后的正则
#   severity     基础严重级别 high / medium
#   capture_idx  需要取作证据 / 做占位符 & 高熵判定的捕获组下标（0 = 整条匹配）
#   check_entropy 是否对捕获值做高熵校验（仅高熵才算命中）
#   check_placeholder 是否对捕获值做占位符校验（占位符则忽略）

SECRET_RULES: List[Dict[str, Any]] = [
    {
        "name": "aws-access-key-id",
        "pattern": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        "severity": SEVERITY_HIGH,
        "capture_idx": 1,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "aws-secret-access-key",
        "pattern": re.compile(r'(?i)aws_?secret_?access_?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        "severity": SEVERITY_HIGH,
        "capture_idx": 1,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "github-token",
        "pattern": re.compile(r'\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b'),
        "severity": SEVERITY_HIGH,
        "capture_idx": 1,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "jwt",
        "pattern": re.compile(r'\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
        "severity": SEVERITY_HIGH,
        "capture_idx": 0,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "pem-private-key-block",
        "pattern": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |[A-Z]+ )?PRIVATE KEY-----'),
        "severity": SEVERITY_HIGH,
        "capture_idx": 0,
        "check_entropy": False,
        "check_placeholder": False,
    },
    {
        "name": "db-connection-string",
        "pattern": re.compile(
            r'(?i)\b(mysql|postgres|postgresql|mongodb(?:\+srv)?)://[^\s:@/]+:[^\s:@/]+@[^\s/]+'
        ),
        "severity": SEVERITY_HIGH,
        "capture_idx": 0,
        "check_entropy": False,
        "check_placeholder": False,
    },
    {
        "name": "bilibili-sessdata",
        "pattern": re.compile(r'(?i)\bSESSDATA\s*[=:]\s*([A-Za-z0-9%_.-]{8,})'),
        "severity": SEVERITY_HIGH,
        "capture_idx": 1,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "bilibili-bili-jct",
        "pattern": re.compile(r'(?i)\bbili_jct\s*[=:]\s*([A-Za-z0-9]{16,})'),
        "severity": SEVERITY_HIGH,
        "capture_idx": 1,
        "check_entropy": False,
        "check_placeholder": True,
    },
    {
        "name": "generic-secret-assignment",
        "pattern": re.compile(
            r'(?i)(api[_-]?key|secret|password|passwd|pwd|token|cookie|session)'
            r'([_-]?(?:key|secret|token|value|id)?)?\s*[=:]\s*["\']([^"\']{6,})["\']'
        ),
        "severity": SEVERITY_MEDIUM,
        "capture_idx": 2,
        "check_entropy": True,
        "check_placeholder": True,
    },
]


def scan_text_for_secrets(text: str) -> List[Tuple[str, str, str]]:
    """对单行文本运行全部 Secret 规则。

    返回 [(rule_name, severity, captured_value_or_snippet), ...]。
    已自动过滤占位符（check_placeholder）与非高熵（check_entropy）的命中。
    """
    results: List[Tuple[str, str, str]] = []
    for rule in SECRET_RULES:
        m = rule["pattern"].search(text)
        if not m:
            continue
        idx = rule.get("capture_idx", 0)
        captured = m.group(idx) if idx <= (m.re.groups) else m.group(0)
        # 占位符过滤
        if rule.get("check_placeholder", False) and is_placeholder_value(captured):
            continue
        # 高熵过滤
        if rule.get("check_entropy", False) and not is_high_entropy(captured):
            continue
        results.append((rule["name"], rule["severity"], captured))
    return results


# --------------------------------------------------------------------------- #
# git 辅助
# --------------------------------------------------------------------------- #

def run_git(args: List[str], cwd: Optional[str] = None,
            stdin: Optional[str] = None) -> "subprocess.CompletedProcess":
    """运行 git 子命令，返回 CompletedProcess；失败时返回非零 returncode。"""
    import subprocess
    return subprocess.run(
        ["git"] + args,
        cwd=cwd,
        stdin=(subprocess.PIPE if stdin is not None else None),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def is_git_repo(cwd: Optional[str] = None) -> bool:
    """判断当前（或指定）目录是否在 git 工作树内。"""
    proc = run_git(["rev-parse", "--is-inside-work-tree"], cwd=cwd)
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def repo_root(cwd: Optional[str] = None) -> Optional[str]:
    """返回 git 仓库根目录；非 git 仓库返回 None。"""
    proc = run_git(["rev-parse", "--show-toplevel"], cwd=cwd)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None
