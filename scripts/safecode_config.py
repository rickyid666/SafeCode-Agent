"""SafeCode 项目配置：.safecode.yml 的解析与校验。

设计要点：

- 零第三方依赖。内置一个最小 YAML 子集解析器，只支持 .safecode.yml 需要的语法
  （嵌套映射、标量列表、映射列表、注释、引号字符串、布尔/整数/空值、空的 [] 与 {}）。
  遇到不支持的语法（锚点 &、别名 *、块标量 | >、非空 flow 集合、多文档 ---）一律
  直接报错，绝不"猜一个值继续跑"。
- 配置本身也是输入，因此 Fail-Closed：
    解析失败 / Schema 非法 / 类型错误 / 试图关闭核心不变量
    一律 exit 2 + status=FAIL + decision=DENY。
- `ignore_paths` 与 `allow_list` 语义严格区分：
    ignore_paths：这些路径不进入某个明确声明的扫描范围，必须可审计，不得覆盖 .git 等核心对象。
    allow_list：某个具体规则的某个已知结果是已确认的例外，必须带 reason，不得使用 "*"。

纯 Python 标准库。Python >= 3.10。
"""

from __future__ import annotations

import copy
import datetime
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from safecode_common import find_upwards

CONFIG_FILENAME = ".safecode.yml"

# 结果代码
CODE_CONFIG_PARSE_ERROR = "CONFIG_PARSE_ERROR"
CODE_CONFIG_SCHEMA_INVALID = "CONFIG_SCHEMA_INVALID"
CODE_CONFIG_INVARIANT_VIOLATION = "CONFIG_INVARIANT_VIOLATION"

DEFAULT_CONFIG: Dict[str, Any] = {
    "schema_version": "1.0",
    "security": {
        "mode": "default",
        "native": {"enabled": True},
        "external_scanners": {
            "enabled": True,
            "required_in_ci": True,
            "timeout_seconds": 120,
            "tools": ["gitleaks", "trufflehog", "detect-secrets"],
        },
        "ignore_paths": [],
        "allow_list": [],
        "custom_rules": [],
    },
    "testing": {
        "flaky_detection": {"enabled": True, "reruns": 3},
        "targets": [],
    },
    "recovery": {
        "max_recovery_attempts": 3,
        "max_total_test_runs": 20,
        "max_total_recoveries": 10,
        "max_total_time": "30m",
    },
    "git": {
        "protected_branches": ["main", "master"],
        "require_pre_push_hook": True,
        "require_ci": True,
        "allow_force_push": False,
        "allow_history_rewrite": False,
    },
    "project": {
        "name": "",
        "bootstrap_mode": False,
        "self_hosting": False,
    },
}

# 核心不变量：这些开关被显式关闭时直接拒绝配置
_GIT_INVARIABLE_KEYS = ("allow_force_push", "allow_history_rewrite")


class ConfigError(Exception):
    """配置错误。code 对应该错误的稳定代码。"""

    def __init__(self, code: str, message: str, location: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.location = location


# --------------------------------------------------------------------------- #
# 最小 YAML 子集解析器
# --------------------------------------------------------------------------- #

_UNSUPPORTED_MARKERS = ("&", "*", "!", "|", ">", "%")


def _strip_comment(line: str) -> str:
    """去掉行尾注释，忽略引号内的 #。"""
    in_single = in_double = False
    out: List[str] = []
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1] in " \t":
                break
        out.append(ch)
    return "".join(out).rstrip()


def _scalar(text: str, lineno: int) -> Any:
    """解析标量。拒绝无法可靠解释的写法。"""
    raw = text.strip()
    if raw == "":
        return None
    if raw in ("[]",):
        return []
    if raw in ("{}",):
        return {}
    if raw[:1] in _UNSUPPORTED_MARKERS:
        raise ConfigError(
            CODE_CONFIG_PARSE_ERROR,
            f"unsupported YAML construct at line {lineno}: {raw[:20]!r}",
            f"line {lineno}",
        )
    if raw.startswith(("[", "{")):
        raise ConfigError(
            CODE_CONFIG_PARSE_ERROR,
            f"flow collections are not supported at line {lineno}: {raw[:20]!r}",
            f"line {lineno}",
        )
    if raw.startswith("'") and raw.endswith("'") and len(raw) >= 2:
        return raw[1:-1].replace("''", "'")
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        body = raw[1:-1]
        try:
            return bytes(body, "utf-8").decode("unicode_escape") if "\\" in body else body
        except Exception:
            return body
    low = raw.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~"):
        return None
    if re.fullmatch(r"-?[0-9]+", raw):
        return int(raw)
    if re.fullmatch(r"-?[0-9]+\.[0-9]+", raw):
        return float(raw)
    return raw


_KEY_RE = re.compile(r"^(?P<key>[A-Za-z0-9_.\-]+|'[^']*'|\"[^\"]*\")\s*:\s*(?P<rest>.*)$")


def _split_key(text: str) -> Optional[Tuple[str, str]]:
    """把 "key: value" 拆成 (key, rest)；不是键值行返回 None。"""
    m = _KEY_RE.match(text.strip())
    if not m:
        return None
    key = m.group("key")
    if key[:1] in ("'", '"'):
        key = key[1:-1]
    return key, m.group("rest")


def _tokenize(text: str) -> List[Tuple[int, str, int]]:
    """产出 (indent, text, lineno) 列表，跳过空行与注释。"""
    entries: List[Tuple[int, str, int]] = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        if "\t" in raw_line[: len(raw_line) - len(raw_line.lstrip())]:
            raise ConfigError(
                CODE_CONFIG_PARSE_ERROR,
                f"tab indentation is not supported (line {lineno})",
                f"line {lineno}",
            )
        line = _strip_comment(raw_line)
        if not line.strip():
            continue
        if line.strip() in ("---", "..."):
            raise ConfigError(
                CODE_CONFIG_PARSE_ERROR,
                f"multi-document YAML is not supported (line {lineno})",
                f"line {lineno}",
            )
        indent = len(line) - len(line.lstrip(" "))
        entries.append((indent, line.strip(), lineno))
    return entries


def _expand_list_items(entries: List[Tuple[int, str, int]]) -> List[Tuple[int, str, int]]:
    """把 "- xxx" 展开为 ("-", indent) + (indent+2, "xxx") 两条。"""
    expanded: List[Tuple[int, str, int]] = []
    for indent, text, lineno in entries:
        if text == "-" or text.startswith("- "):
            rest = text[1:].strip()
            expanded.append((indent, "-", lineno))
            if rest:
                expanded.append((indent + 2, rest, lineno))
        else:
            expanded.append((indent, text, lineno))
    return expanded


def _parse_block(entries: List[Tuple[int, str, int]], idx: int) -> Tuple[Any, int]:
    """递归解析一个块（映射或列表或标量），返回 (值, 下一个索引)。"""
    if idx >= len(entries):
        return None, idx
    indent, text, lineno = entries[idx]

    if text == "-":
        items: List[Any] = []
        while idx < len(entries):
            cur_indent, cur_text, _ = entries[idx]
            if cur_indent != indent or cur_text != "-":
                break
            idx += 1
            if idx < len(entries) and entries[idx][0] > indent:
                value, idx = _parse_block(entries, idx)
                items.append(value)
            else:
                items.append(None)
        return items, idx

    key_rest = _split_key(text)
    if key_rest is None:
        return _scalar(text, lineno), idx + 1

    result: Dict[str, Any] = {}
    while idx < len(entries):
        cur_indent, cur_text, cur_lineno = entries[idx]
        if cur_indent != indent or cur_text == "-":
            break
        k_rest = _split_key(cur_text)
        if k_rest is None:
            raise ConfigError(
                CODE_CONFIG_PARSE_ERROR,
                f"expected 'key: value' at line {cur_lineno}, got {cur_text[:30]!r}",
                f"line {cur_lineno}",
            )
        key, rest = k_rest
        idx += 1
        if rest.strip() == "":
            if idx < len(entries) and entries[idx][0] > indent:
                value, idx = _parse_block(entries, idx)
            else:
                value = None
        else:
            value = _scalar(rest, cur_lineno)
        result[key] = value
    return result, idx


def parse_yaml_subset(text: str, source: str = "<config>") -> Dict[str, Any]:
    """解析受限 YAML 子集。失败抛 ConfigError（Fail-Closed）。"""
    entries = _expand_list_items(_tokenize(text))
    if not entries:
        return {}
    value, idx = _parse_block(entries, 0)
    if idx != len(entries):
        indent, leftover, lineno = entries[idx]
        raise ConfigError(
            CODE_CONFIG_PARSE_ERROR,
            f"unexpected content at line {lineno}: {leftover[:30]!r} (bad indentation?)",
            f"line {lineno}",
        )
    if not isinstance(value, dict):
        raise ConfigError(
            CODE_CONFIG_PARSE_ERROR,
            f"top level of {source} must be a mapping",
            source,
        )
    return value


# --------------------------------------------------------------------------- #
# 校验
# --------------------------------------------------------------------------- #

def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_duration(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return re.fullmatch(r"[0-9]+(s|m|h)", value.strip()) is not None


def _check_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            datetime.datetime.strptime(value, fmt)
            return True
        except ValueError:
            continue
    return False


def validate_config(data: Dict[str, Any]) -> List[str]:
    """校验配置。返回错误消息列表（空表示合法）。"""
    errors: List[str] = []

    if not isinstance(data, dict):
        return ["config must be a mapping"]

    version = data.get("schema_version")
    if version is None:
        errors.append("missing required field: schema_version")
    elif version != "1.0":
        errors.append(f"unsupported schema_version: {version!r} (expected '1.0')")

    security = data.get("security")
    if security is not None:
        if not isinstance(security, dict):
            errors.append("security must be a mapping")
        else:
            mode = security.get("mode")
            if mode is not None and mode not in ("default", "strict"):
                errors.append(f"security.mode must be 'default' or 'strict', got {mode!r}")

            native = security.get("native")
            if native is not None:
                if not isinstance(native, dict):
                    errors.append("security.native must be a mapping")
                elif native.get("enabled") is False:
                    errors.append(
                        "security.native.enabled=false is not allowed: "
                        "native security gate is a core invariant and cannot be disabled"
                    )

            ext = security.get("external_scanners")
            if ext is not None:
                if not isinstance(ext, dict):
                    errors.append("security.external_scanners must be a mapping")
                else:
                    tools = ext.get("tools")
                    if tools is not None:
                        if not isinstance(tools, list):
                            errors.append("security.external_scanners.tools must be a list")
                        else:
                            for tool in tools:
                                if tool not in ("gitleaks", "trufflehog", "detect-secrets"):
                                    errors.append(f"unsupported external scanner: {tool!r}")
                    timeout = ext.get("timeout_seconds")
                    if timeout is not None and (not _is_int(timeout) or timeout < 1):
                        errors.append("security.external_scanners.timeout_seconds must be a positive integer")

            ignores = security.get("ignore_paths")
            if ignores is not None:
                if not isinstance(ignores, list):
                    errors.append("security.ignore_paths must be a list")
                else:
                    for item in ignores:
                        if not isinstance(item, str) or not item.strip():
                            errors.append(f"security.ignore_paths entries must be non-empty strings, got {item!r}")
                            continue
                        norm = item.replace("\\", "/").strip()
                        if norm.startswith("/"):
                            errors.append(f"security.ignore_paths must be relative: {item!r}")
                        if norm in ("", ".", "./", "*"):
                            errors.append(f"security.ignore_paths cannot cover the whole repository: {item!r}")
                        if ".git" in norm.split("/") or norm.startswith(".git"):
                            errors.append(f"security.ignore_paths cannot ignore .git: {item!r}")

            allow_list = security.get("allow_list")
            if allow_list is not None:
                if not isinstance(allow_list, list):
                    errors.append("security.allow_list must be a list")
                else:
                    for entry in allow_list:
                        if not isinstance(entry, dict):
                            errors.append(f"security.allow_list entries must be mappings, got {entry!r}")
                            continue
                        rule = entry.get("rule")
                        path = entry.get("path")
                        reason = entry.get("reason")
                        if not isinstance(rule, str) or not rule.strip():
                            errors.append("allow_list entry requires a non-empty 'rule'")
                        elif rule.strip() == "*":
                            errors.append("allow_list rule '*' is not allowed: it would disable the scanner globally")
                        if not isinstance(path, str) or not path.strip():
                            errors.append("allow_list entry requires a non-empty 'path'")
                        elif path.strip() == "*":
                            errors.append("allow_list path '*' is not allowed: it would disable the scanner globally")
                        if not isinstance(reason, str) or len(reason.strip()) < 4:
                            errors.append("allow_list entry requires a meaningful 'reason'")
                        expires = entry.get("expires")
                        if expires is not None and not _check_date(expires):
                            errors.append(f"allow_list expires must be YYYY-MM-DD or ISO8601 UTC, got {expires!r}")

            custom_rules = security.get("custom_rules")
            if custom_rules is not None:
                if not isinstance(custom_rules, list):
                    errors.append("security.custom_rules must be a list")
                else:
                    for rule in custom_rules:
                        if not isinstance(rule, dict):
                            errors.append("security.custom_rules entries must be mappings")
                            continue
                        if not isinstance(rule.get("id"), str) or not rule["id"].strip():
                            errors.append("custom_rules entry requires a non-empty 'id'")
                        pattern = rule.get("pattern")
                        if not isinstance(pattern, str) or not pattern:
                            errors.append("custom_rules entry requires a non-empty 'pattern'")
                        else:
                            try:
                                re.compile(pattern)
                            except re.error as exc:
                                errors.append(f"custom_rules pattern invalid: {exc}")
                        severity = rule.get("severity")
                        if severity is not None and severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                            errors.append(f"custom_rules severity must be LOW/MEDIUM/HIGH/CRITICAL, got {severity!r}")

    testing = data.get("testing")
    if testing is not None:
        if not isinstance(testing, dict):
            errors.append("testing must be a mapping")
        else:
            flaky = testing.get("flaky_detection")
            if flaky is not None:
                if not isinstance(flaky, dict):
                    errors.append("testing.flaky_detection must be a mapping")
                else:
                    reruns = flaky.get("reruns")
                    if reruns is not None and (not _is_int(reruns) or not (0 <= reruns <= 10)):
                        errors.append("testing.flaky_detection.reruns must be an integer between 0 and 10")
            targets = testing.get("targets")
            if targets is not None and not isinstance(targets, list):
                errors.append("testing.targets must be a list")

    recovery = data.get("recovery")
    if recovery is not None:
        if not isinstance(recovery, dict):
            errors.append("recovery must be a mapping")
        else:
            for key in ("max_recovery_attempts", "max_total_test_runs", "max_total_recoveries"):
                value = recovery.get(key)
                if value is not None and (not _is_int(value) or value < 1):
                    errors.append(f"recovery.{key} must be a positive integer")
            duration = recovery.get("max_total_time")
            if duration is not None and not _check_duration(duration):
                errors.append(f"recovery.max_total_time must look like 30m / 90s / 2h, got {duration!r}")

    git = data.get("git")
    if git is not None:
        if not isinstance(git, dict):
            errors.append("git must be a mapping")
        else:
            branches = git.get("protected_branches")
            if branches is not None:
                if not isinstance(branches, list) or not branches:
                    errors.append("git.protected_branches must be a non-empty list")
                else:
                    for branch in branches:
                        if not isinstance(branch, str) or not branch.strip():
                            errors.append(f"git.protected_branches entries must be non-empty strings, got {branch!r}")
            for key in _GIT_INVARIABLE_KEYS:
                if git.get(key) is True:
                    errors.append(
                        f"git.{key}=true is not allowed: risky git operations require human approval "
                        "and cannot be enabled by project config"
                    )

    project = data.get("project")
    if project is not None and not isinstance(project, dict):
        errors.append("project must be a mapping")

    return errors


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


# --------------------------------------------------------------------------- #
# Config 对象
# --------------------------------------------------------------------------- #

class Config:
    """合并了默认值的项目配置。"""

    def __init__(self, data: Optional[Dict[str, Any]] = None, path: Optional[str] = None,
                 *, loaded: bool = False) -> None:
        self.raw: Dict[str, Any] = _deep_merge(DEFAULT_CONFIG, data or {})
        self.path: Optional[str] = path
        self.loaded = loaded

    # ---- 通用访问 ---- #
    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.raw
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def section(self, name: str) -> Dict[str, Any]:
        value = self.get(name, {})
        return value if isinstance(value, dict) else {}

    # ---- 便捷属性 ---- #
    @property
    def security(self) -> Dict[str, Any]:
        return self.section("security")

    @property
    def testing(self) -> Dict[str, Any]:
        return self.section("testing")

    @property
    def recovery(self) -> Dict[str, Any]:
        return self.section("recovery")

    @property
    def git(self) -> Dict[str, Any]:
        return self.section("git")

    @property
    def project(self) -> Dict[str, Any]:
        return self.section("project")

    @property
    def ignore_paths(self) -> List[str]:
        value = self.security.get("ignore_paths") or []
        return [str(v).replace("\\", "/") for v in value]

    @property
    def allow_list(self) -> List[Dict[str, Any]]:
        value = self.security.get("allow_list") or []
        return [v for v in value if isinstance(v, dict)]

    @property
    def custom_rules(self) -> List[Dict[str, Any]]:
        value = self.security.get("custom_rules") or []
        return [v for v in value if isinstance(v, dict)]

    @property
    def external_scanners_enabled(self) -> bool:
        return bool(self.get("security.external_scanners.enabled", True))

    @property
    def external_scanner_tools(self) -> List[str]:
        value = self.get("security.external_scanners.tools") or []
        return [str(v) for v in value]

    @property
    def external_scanner_timeout(self) -> int:
        value = self.get("security.external_scanners.timeout_seconds", 120)
        return int(value) if _is_int(value) and value > 0 else 120

    @property
    def external_scanners_required_in_ci(self) -> bool:
        return bool(self.get("security.external_scanners.required_in_ci", True))

    @property
    def protected_branches(self) -> List[str]:
        value = self.git.get("protected_branches") or []
        return [str(v) for v in value]

    @property
    def budget_limits(self) -> Dict[str, Any]:
        recovery = self.recovery
        return {
            "max_recovery_attempts": int(recovery.get("max_recovery_attempts", 3)),
            "max_total_test_runs": int(recovery.get("max_total_test_runs", 20)),
            "max_total_recoveries": int(recovery.get("max_total_recoveries", 10)),
            "max_total_time": str(recovery.get("max_total_time", "30m")),
        }

    def is_protected_branch(self, branch: str) -> bool:
        return branch in self.protected_branches

    def to_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self.raw)


def load_config(path: Optional[str] = None, cwd: Optional[str] = None,
                *, required: bool = False) -> Config:
    """加载并校验 .safecode.yml。

    - path 显式给出但不存在 -> ConfigError
    - 自动查找（向上遍历）找不到：required=True 时 ConfigError，否则返回默认配置
    - 任何解析 / 校验失败 -> ConfigError，调用方必须 exit 2 + DENY
    """
    target = path
    if target is None:
        target = find_upwards(CONFIG_FILENAME, cwd)
        if target is None:
            if required:
                raise ConfigError(
                    CODE_CONFIG_SCHEMA_INVALID,
                    f"{CONFIG_FILENAME} not found and is required",
                )
            return Config({}, None, loaded=False)

    if not os.path.isfile(target):
        raise ConfigError(
            CODE_CONFIG_SCHEMA_INVALID,
            f"config file not found: {target}",
            target,
        )

    try:
        with open(target, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise ConfigError(CODE_CONFIG_PARSE_ERROR, f"cannot read config: {exc}", target) from exc

    data = parse_yaml_subset(text, source=target)
    errors = validate_config(data)
    if errors:
        raise ConfigError(
            CODE_CONFIG_SCHEMA_INVALID,
            "invalid .safecode.yml: " + "; ".join(errors),
            target,
        )
    return Config(data, target, loaded=True)
