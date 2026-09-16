"""SafeCode Agent 核心协议库。

这一层只负责"协议"本身，不含任何具体检查逻辑：

- Structured JSON Result（schema_version 1.0）与状态 / 决策枚举
- 统一 Exit Code 契约
- Policy Mode（LOCAL / STRICT）判定
- Decision Resolver：JSON + Exit Code + Policy Mode 合并为 Effective Decision
- Result 的结构化校验（与 schemas/result-1.0.json 一致，纯标准库实现）
- 输出约定：stdout 只放机器可解析 JSON，人类日志一律写 stderr
- 错误等级 L0..L6 与其策略动作映射
- git 只读辅助

任何脚本都不允许自己解释"是否放行"——一律调用 resolve_decision()。
纯 Python 标准库，跨平台。Python >= 3.10。
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# 协议版本
# --------------------------------------------------------------------------- #

SCHEMA_VERSION = "1.0"

# --------------------------------------------------------------------------- #
# status / decision / severity / category
# --------------------------------------------------------------------------- #

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_DEGRADED = "DEGRADED"
STATUSES = (STATUS_PASS, STATUS_FAIL, STATUS_DEGRADED)

DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"
DECISION_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
DECISIONS = (DECISION_ALLOW, DECISION_REQUIRE_APPROVAL, DECISION_DENY)

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"
SEVERITIES = (SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL)

CATEGORY_SECURITY = "SECURITY"
CATEGORY_GIT = "GIT"
CATEGORY_TEST = "TEST"
CATEGORY_DEPENDENCY = "DEPENDENCY"
CATEGORY_RECOVERY = "RECOVERY"
CATEGORY_CONFIG = "CONFIG"
CATEGORY_SYSTEM = "SYSTEM"

# 严格度阶梯，用于 Decision Resolver 取更严格结果
DECISION_STRICTNESS: Dict[str, int] = {
    DECISION_ALLOW: 0,
    DECISION_REQUIRE_APPROVAL: 1,
    DECISION_DENY: 2,
}

# --------------------------------------------------------------------------- #
# 统一 Exit Code 契约
# --------------------------------------------------------------------------- #

EXIT_OK = 0        # 程序执行成功；是否允许继续由 JSON decision + Policy Mode 决定
EXIT_FINDING = 1   # 检查明确发现安全 / 策略问题（含 REQUIRE_APPROVAL 的阻断通道）
EXIT_USAGE = 2     # 参数或配置错误
EXIT_TOOL = 3      # 工具 / Scanner 执行失败
EXIT_ENV = 4       # 环境异常

EXIT_CODES = (EXIT_OK, EXIT_FINDING, EXIT_USAGE, EXIT_TOOL, EXIT_ENV)

# --------------------------------------------------------------------------- #
# Policy Mode
# --------------------------------------------------------------------------- #

MODE_LOCAL = "LOCAL"
MODE_STRICT = "STRICT"

# 这些环境变量存在时视为 CI 环境（STRICT 等价）
CI_ENV_VARS = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "TF_BUILD",
    "JENKINS_URL",
    "CIRCLECI",
)


def _env_truthy(name: str) -> bool:
    raw = os.environ.get(name, "")
    return raw.strip().lower() not in ("", "0", "false", "no", "off")


def is_ci_environment() -> bool:
    """判断当前是否运行在 CI / 无人值守环境中。"""
    return any(_env_truthy(v) for v in CI_ENV_VARS)


def resolve_mode(strict_flag: bool = False, config: Any = None) -> str:
    """解析当前 Policy Mode。

    STRICT 的触发条件（任一满足）：
    - 命令行 --strict
    - 环境变量 SAFECODE_STRICT=1
    - CI 环境变量（CI / GITHUB_ACTIONS / ...）
    - .safecode.yml 中 security.mode == "strict"
    """
    if strict_flag or _env_truthy("SAFECODE_STRICT"):
        return MODE_STRICT
    if is_ci_environment():
        return MODE_STRICT
    try:
        if config is not None and config.get("security.mode") == "strict":
            return MODE_STRICT
    except Exception:  # pragma: no cover - 配置对象异常不影响模式判定
        pass
    return MODE_LOCAL


# --------------------------------------------------------------------------- #
# Result 数据结构
# --------------------------------------------------------------------------- #

@dataclasses.dataclass
class Location:
    """问题位置。file 必填，line / column 可选。"""

    file: str
    line: Optional[int] = None
    column: Optional[int] = None
    extra: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"file": self.file}
        if self.line is not None:
            out["line"] = int(self.line)
        if self.column is not None:
            out["column"] = int(self.column)
        out.update(self.extra)
        return out

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Location":
        known = {"file", "line", "column"}
        return Location(
            file=str(d.get("file", "")),
            line=d.get("line"),
            column=d.get("column"),
            extra={k: v for k, v in d.items() if k not in known},
        )


@dataclasses.dataclass
class Result:
    """统一 Structured JSON Result。"""

    status: str
    decision: str
    severity: str
    category: str
    code: str
    message: str
    locations: List[Location] = dataclasses.field(default_factory=list)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "decision": self.decision,
            "severity": self.severity,
            "category": self.category,
            "code": self.code,
            "message": self.message,
            "locations": [loc.to_dict() for loc in self.locations],
            "metadata": dict(self.metadata or {}),
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Result":
        locations = [
            Location.from_dict(item) if isinstance(item, dict) else Location(file=str(item))
            for item in (d.get("locations") or [])
        ]
        return Result(
            status=d.get("status", ""),
            decision=d.get("decision", ""),
            severity=d.get("severity", ""),
            category=d.get("category", ""),
            code=d.get("code", ""),
            message=d.get("message", ""),
            locations=locations,
            metadata=d.get("metadata") or {},
            schema_version=d.get("schema_version", ""),
        )


def make_result(
    status: str,
    decision: str,
    code: str,
    message: str,
    *,
    severity: str = SEVERITY_LOW,
    category: str = CATEGORY_SYSTEM,
    locations: Optional[Sequence[Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Result:
    """构造 Result 的快捷函数。locations 可传 Location 或 dict。"""
    locs: List[Location] = []
    for item in (locations or []):
        if isinstance(item, Location):
            locs.append(item)
        elif isinstance(item, dict):
            locs.append(Location.from_dict(item))
        else:
            locs.append(Location(file=str(item)))
    return Result(
        status=status,
        decision=decision,
        severity=severity,
        category=category,
        code=code,
        message=message,
        locations=locs,
        metadata=dict(metadata or {}),
    )


def pass_result(code: str = "CHECK_PASSED", message: str = "Check completed successfully",
                *, severity: str = SEVERITY_LOW, category: str = CATEGORY_SYSTEM,
                locations: Optional[Sequence[Any]] = None,
                metadata: Optional[Dict[str, Any]] = None) -> Result:
    """PASS + ALLOW。"""
    return make_result(STATUS_PASS, DECISION_ALLOW, code, message,
                       severity=severity, category=category,
                       locations=locations, metadata=metadata)


def fail_deny_result(code: str, message: str, *, severity: str = SEVERITY_HIGH,
                     category: str = CATEGORY_SECURITY,
                     locations: Optional[Sequence[Any]] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> Result:
    """FAIL + DENY（检查明确发现问题）。"""
    return make_result(STATUS_FAIL, DECISION_DENY, code, message,
                       severity=severity, category=category,
                       locations=locations, metadata=metadata)


def degraded_result(code: str, message: str, *, severity: str = SEVERITY_MEDIUM,
                    category: str = CATEGORY_SECURITY,
                    metadata: Optional[Dict[str, Any]] = None) -> Result:
    """DEGRADED + ALLOW（本地非严格模式）；在 STRICT / CI 下由 Resolver 升级为 DENY。"""
    return make_result(STATUS_DEGRADED, DECISION_ALLOW, code, message,
                       severity=severity, category=category, metadata=metadata)


def approval_result(code: str, message: str, *, severity: str = SEVERITY_HIGH,
                    category: str = CATEGORY_GIT,
                    locations: Optional[Sequence[Any]] = None,
                    metadata: Optional[Dict[str, Any]] = None) -> Result:
    """PASS + REQUIRE_APPROVAL（检查完成，但策略要求人工授权）。"""
    return make_result(STATUS_PASS, DECISION_REQUIRE_APPROVAL, code, message,
                       severity=severity, category=category,
                       locations=locations, metadata=metadata)


def usage_error_result(code: str, message: str) -> Result:
    return make_result(STATUS_FAIL, DECISION_DENY, code, message,
                       severity=SEVERITY_MEDIUM, category=CATEGORY_CONFIG)


def tool_error_result(code: str, message: str, *,
                      category: str = CATEGORY_SECURITY) -> Result:
    return make_result(STATUS_FAIL, DECISION_DENY, code, message,
                       severity=SEVERITY_MEDIUM, category=category)


def env_error_result(code: str, message: str) -> Result:
    return make_result(STATUS_FAIL, DECISION_DENY, code, message,
                       severity=SEVERITY_MEDIUM, category=CATEGORY_SYSTEM)


# --------------------------------------------------------------------------- #
# Result 结构化校验（与 schemas/result-1.0.json 等价，纯标准库）
# --------------------------------------------------------------------------- #

_CODE_RE = re.compile(r"^[A-Z0-9_]+$")


def validate_result_dict(d: Any) -> Tuple[bool, List[str]]:
    """按 result-1.0 Schema 校验一个 dict。返回 (是否有效, 错误列表)。

    无法识别的 Schema / 不合法结构一律判为无效，调用方必须 DENY。
    """
    errors: List[str] = []
    if not isinstance(d, dict):
        return False, ["result must be a JSON object"]

    required = ("schema_version", "status", "decision", "severity",
                "category", "code", "message", "locations", "metadata")
    for key in required:
        if key not in d:
            errors.append(f"missing required field: {key}")

    if d.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"unsupported schema_version: {d.get('schema_version')!r}")
    if d.get("status") not in STATUSES:
        errors.append(f"invalid status: {d.get('status')!r}")
    if d.get("decision") not in DECISIONS:
        errors.append(f"invalid decision: {d.get('decision')!r}")
    if d.get("severity") not in SEVERITIES:
        errors.append(f"invalid severity: {d.get('severity')!r}")

    category = d.get("category")
    if not isinstance(category, str) or not category:
        errors.append("category must be a non-empty string")

    code = d.get("code")
    if not isinstance(code, str) or not _CODE_RE.match(code or ""):
        errors.append(f"code must match ^[A-Z0-9_]+$: {code!r}")

    if not isinstance(d.get("message"), str):
        errors.append("message must be a string")

    locations = d.get("locations")
    if not isinstance(locations, list):
        errors.append("locations must be an array")
    else:
        for i, loc in enumerate(locations):
            if not isinstance(loc, dict):
                errors.append(f"locations[{i}] must be an object")
                continue
            if not isinstance(loc.get("file"), str):
                errors.append(f"locations[{i}].file must be a string")
            for num_key in ("line", "column"):
                if num_key in loc and loc[num_key] is not None:
                    val = loc[num_key]
                    if not isinstance(val, int) or isinstance(val, bool) or val < 1:
                        errors.append(f"locations[{i}].{num_key} must be an integer >= 1")

    if not isinstance(d.get("metadata"), dict):
        errors.append("metadata must be an object")

    return (not errors), errors


def validate_result(result: Result | Dict[str, Any]) -> Tuple[bool, List[str]]:
    """校验 Result 对象或 dict。"""
    if isinstance(result, Result):
        return validate_result_dict(result.to_dict())
    return validate_result_dict(result)


# --------------------------------------------------------------------------- #
# Decision Resolver
# --------------------------------------------------------------------------- #

@dataclasses.dataclass
class Resolution:
    """Decision Resolver 的输出。"""

    effective_decision: str
    effective_status: str
    mode: str
    reasons: List[str] = dataclasses.field(default_factory=list)
    blocking: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "effective_decision": self.effective_decision,
            "effective_status": self.effective_status,
            "mode": self.mode,
            "blocking": self.blocking,
            "reasons": list(self.reasons),
        }


def stricter(a: str, b: str) -> str:
    """返回两个 decision 中更严格的一个。"""
    return a if DECISION_STRICTNESS.get(a, 2) >= DECISION_STRICTNESS.get(b, 2) else b


def declared_approval(status: Optional[str], decision: Optional[str]) -> bool:
    """检查结果是否为"程序正常完成、策略要求人工授权"。

    契约要求 Exit != 0 必须至少 DENY；但 REQUIRE_APPROVAL 是"可被人工解除的阻断"，
    若直接降级为 DENY 会丢失授权语义，使 Approval Token 机制失效。
    因此这里对 (status=PASS, decision=REQUIRE_APPROVAL) 做显式保留：仍然是阻断，
    但保留可授权路径。该实现细节记录在 rules/git.md 与 README 的"契约取舍"一节。
    """
    return status == STATUS_PASS and decision == DECISION_REQUIRE_APPROVAL


def resolve_decision(
    result: Optional[Result | Dict[str, Any]],
    exit_code: int,
    mode: str,
    *,
    schema_valid: Optional[bool] = None,
) -> Resolution:
    """把 JSON Result + Exit Code + Policy Mode 合并为 Effective Decision。

    取更严格结果：ALLOW < REQUIRE_APPROVAL < DENY，并额外满足：
    - FAIL -> DENY
    - Exit != 0 -> 至少 DENY（唯一例外：status=PASS 且 decision=REQUIRE_APPROVAL，
      保留为 REQUIRE_APPROVAL 以支持人工授权路径）
    - Schema 无效 / 结果缺失 -> DENY
    - DEGRADED + ALLOW 在 STRICT / CI 下 -> DENY
    """
    reasons: List[str] = []
    parsed: Optional[Result] = None

    if isinstance(result, Result):
        parsed = result
    elif isinstance(result, dict):
        parsed = Result.from_dict(result)
    else:
        parsed = None

    if parsed is None or not parsed.status:
        return Resolution(
            effective_decision=DECISION_DENY,
            effective_status=STATUS_FAIL,
            mode=mode,
            reasons=["no structured result available: cannot verify -> DENY"],
            blocking=True,
        )

    if schema_valid is None:
        schema_valid, schema_errors = validate_result(parsed)
    else:
        schema_errors = []
    if not schema_valid:
        return Resolution(
            effective_decision=DECISION_DENY,
            effective_status=STATUS_FAIL,
            mode=mode,
            reasons=["result schema invalid -> DENY"] + list(schema_errors),
            blocking=True,
        )

    decision = parsed.decision
    status = parsed.status

    if status == STATUS_FAIL:
        if decision != DECISION_DENY:
            reasons.append("status=FAIL but decision!=DENY; FAIL forces DENY")
        decision = DECISION_DENY

    if status == STATUS_DEGRADED and decision == DECISION_ALLOW:
        if mode == MODE_STRICT:
            reasons.append("status=DEGRADED + ALLOW in STRICT/CI -> DENY")
            decision = DECISION_DENY
        else:
            reasons.append("status=DEGRADED + ALLOW in LOCAL mode -> kept, but DEGRADED != PASS")

    if exit_code != EXIT_OK:
        if declared_approval(status, decision):
            reasons.append(f"exit={exit_code} with REQUIRE_APPROVAL -> blocking, approval path kept")
            decision = stricter(decision, DECISION_REQUIRE_APPROVAL)
        else:
            reasons.append(f"exit={exit_code} != 0 -> at least DENY")
            decision = DECISION_DENY

    blocking = decision != DECISION_ALLOW
    if not reasons:
        reasons.append("json and exit code agree")

    return Resolution(
        effective_decision=decision,
        effective_status=status,
        mode=mode,
        reasons=reasons,
        blocking=blocking,
    )


# --------------------------------------------------------------------------- #
# 错误等级 L0..L6 与策略动作
# --------------------------------------------------------------------------- #

L0, L1, L2, L3, L4, L5, L6 = "L0", "L1", "L2", "L3", "L4", "L5", "L6"
ERROR_LEVELS = (L0, L1, L2, L3, L4, L5, L6)

ERROR_LEVEL_MEANING: Dict[str, str] = {
    L0: "Normal / 正常操作",
    L1: "Test Failure / 测试失败，可在 Budget 内自动修复",
    L2: "Build Failure / 构建失败，可在 Budget 内自动修复",
    L3: "Environment or Dependency / 环境或依赖问题，可尝试恢复，无法恢复则停止",
    L4: "Workspace Abnormal / 工作区异常，停止并恢复",
    L5: "Security Risk / 安全风险，立即 Hard Stop",
    L6: "Unknown or Dangerous / 无法确认影响，Hard Stop 并请求人工授权",
}

LEVEL_ACTION_ALLOW = "ALLOW"
LEVEL_ACTION_RECOVER = "RECOVER"
LEVEL_ACTION_RECOVER_OR_STOP = "RECOVER_OR_STOP"
LEVEL_ACTION_STOP = "STOP"
LEVEL_ACTION_HARD_STOP = "HARD_STOP"
LEVEL_ACTION_HARD_STOP_APPROVAL = "HARD_STOP_APPROVAL"

ERROR_LEVEL_ACTION: Dict[str, str] = {
    L0: LEVEL_ACTION_ALLOW,
    L1: LEVEL_ACTION_RECOVER,
    L2: LEVEL_ACTION_RECOVER,
    L3: LEVEL_ACTION_RECOVER_OR_STOP,
    L4: LEVEL_ACTION_STOP,
    L5: LEVEL_ACTION_HARD_STOP,
    L6: LEVEL_ACTION_HARD_STOP_APPROVAL,
}

# 等级 -> 默认决策
LEVEL_DECISION: Dict[str, str] = {
    L0: DECISION_ALLOW,
    L1: DECISION_ALLOW,                 # 允许在预算内自救
    L2: DECISION_ALLOW,
    L3: DECISION_ALLOW,                 # 允许尝试恢复
    L4: DECISION_DENY,
    L5: DECISION_DENY,
    L6: DECISION_REQUIRE_APPROVAL,
}

# 立即触发 Hard Stop、不允许 Agent 自行猜测后继续
HARD_STOP_LEVELS = (L5, L6)


def error_level_meaning(level: str) -> str:
    return ERROR_LEVEL_MEANING.get(level, f"未知等级 {level}")


def level_action(level: str) -> str:
    return ERROR_LEVEL_ACTION.get(level, LEVEL_ACTION_STOP)


def level_decision(level: str) -> str:
    return LEVEL_DECISION.get(level, DECISION_DENY)


# --------------------------------------------------------------------------- #
# 输出：stdout 只放 JSON，人类日志写 stderr
# --------------------------------------------------------------------------- #

class Reporter:
    """统一输出通道。

    - stdout：机器可解析的 Structured JSON（唯一）
    - stderr：人类可读日志
    """

    def __init__(self, *, json_only: bool = False, quiet: bool = False,
                 verbose: bool = False) -> None:
        self.json_only = json_only
        self.quiet = quiet
        self.verbose = verbose

    # ---- 人类日志（stderr） ---- #
    def log(self, message: str = "") -> None:
        if self.json_only or self.quiet:
            return
        print(message, file=sys.stderr)

    def info(self, message: str) -> None:
        self.log(message)

    def debug(self, message: str) -> None:
        if self.verbose:
            self.log(message)

    def warn(self, message: str) -> None:
        if self.json_only:
            return
        print(f"[warn] {message}", file=sys.stderr)

    def error(self, message: str) -> None:
        if self.json_only:
            return
        print(f"[error] {message}", file=sys.stderr)

    # ---- 机器结果（stdout） ---- #
    def emit_json(self, payload: Any) -> None:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=False))

    def emit_result(self, result: Result, *, resolution: Optional[Resolution] = None,
                    exit_code: Optional[int] = None) -> int:
        """输出 Result 并返回进程退出码。"""
        payload = result.to_dict()
        if resolution is not None:
            payload["resolution"] = resolution.to_dict()
        self.emit_json(payload)
        if exit_code is None:
            exit_code = exit_code_for(result)
        return exit_code


def exit_code_for(result: Result, *, usage: bool = False, tool_failure: bool = False,
                  env_failure: bool = False) -> int:
    """按 Exit Code 契约把 Result 映射为退出码。

    显式标志优先（usage / env / tool），否则按 decision：
    DENY -> 1，REQUIRE_APPROVAL -> 1（阻断通道），ALLOW -> 0。
    """
    if usage:
        return EXIT_USAGE
    if env_failure:
        return EXIT_ENV
    if tool_failure:
        return EXIT_TOOL
    if result.decision in (DECISION_DENY, DECISION_REQUIRE_APPROVAL):
        return EXIT_FINDING
    return EXIT_OK


# --------------------------------------------------------------------------- #
# 统一 CLI 公共参数
# --------------------------------------------------------------------------- #

def add_common_arguments(parser: Any, *, suppress_defaults: bool = False) -> None:
    """为子命令添加 v1.0 CLI 契约要求的公共参数。

    suppress_defaults=True 用于子解析器：避免子解析器的默认值覆盖掉写在
    子命令**之前**的同名参数（argparse 的经典坑），这样
    `cmd --json sub` 与 `cmd sub --json` 两种写法都成立。
    """
    import argparse

    def _default(value: Any) -> Any:
        return argparse.SUPPRESS if suppress_defaults else value

    parser.add_argument("--config", metavar="PATH", default=_default(None),
                        help="路径到 .safecode.yml（默认自动向上查找）")
    parser.add_argument("--json", dest="json_only", action="store_true",
                        default=_default(False),
                        help="只输出机器 JSON，不混入人类日志")
    parser.add_argument("--strict", action="store_true", default=_default(False),
                        help="强制 STRICT 模式（DEGRADED 一律 DENY）")
    parser.add_argument("--quiet", action="store_true", default=_default(False),
                        help="抑制人类日志")
    parser.add_argument("--verbose", action="store_true", default=_default(False),
                        help="输出调试日志到 stderr")
    parser.add_argument("--baseline", metavar="PATH", default=_default(None),
                        help="Baseline 文件路径（默认 .safecode/baseline.json）")
    parser.add_argument("--task-id", metavar="ID", default=_default(None),
                        help="任务 ID，用于 Persistent Budget 状态文件")


def reporter_from_args(args: Any) -> Reporter:
    return Reporter(
        json_only=bool(getattr(args, "json_only", False)),
        quiet=bool(getattr(args, "quiet", False)),
        verbose=bool(getattr(args, "verbose", False)),
    )


# --------------------------------------------------------------------------- #
# git 只读辅助
# --------------------------------------------------------------------------- #

def run_git(args: Sequence[str], cwd: Optional[str] = None,
            stdin_text: Optional[str] = None,
            timeout: int = 60) -> subprocess.CompletedProcess:
    """运行 git 子命令（只读用途为主），失败时返回非零 returncode。"""
    try:
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            input=(stdin_text if stdin_text is not None else None),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(["git", *args], 127, "", "git not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(["git", *args], 124, "", "git timeout")


def is_git_repo(cwd: Optional[str] = None) -> bool:
    proc = run_git(["rev-parse", "--is-inside-work-tree"], cwd=cwd)
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def repo_root(cwd: Optional[str] = None) -> Optional[str]:
    proc = run_git(["rev-parse", "--show-toplevel"], cwd=cwd)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def git_dir(cwd: Optional[str] = None) -> Optional[str]:
    proc = run_git(["rev-parse", "--git-dir"], cwd=cwd)
    if proc.returncode != 0:
        return None
    raw = proc.stdout.strip()
    if not raw:
        return None
    if os.path.isabs(raw):
        return raw
    base = cwd or os.getcwd()
    return os.path.normpath(os.path.join(base, raw))


def repo_head(cwd: Optional[str] = None) -> str:
    proc = run_git(["rev-parse", "HEAD"], cwd=cwd)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def current_branch(cwd: Optional[str] = None) -> str:
    proc = run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def repo_identity(cwd: Optional[str] = None) -> str:
    """仓库身份：优先 remote.origin.url，退化到仓库绝对路径。"""
    proc = run_git(["remote", "get-url", "origin"], cwd=cwd)
    if proc.returncode == 0 and proc.stdout.strip():
        return proc.stdout.strip()
    root = repo_root(cwd)
    return root or (cwd or os.getcwd())


def repo_state(cwd: Optional[str] = None) -> str:
    """仓库状态摘要：HEAD + 当前分支 + worktree 是否脏。"""
    head = repo_head(cwd)
    branch = current_branch(cwd)
    status = run_git(["status", "--porcelain"], cwd=cwd)
    dirty = bool(status.stdout.strip()) if status.returncode == 0 else True
    return f"head={head};branch={branch};dirty={int(dirty)}"


# --------------------------------------------------------------------------- #
# 杂项
# --------------------------------------------------------------------------- #

def find_upwards(filename: str, start: Optional[str] = None) -> Optional[str]:
    """从 start 向上查找文件（默认从 cwd 开始）。"""
    cur = os.path.abspath(start or os.getcwd())
    while True:
        candidate = os.path.join(cur, filename)
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def now_utc_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_duration(text: str) -> Optional[int]:
    """解析 "30m" / "90s" / "2h" 为秒数；无法解析返回 None。"""
    if not isinstance(text, str):
        return None
    m = re.fullmatch(r"\s*([0-9]+)\s*([smh])\s*", text)
    if not m:
        return None
    value = int(m.group(1))
    unit = m.group(2)
    return value * {"s": 1, "m": 60, "h": 3600}[unit]


def read_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json_file(path: str, payload: Any) -> None:
    """原子写入 JSON（临时文件 + replace）。"""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")
    os.replace(tmp, path)


def iter_text_lines(text: str) -> Iterable[Tuple[int, str]]:
    """逐行产出 (行号从 1 开始, 行内容)。"""
    for idx, line in enumerate(text.splitlines(), start=1):
        yield idx, line


def read_stdin_safely(timeout: float = 5.0) -> Tuple[str, bool]:
    """读取 stdin，带超时保护，返回 (文本, 是否超时)。

    契约要求 SafeCode 不得在无人值守环境阻塞等待 stdin：这里用守护线程读取，
    超时后立即返回并把控制权交给调用方（调用方应 Fail-Closed，而不是继续等待）。
    交互式终端（isatty）直接返回空文本，视为"没有输入"。
    """
    import threading

    try:
        if sys.stdin is None or sys.stdin.isatty():
            return "", False
    except (ValueError, OSError):
        return "", False

    box: Dict[str, Any] = {}

    def _reader() -> None:
        try:
            box["data"] = sys.stdin.read()
        except Exception as exc:  # pragma: no cover - 取决于宿主 stdin
            box["error"] = str(exc)

    thread = threading.Thread(target=_reader, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return "", True
    return str(box.get("data") or ""), False
