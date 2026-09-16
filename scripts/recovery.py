#!/usr/bin/env python3
"""SafeCode Recovery CLI —— Persistent Budget + Recovery 工作流入口。

子命令：
- record-failure 记录一次失败（--type test_run|recovery，默认 recovery）
- record-success 记录恢复成功（consecutive_failures 归零）
- status        输出当前预算计数与剩余额度
- reset         清空状态（--task-id 或 --all）
- report        打印已有诊断报告路径与内容摘要

退出码契约：
- 0  正常（失败在预算内、允许继续 / 成功 / status / reset / report）
- 1  发现明确问题或需人工授权（预算耗尽 → DENY；L5 → DENY；L6 → REQUIRE_APPROVAL）
- 2  参数 / 配置错误
- 4  环境异常（状态损坏 / 锁超时）

stdout 只输出一个 Structured JSON 对象；人类日志一律走 stderr（--json 时静默）。
纯 Python 标准库，跨平台。Python >= 3.10。
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import safecode_common as sc
import safecode_config as cfg
import safecode_budget as budget

# 风险等级（来自 safecode_common）
L5 = sc.L5
L6 = sc.L6
L4 = sc.L4
L3 = sc.L3


# --------------------------------------------------------------------------- #
# CLI 参数
# --------------------------------------------------------------------------- #

def _add_common(parser: argparse.ArgumentParser) -> None:
    sc.add_common_arguments(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recovery.py",
        description="SafeCode Persistent Budget + Recovery CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("record-failure", help="记录一次失败并更新预算")
    _add_common(p)
    p.add_argument("--type", choices=["test_run", "recovery"], default="recovery",
                   help="失败类型（默认 recovery）")
    p.add_argument("--level", default="L1", help="错误等级 L0..L6（默认 L1）")
    p.add_argument("--code", default="ASSERTION_FAILURE", help="结果代码")
    p.add_argument("--summary", default="", help="失败摘要")
    p.add_argument("--duration", type=float, default=0, help="本次耗时（秒）")

    p = sub.add_parser("record-success", help="记录恢复成功")
    _add_common(p)
    p.add_argument("--code", default="RECOVERY_SUCCESS", help="结果代码")
    p.add_argument("--summary", default="", help="摘要")
    p.add_argument("--level", default="L0", help="错误等级（默认 L0）")
    p.add_argument("--duration", type=float, default=0, help="本次耗时（秒）")

    p = sub.add_parser("status", help="输出当前预算状态")
    _add_common(p)

    p = sub.add_parser("reset", help="清空预算状态")
    _add_common(p)
    p.add_argument("--all", action="store_true", help="清空所有 task 状态")

    p = sub.add_parser("report", help="打印已有诊断报告")
    _add_common(p)

    return parser


def _resolve_root() -> str:
    return sc.repo_root(os.getcwd()) or os.getcwd()


def resolve_task_id(args: argparse.Namespace, root: str) -> Optional[str]:
    if getattr(args, "task_id", None):
        return args.task_id
    env = os.environ.get("SAFECODE_TASK_ID")
    if env:
        return env
    cur = budget.get_current_task(root)
    return cur or None


# --------------------------------------------------------------------------- #
# 子命令实现（返回 (Result, exit_code)）
# --------------------------------------------------------------------------- #

def cmd_record_failure(args: argparse.Namespace, root: str, limits: Dict[str, Any]
                       ) -> Tuple[sc.Result, int]:
    task_id = resolve_task_id(args, root)
    if not task_id:
        return sc.usage_error_result("MISSING_TASK_ID",
                                      "record-failure requires --task-id (or SAFECODE_TASK_ID / current)"), sc.EXIT_USAGE
    budget.set_current_task(task_id, root)

    level = args.level
    # L5 / L6 立即 Hard Stop：不消耗任何预算
    if level == L5:
        return sc.fail_deny_result(
            "HARD_STOP_SECURITY",
            "Security risk (L5): immediate hard stop, recovery denied.",
            severity=sc.SEVERITY_CRITICAL, category=sc.CATEGORY_RECOVERY), sc.EXIT_FINDING
    if level == L6:
        return sc.approval_result(
            "HARD_STOP_UNKNOWN",
            "Unknown / dangerous (L6): hard stop and require human approval.",
            category=sc.CATEGORY_RECOVERY), sc.EXIT_FINDING

    # 正常记录（在文件锁内读-改-写）
    if args.type == "test_run":
        state = budget.record_test_run(task_id, root=root, level=level, code=args.code,
                                       summary=args.summary, duration_seconds=args.duration, limits=limits)
    else:
        state = budget.record_recovery(task_id, root=root, level=level, code=args.code,
                                       summary=args.summary, duration_seconds=args.duration, limits=limits)

    reason = budget.check_exhausted(state, limits)
    if reason:
        report_path = budget.write_diagnostic_report(state, limits, root=root, reason=reason)
        result = sc.fail_deny_result(
            "BUDGET_EXHAUSTED",
            f"Recovery budget exhausted: {reason}. Stop modifying, do not push, human intervention required.",
            category=sc.CATEGORY_RECOVERY)
        result.metadata["diagnostic_report"] = report_path
        result.metadata["budget"] = budget.budget_report(state, limits)
        return result, sc.EXIT_FINDING

    # L4：工作区异常，立即停止恢复（预算内也停）
    if level == L4:
        report_path = budget.write_diagnostic_report(state, limits, root=root, reason="workspace abnormal: stop and recover")
        result = sc.fail_deny_result(
            "WORKSPACE_ABNORMAL",
            "Workspace abnormal (L4): stop and recover.",
            category=sc.CATEGORY_RECOVERY)
        result.metadata["diagnostic_report"] = report_path
        result.metadata["budget"] = budget.budget_report(state, limits)
        return result, sc.EXIT_FINDING

    # L1 / L2 / L3：预算内允许继续恢复
    if level == L3:
        hint = "Environment/dependency (L3): attempt recovery; if unrecoverable, stop."
    else:
        hint = "Recovery allowed within budget."
    result = sc.pass_result("RECOVERY_ALLOWED", hint, category=sc.CATEGORY_RECOVERY)
    result.metadata["budget"] = budget.budget_report(state, limits)
    if level == L3:
        result.metadata["recover_hint"] = "recover if possible, else stop"
    return result, sc.EXIT_OK


def cmd_record_success(args: argparse.Namespace, root: str, limits: Dict[str, Any]
                       ) -> Tuple[sc.Result, int]:
    task_id = resolve_task_id(args, root)
    if not task_id:
        return sc.usage_error_result("MISSING_TASK_ID",
                                      "record-success requires --task-id (or SAFECODE_TASK_ID / current)"), sc.EXIT_USAGE
    budget.set_current_task(task_id, root)

    state = budget.record_success(task_id, root=root, level=args.level, code=args.code,
                                  summary=args.summary, duration_seconds=args.duration, limits=limits)
    result = sc.pass_result("RECOVERY_SUCCESS",
                            "Recovery succeeded: consecutive failures reset.",
                            category=sc.CATEGORY_RECOVERY)
    result.metadata["budget"] = budget.budget_report(state, limits)
    return result, sc.EXIT_OK


def cmd_status(args: argparse.Namespace, root: str, limits: Dict[str, Any]
               ) -> Tuple[sc.Result, int]:
    task_id = resolve_task_id(args, root)
    if not task_id:
        return sc.usage_error_result("MISSING_TASK_ID",
                                      "status requires --task-id (or SAFECODE_TASK_ID / current)"), sc.EXIT_USAGE
    state = budget.load_state(task_id, root=root)
    report = budget.budget_report(state, limits)
    result = sc.pass_result("BUDGET_STATUS", "Current recovery budget state.",
                            category=sc.CATEGORY_RECOVERY)
    result.metadata["task_id"] = task_id
    result.metadata["budget"] = report
    result.metadata["state"] = {
        "task_id": state.get("task_id", task_id),
        "started_at": state.get("started_at", ""),
        "updated_at": state.get("updated_at", ""),
        "last_result_code": state.get("last_result_code", ""),
    }
    return result, sc.EXIT_OK


def cmd_reset(args: argparse.Namespace, root: str, limits: Dict[str, Any]
              ) -> Tuple[sc.Result, int]:
    if not args.all and not args.task_id:
        return sc.usage_error_result("MISSING_TARGET",
                                      "reset requires --task-id or --all"), sc.EXIT_USAGE
    if args.all:
        state_dir = budget.state_dir(root)
        removed = 0
        if os.path.isdir(state_dir):
            for name in os.listdir(state_dir):
                if name.endswith(".json") or name == "current":
                    try:
                        os.remove(os.path.join(state_dir, name))
                        removed += 1
                    except OSError:
                        pass
        result = sc.pass_result("BUDGET_RESET",
                                f"Reset all budget states (removed {removed} file(s)).",
                                category=sc.CATEGORY_RECOVERY)
        return result, sc.EXIT_OK
    budget.reset_state(args.task_id, root=root)
    result = sc.pass_result("BUDGET_RESET",
                            f"Reset budget state for task {args.task_id}.",
                            category=sc.CATEGORY_RECOVERY)
    return result, sc.EXIT_OK


def cmd_report(args: argparse.Namespace, root: str, limits: Dict[str, Any]
               ) -> Tuple[sc.Result, int]:
    path = budget.diagnostic_report_path(root)
    if os.path.isfile(path):
        try:
            text = open(path, encoding="utf-8").read()
        except OSError as exc:
            text = ""
            path_str = ""
        else:
            path_str = path
        result = sc.pass_result("BUDGET_REPORT", "Diagnostic report found.",
                                category=sc.CATEGORY_RECOVERY)
        result.metadata["report_path"] = path_str
        result.metadata["report_summary"] = (text[:800] if text else "")
    else:
        result = sc.pass_result("BUDGET_REPORT", "No diagnostic report found.",
                                category=sc.CATEGORY_RECOVERY)
        result.metadata["report_path"] = None
    return result, sc.EXIT_OK


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #

_DISPATCH = {
    "record-failure": cmd_record_failure,
    "record-success": cmd_record_success,
    "status": cmd_status,
    "reset": cmd_reset,
    "report": cmd_report,
}


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    reporter = sc.reporter_from_args(args)
    root = _resolve_root()

    # 配置（.safecode.yml）加载失败 → 配置错误 exit 2
    try:
        config = cfg.load_config(getattr(args, "config", None), cwd=os.getcwd())
    except cfg.ConfigError as exc:
        result = sc.usage_error_result(exc.code, exc.message)
        reporter.emit_json(result.to_dict())
        return sc.EXIT_USAGE

    try:
        limits = config.budget_limits
        handler = _DISPATCH.get(args.command)
        if handler is None:
            result = sc.usage_error_result("UNKNOWN_COMMAND", f"unknown command: {args.command}")
            code = sc.EXIT_USAGE
        else:
            result, code = handler(args, root, limits)
    except budget.BudgetError as exc:
        # 状态损坏 / 锁超时 → 环境异常 exit 4
        result = sc.env_error_result(exc.code, str(exc))
        code = sc.EXIT_ENV

    reporter.emit_json(result.to_dict())
    return code


if __name__ == "__main__":
    sys.exit(main())
