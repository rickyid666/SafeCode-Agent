"""Decision Resolver：把 Structured JSON + Exit Code + Policy Mode 合并为 Effective Decision。

契约要点（v1.0）：

- ALLOW < REQUIRE_APPROVAL < DENY，取更严格结果。
- FAIL -> DENY；Exit != 0 -> 至少 DENY；Schema 无效 -> DENY；结果缺失 -> DENY。
- DEGRADED + ALLOW 只在 LOCAL 非严格模式成立；STRICT / CI 下升级为 DENY。

用法：

    python scripts/decision-resolver.py --result result.json --exit-code 1 --strict
    echo '{...}' | python scripts/decision-resolver.py - --exit-code 0

退出码：Effective Decision = ALLOW -> 0，其余 -> 1。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from safecode_common import (  # noqa: E402
    CATEGORY_SYSTEM,
    DECISION_ALLOW,
    EXIT_FINDING,
    EXIT_OK,
    EXIT_USAGE,
    Reporter,
    Result,
    add_common_arguments,
    make_result,
    read_stdin_safely,
    resolve_decision,
    resolve_mode,
    validate_result_dict,
)
from safecode_config import ConfigError, load_config  # noqa: E402


def resolve(
    result: Optional[Result | Dict[str, Any]],
    exit_code: int,
    *,
    strict: bool = False,
    config: Any = None,
) -> Dict[str, Any]:
    """供其他脚本直接调用的解析入口。返回 Resolution 的 dict 形式。"""
    mode = resolve_mode(strict_flag=strict, config=config)
    schema_valid: Optional[bool] = None
    if isinstance(result, dict):
        schema_valid, _ = validate_result_dict(result)
    return resolve_decision(result, exit_code, mode, schema_valid=schema_valid).to_dict()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safecode decision",
        description="Merge Structured JSON + exit code + policy mode into an effective decision.",
    )
    parser.add_argument("result", nargs="?", default="-",
                        help="Result JSON file, or '-' to read from stdin")
    parser.add_argument("--exit-code", type=int, default=0,
                        help="Exit code of the check that produced the result")
    add_common_arguments(parser)
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    reporter = Reporter(json_only=bool(args.json_only), quiet=bool(args.quiet),
                        verbose=bool(args.verbose))

    try:
        config = load_config(args.config, required=False)
    except ConfigError as exc:
        reporter.error(f"{exc.code}: {exc.message}")
        result = make_result("FAIL", "DENY", exc.code, exc.message,
                             category=CATEGORY_SYSTEM)
        return reporter.emit_result(result, exit_code=EXIT_USAGE)

    raw = ""
    try:
        if args.result == "-":
            raw, timed_out = read_stdin_safely()
            if timed_out:
                result = make_result(
                    "FAIL", "DENY", "RESULT_UNAVAILABLE",
                    "no result available on stdin within timeout: cannot verify -> DENY",
                    category=CATEGORY_SYSTEM)
                reporter.error(result.message)
                return reporter.emit_result(result, exit_code=EXIT_USAGE)
        else:
            with open(args.result, "r", encoding="utf-8") as fh:
                raw = fh.read()
    except OSError as exc:
        result = make_result("FAIL", "DENY", "RESULT_UNREADABLE", str(exc),
                             category=CATEGORY_SYSTEM)
        return reporter.emit_result(result, exit_code=EXIT_USAGE)

    parsed: Optional[Dict[str, Any]] = None
    parse_error = ""
    if raw.strip():
        try:
            candidate = json.loads(raw)
            if isinstance(candidate, dict):
                parsed = candidate
            else:
                parse_error = "result JSON must be an object"
        except ValueError as exc:
            parse_error = f"result JSON is not parseable: {exc}"

    mode = resolve_mode(strict_flag=bool(args.strict), config=config)
    schema_valid: Optional[bool] = None
    if parsed is not None:
        schema_valid, schema_errors = validate_result_dict(parsed)
    else:
        schema_errors = [parse_error or "no result provided"]

    resolution = resolve_decision(parsed, args.exit_code, mode, schema_valid=schema_valid)

    payload: Dict[str, Any] = {
        "schema_version": "1.0",
        "status": resolution.effective_status,
        "decision": resolution.effective_decision,
        "severity": (parsed or {}).get("severity", "LOW"),
        "category": (parsed or {}).get("category", CATEGORY_SYSTEM),
        "code": (parsed or {}).get("code", "RESOLVED"),
        "message": f"effective decision: {resolution.effective_decision}",
        "locations": (parsed or {}).get("locations", []) or [],
        "metadata": {
            "resolution": resolution.to_dict(),
            "input_exit_code": args.exit_code,
            "input_status": (parsed or {}).get("status"),
            "input_decision": (parsed or {}).get("decision"),
            "schema_valid": bool(schema_valid),
            "schema_errors": list(schema_errors) if not schema_valid else [],
        },
    }
    reporter.emit_json(payload)
    if resolution.blocking:
        reporter.warn(f"blocked: {resolution.effective_decision}")
        return EXIT_FINDING
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
