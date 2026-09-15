#!/usr/bin/env python3
"""SafeCode Agent — 测试运行器与失败分类。

调用 `python -m pytest` 运行测试，解析其输出，将失败按错误等级分类：

    L0  全部通过                       -> 继续
    L1  普通断言失败 (assert)          -> 自动修复
    L2  编译 / 语法错误 (SyntaxError)  -> 定位并修复
    L3  环境 / 依赖异常 (ImportError / ModuleNotFoundError / fixture 错误)
                                     -> 尝试恢复依赖
    L6  无法归类的失败                 -> 停止并请求人工确认

用法：
    python scripts/test-runner.py [--json] [pytest 目标路径...] [-- --透传参数]

退出码：
    0  全部通过（L0）
    1  存在失败 / 测试被拒绝（L1/L2/L3/L6）
    2  用法错误 / 内部错误
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

import safecode_common as sc

DEFAULT_TIMEOUT = 1800  # 秒

# pytest 失败项摘要行： "FAILED path::test - Reason" 或 "FAILED path::test"
_FAILED_RE = re.compile(r"^FAILED\s+(\S+?)(?:\s+-\s+(.*))?$")
# 错误（收集/import）项
_ERROR_RE = re.compile(r"^(ERROR|INTERNALERROR)\s+(\S+)\s*(?:-\s+(.*))?$")


class FailureItem:
    def __init__(self, node_id: str, message: str, sub_level: str):
        self.node_id = node_id
        self.message = (message or "").strip()
        self.sub_level = sub_level

    @property
    def file(self) -> str:
        # node id 形如 path/to/test.py::TestClass::test_name
        return self.node_id.split("::", 1)[0] if self.node_id else ""

    @property
    def line(self) -> int:
        # pytest 短摘要不含行号，尝试从消息提取 "(line N)"
        m = re.search(r"line\s+(\d+)", self.message)
        if m:
            return int(m.group(1))
        return 0

    def summary(self) -> str:
        return sc.truncate_evidence(self.message or self.node_id, 120)


def classify_message(message: str, node_id: str) -> str:
    """根据失败消息与节点判定子等级。"""
    msg = (message or "").lower()
    if "syntaxerror" in msg or "invalid syntax" in msg:
        return sc.L2
    if "modulenotfounderror" in msg or "importerror" in msg or "no module named" in msg:
        return sc.L3
    if "fixture" in msg or "error during fixture" in msg or "fixture '" in msg or "not found" in msg:
        return sc.L3
    if "assert" in msg or "assertionerror" in msg:
        return sc.L1
    return sc.L6


def parse_pytest_output(stdout: str, stderr: str) -> tuple:
    """解析 pytest 输出，返回 (overall_level, [FailureItem], passed)."""
    text = (stdout or "") + "\n" + (stderr or "")
    items: list = []
    collection_error = False

    for line in text.splitlines():
        fm = _FAILED_RE.match(line.strip())
        if fm:
            node_id = fm.group(1)
            message = fm.group(2) or ""
            level = classify_message(message, node_id)
            items.append(FailureItem(node_id, message, level))
            continue
        em = _ERROR_RE.match(line.strip())
        if em:
            collection_error = True
            node_id = em.group(2) or "collection"
            message = em.group(3) or ""
            # 收集错误多为 import / 语法问题
            if "syntaxerror" in message.lower() or "invalid syntax" in message.lower():
                level = sc.L2
            else:
                level = sc.L3
            items.append(FailureItem(node_id, message, level))

    # 通过判定
    if not items:
        if re.search(r"passed", text) or "no tests ran" in text.lower():
            return sc.L0, [], True
        return sc.L0, [], True

    # 计算总等级：取最严重
    sub_levels = {it.sub_level for it in items}
    if sc.L2 in sub_levels:
        overall = sc.L2
    elif sc.L3 in sub_levels:
        overall = sc.L3
    elif sc.L1 in sub_levels:
        overall = sc.L1
    else:
        overall = sc.L6
    return overall, items, False


ACTION_HINT = {
    sc.L1: "建议：自动修复失败的断言逻辑（检查预期值与实际值）。",
    sc.L2: "建议：定位编译 / 语法错误并修复对应文件。",
    sc.L3: "建议：尝试恢复环境 / 依赖（安装缺失包、检查虚拟环境、重建 fixture）。",
    sc.L6: "建议：无法确定失败原因，停止修改并请求人工确认。",
    sc.L0: "无需动作，全部通过。",
}


def print_human_report(overall: str, items: list, duration: float, target: str) -> None:
    print(sc.colorize("SafeCode 测试运行器", "bold"))
    print(f"目标: {target}")
    print(f"耗时: {duration:.1f}s")
    print(f"错误等级: {overall} — {sc.error_level_meaning(overall)}")
    print(f"失败/错误数: {len(items)}")
    if items:
        print("-" * 60)
        for it in items:
            print(f"  [{it.sub_level}] {it.file}"
                  + (f":{it.line}" if it.line else "")
                  + f"  ({sc.truncate_evidence(it.summary(), 80)})")
    print("-" * 60)
    print(ACTION_HINT.get(overall, ""))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="test-runner.py",
        description="SafeCode 测试运行器（pytest 封装 + 失败分级）",
    )
    parser.add_argument("--json", action="store_true", help="输出结构化 JSON 结果")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"pytest 超时秒数（默认 {DEFAULT_TIMEOUT}）")
    # 剩余位置参数分为 pytest 目标 与 -- 之后的透传参数
    parser.add_argument("rest", nargs=argparse.REMAINDER, help="pytest 目标及 -- 透传参数")
    args = parser.parse_args(argv)

    # 拆分 targets 与 passthrough
    rest = args.rest or []
    if "--" in rest:
        idx = rest.index("--")
        targets = rest[:idx]
        passthrough = rest[idx + 1:]
    else:
        targets = rest
        passthrough = []

    cmd = [sys.executable, "-m", "pytest", "-v"] + targets + passthrough
    target_desc = " ".join(targets) if targets else "（默认目标）"

    import time
    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        duration = time.perf_counter() - start
        print(sc.colorize(f"pytest 超时（>{args.timeout}s），判定为环境异常 (L3)。", "red"),
              file=sys.stderr)
        if args.json:
            sc.write_json_report({"tool": "test-runner", "level": sc.L3,
                                  "passed": False, "failures": [],
                                  "error": "timeout", "duration": round(duration, 1)})
        return sc.EXIT_GATE_REJECT
    except Exception as exc:  # noqa: BLE001
        print(f"错误: 无法运行 pytest: {exc}", file=sys.stderr)
        return sc.EXIT_USAGE

    duration = time.perf_counter() - start
    overall, items, passed = parse_pytest_output(proc.stdout, proc.stderr)

    if args.json:
        payload = {
            "tool": "test-runner",
            "level": overall,
            "passed": passed,
            "failure_count": len(items),
            "action": ACTION_HINT.get(overall, ""),
            "failures": [
                {"level": it.sub_level, "file": it.file, "line": it.line,
                 "summary": it.summary(), "node_id": it.node_id}
                for it in items
            ],
            "pytest_returncode": proc.returncode,
        }
        sc.write_json_report(payload)
    else:
        print_human_report(overall, items, duration, target_desc)

    return sc.EXIT_PASS if passed else sc.EXIT_GATE_REJECT


if __name__ == "__main__":
    sys.exit(main())
