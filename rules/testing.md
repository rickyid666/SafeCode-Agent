# rules/testing.md — 测试规则（软约束）

## 测什么

优先覆盖核心业务逻辑，不要一上来追求 UI 全覆盖。顺序：

1. 核心逻辑单元测试
2. 状态机
3. 多任务 / 并发
4. Web E2E
5. CLI E2E
6. 桌面端 / Android 构建

至少覆盖：单任务启动、单任务停止、waiting 状态、waiting -> running、
running -> stopped、开播轮询、异常重试、任务取消、多房间互不污染、请求闸门、
配置错误、网络异常。

## 可测试性设计

不要把等待时间硬编码在业务逻辑里：

```python
# 生产
LIKE_INTERVAL = 1.0
WAIT_LIVE_INTERVAL = 5.0
RETRY_INTERVAL = 3.0
REQUEST_TIMEOUT = 10.0
```

测试环境用更短的值，或者更彻底一点——把时间、sleep、网络请求抽象出去，
让测试注入 Mock。生产配置与测试配置必须明确分离。

## 测试怎么写（就本仓库而言）

黑盒优先：用 subprocess 调 CLI，断言 Structured JSON 与退出码，而不是断言内部函数。
这样测试验证的是契约，实现重构不会让测试白写。

外部依赖用 PATH 桩：不装 `gitleaks`、`osv-scanner` 也能测"Scanner 异常必须 DENY"——
在临时目录造一个假的同名可执行文件，让它输出合法 JSON / 退出非零 / 输出垃圾，
三种情况各测一遍。Windows 上记得同时提供 `.bat`/`.cmd`。

不要在测试里写真实格式的凭据字面量，需要样例就运行时拼接。

## 失败不等于 Bug

一次 FAIL 不代表代码错了。分类：

```
Compile Error / Assertion Failure / Dependency Error
Environment Error / Real Bug / Flaky Test / Unknown
```

- `Flaky Test` 和 `Environment Error` 不要默认去改业务代码。
- 无法归类的失败按 L6 处理：停下来问，不要猜。

## Flaky 检测

```
初始 Test -> FAIL
   -> 代码与环境不变，额外 rerun 3 次（默认）
   -> 比较结果
```

- 结果不稳定（既有 PASS 又有 FAIL）-> `category = FLAKY_TEST`，停止无意义的代码修改。
- 三次都 FAIL -> 不认定 Flaky，走正常错误分类。
- 三次都 PASS（初始 FAIL 之后）-> 同样是 Flaky，一样记录。

每次 rerun 都要记录 run 序号、退出码、失败测试 id、代码状态（HEAD）、环境摘要，
让结果可复现、可审计。rerun 消耗 Test Budget，不消耗 Recovery 次数。

Test Budget（`max_total_test_runs`）数的是实际执行次数，所以**通过的那次也消耗**：
它回答"一共跑了几次测试"，"是不是白跑"由 `consecutive_failures` 单独判断。

## 测试结果要能被机器读

`test-runner.py` 会把结果整理成 Structured JSON：等级（L0..L6）、类别、失败测试列表、
每次运行记录、预算快照。Recovery 读的是这些结构化字段，不是正则去啃自然语言日志。
