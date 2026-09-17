# rules/recovery.md — 自救规则（软约束）

测试或构建失败时，Agent 应该尝试自救，但自救是有预算的、有上限的、可审计的。

```
失败
 -> 读取完整错误信息
 -> 解析 Structured JSON（不要正则去啃自然语言日志）
 -> 分类
 -> 定位原因
 -> 修改
 -> 重新测试
```

## 错误分类

```
L0  Normal                 正常，继续
L1  Test Failure           测试失败，可在预算内自动修复
L2  Build Failure          构建失败，可在预算内自动修复
L3  Environment / Dependency  环境或依赖问题，可尝试恢复；无法恢复则停止
L4  Workspace Abnormal     工作区异常，停止并恢复
L5  Security Risk          安全风险，立即 Hard Stop
L6  Unknown / Dangerous    无法确认影响，Hard Stop 并请求人工授权
```

等级不是给 Agent 自由发挥的建议，而是 Policy Engine 的输入：

```
L0 -> ALLOW
L1 -> RECOVER
L2 -> RECOVER
L3 -> RECOVER / STOP
L4 -> STOP
L5 -> HARD STOP
L6 -> HARD STOP + HUMAN APPROVAL
```

`L5` 不得通过普通对话自动绕过；`L6` 默认 `REQUIRE_APPROVAL`，操作本身不可授权时才 DENY。
`UNKNOWN` 表示无法确认，不表示安全。

## 预算

单个错误的连续重试次数不够，必须有全局预算：

```
MAX_RECOVERY_ATTEMPTS = 3      单任务连续失败上限
MAX_TOTAL_TEST_RUNS   = 20     实际测试执行次数（通过与否都计数）
MAX_TOTAL_RECOVERIES  = 10     累计自救次数
MAX_TOTAL_TIME        = 30m    累计耗时
```

计数口径要说清楚：

- **一次 Recovery**：针对一次已识别的失败原因采取修复动作，并进入下一次验证尝试。
- **每一次真实测试执行都计入** `MAX_TOTAL_TEST_RUNS`，包括通过的那一次和每一次 Flaky
  rerun。只有 `consecutive_failures` 区分结果（通过归零、失败累加），它才是自救循环的闸。
  这让配置里的 `20` 就等于"最多跑 20 次测试"，而不是"最多失败 20 次"。
- 单纯重跑同一个测试、没有修复动作，**不算 Recovery**，但仍然计入 `MAX_TOTAL_TEST_RUNS`。
- Flaky 检测需要的 rerun 只消耗 Test Budget。
- 已经通过的那一次不因预算耗尽被拒：结果里标 `budget_exhausted: true` 提示不要再跑，
  但仍判 PASS —— 本次执行已经成功，"还能不能再跑"是另一回事。

```
Test #1 FAIL -> 修复 -> Recovery #1 -> Test #2 FAIL -> 修复 -> Recovery #2 -> Test #3
= 3 test runs, 2 recoveries
```

预算耗尽时：

```
停止自动恢复 -> 生成诊断报告 -> 人工介入
```

不允许"单个环节都没超限，整体跑了好几个小时"。

## 预算必须持久化

```
.safecode/state/<task-id>.json
```

记录 `test_runs`、`recoveries`、`elapsed_seconds`、`consecutive_failures`、
`last_result_code`、完整 history。

Agent 重启、Session 切换、工具重新调用，都不能靠重启进程把预算归零。
状态文件要防并发丢更新（更新在锁内读-改-写），损坏时 Fail-Closed，不允许静默重建。

## 什么时候必须停手

- 连续失败达到 `MAX_RECOVERY_ATTEMPTS`
- 任一全局预算耗尽
- 判定为 `FLAKY_TEST` 或 `ENVIRONMENT`（这两类不该去改业务代码）
- 出现 L5 / L6
- 状态文件损坏、无法确认当前预算

停下时要输出诊断报告（`.safecode/diagnostic-report.md`）：任务 ID、起止时间、
累计计数、按等级分布、历次失败摘要，以及明确的一句"已达到最大自救轮数/预算耗尽，
停止修改，禁止 Push，需人工介入"。
