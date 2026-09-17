---
name: safecode-agent
description: 面向 AI Coding Agent 的安全开发工作流：检查 -> 修改 -> 测试 -> 失败自救 -> 安全扫描 -> Diff 审查 -> Push -> CI 再验证。当你要连续写代码、跑测试、修复失败并提交推送，需要在危险操作前刹车、在检查未通过时拒绝进入 Git 时使用。
---

# SafeCode Agent

这个 Skill 提供一套安全的工程工作流。它不替你写业务代码，它管的是**流程的可信度**。

一句最重要的话：**不要相信"AI 说自己检查过了"。** 关键安全规则由 `scripts/` 下的
可执行门禁强制执行，你要做的是调用它们、读取它们的退出码，并且尊重结果。

依赖规则细节时读 `rules/`：

- `rules/security.md` — 安全扫描、Baseline、凭据泄露处理
- `rules/testing.md` — 测试优先级、Flaky 检测
- `rules/recovery.md` — 错误等级、自救预算
- `rules/git.md` — Git 门禁、Hard Stop、授权令牌

## 工作流

### 1. Plan

先说清楚要改什么、验收标准是什么。有多个工作区 / 构建目录 / 同步副本时，
先确定唯一基准：**以实际 Git 仓库为唯一代码事实来源**。测试、构建、提交必须针对
同一份代码，避免"改了 A 测了 B"。

### 2. Inspect

动手前先看清状态：

```bash
git status --porcelain
git branch --show-current
git log --oneline -5
python scripts/safecode.py git guard --status
```

同时确认项目的构建方式、测试方式，以及项目规则文件（`AGENTS.md`、`CLAUDE.md`
或其他 Skill）。工作区与远端不一致时先对齐，再开始改。

高风险改动前留一个可恢复点（`git status` / `git diff` 记录、临时分支或 commit）。

### 3. Modify

按计划改。改的范围要能对应到步骤 1 的验收标准，不要顺手重构无关代码。

### 4. Test

```bash
python scripts/safecode.py test run
```

结构化结果会给出等级（L0..L6）、类别、失败测试列表，以及每次运行记录。
失败时**读 JSON，不要去正则解析自然语言日志**。

Flaky 与环境类失败不要去改业务代码，改测试或修环境。

### 5. Recover if needed

失败后按等级决定动作（`rules/recovery.md` 有完整表）：

```
L1/L2  -> 在预算内自动修复
L3     -> 尝试恢复环境/依赖，恢复不了就停
L4     -> 停止并恢复工作区
L5     -> HARD STOP，不自行绕过
L6     -> HARD STOP + 请求人工授权
```

预算记在 `.safecode/state/<task-id>.json`：`max_recovery_attempts=3`、
`max_total_test_runs=20`、`max_total_recoveries=10`、`max_total_time=30m`。
`max_total_test_runs` 数的是**实际测试执行次数**——通过的那次与 Flaky rerun 都算，
不只看失败；判断"该不该停"看的是 `consecutive_failures`。
连续失败 3 次或预算耗尽就停手，输出诊断报告，交人工。

```bash
python scripts/safecode.py recover status
```

### 6. Security Scan

```bash
python scripts/safecode.py security scan --staged
```

只看**本次准备提交的内容**。有阻断 finding 就不要提交。

发现真实凭据时不要只删文件里的字符串：**先 Revoke / Rotate 凭据**，
再评估是否需要清理历史（历史改写是 HIGH RISK，必须人工确认）。

需要保留某个已知、已审计的结果时，写 Baseline 或 `allow_list`，带 reason：

```bash
python scripts/safecode.py security baseline --reason "audited test fixture"
```

Check 无法完成（Scanner 缺失、超时、输出无法解析、shallow 仓库扫不了历史）
不是 PASS，不要把它当成"没问题"。

### 7. Review Diff

```bash
python scripts/safecode.py dependency check
python scripts/safecode.py git guard --check-diff
```

确认清单：只改了预期文件；没有顺手带进 `.env`、私钥、大二进制；
依赖变化与 manifest 一致；没有危险命令被写进脚本；删除量和影响面在预期内。

### 8. Push

```bash
python scripts/safecode.py pre-push
```

它串联 Diff 检查、安全扫描、依赖检查、测试与 Git Guard，由 Decision Resolver 汇总。
只有 Effective Decision 为 `ALLOW` 才允许 Push：

```
Effective Decision = ALLOW
+ 所有 Required Gate PASS
+ 无未授权 Hard Stop
+ Git Guard ALLOW
```

被拒绝时的退出码：`1` 发现问题或需要授权、`2` 参数/配置错误、`3` 工具失败、`4` 环境异常。

需要人工授权的操作走令牌流程：请求授权 -> 拿到一次性 token ->
验证 operation fingerprint 匹配且未过期 -> 重放同一个操作。

不要用 `git push --no-verify` 绕过；它不会让 CI 变成 PASS，只会被记录成绕过事件。

本地门禁通过 ≠ 推送一定成功。目标分支开着 Required status checks 时，服务端还要求被推的
commit 自己已经拿到这些 check 的成功状态，否则回 `GH006 ... required status checks are
expected`。这种情况先把 commit 推到非保护分支让 CI 跑出来，再推目标分支：

```bash
git push origin HEAD:refs/heads/ci/<topic>   # 先让 CI 在这个 sha 上跑出 checks
git push origin main                         # checks 满足后再推，本地门禁照走
```

### 9. CI 再验证

Push 之后还有两道防线：CI（`test` / `security` / `dependency`）与分支保护
（Required status checks）。本地 hook 可以被删除，CI 不能；CI 通过但没配成
Required check，也挡不住直接 merge。CI 红了就是没通过——它和本地 Gates 是同一套
判定的独立执行，不是"再确认一下"。

## 硬性要求

- 不放行任何"无法确认"的情况；检查无法完成一律不 PASS。
- 退出码非 0 不得被解释为通过；JSON 与退出码冲突时取更严格的一方。
- `DEGRADED` 不是 PASS；CI / `--strict` 下 `DEGRADED` 就是 DENY。
- `L5` / `L6` 不允许 Agent 自行猜测后继续。
- 不得修改 `.safecode.yml` 来关闭核心不变量（被禁止的组合会直接判配置非法）。
- 不得用 `--no-verify`、删 hook、改配置等方式"绕过一次检查"。
