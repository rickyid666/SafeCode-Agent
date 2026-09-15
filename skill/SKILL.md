---
name: safecode-agent
description: 给 AI Coding Agent 套上可刹车的安全开发工作流——开发任务中自动执行 检查→修改→测试→自救→安全扫描→Diff审查→Push，并在安全风险、连续失败或拿不准时停止请求确认。
---

# SafeCode Agent

面向 AI Coding Agent 的通用安全开发 Skill。它不写业务代码，只提供一条带刹车的安全工程工作流。

触发场景：Agent 开始任何写代码/改代码/测试/修复/推送的开发任务时加载本 Skill，并在整个过程中遵循以下流程。

## 工作流

```text
Plan
 ↓
Inspect
 ↓
Modify
 ↓
Test
 ↓
Recover (if needed)
 ↓
Security Scan
 ↓
Review Diff
 ↓
Push
```

详细规则见 `../rules/`：`security.md`、`testing.md`、`recovery.md`、`git.md`。脚本位于 `../scripts/`。

---

## Plan

明确本次任务目标与范围，确认改动会落在哪个分支、影响哪些文件。不要一上来就改。

## Inspect（对照 rules：先检查再修改）

动手前必须检查当前项目状态：

```bash
git branch            # 当前分支
git status            # 工作区状态
git diff              # 未暂存改动
git log -n 5          # 最近提交
```

同时确认构建方式、测试方式，以及项目规则文件（`AGENTS.md`、`CLAUDE.md` 或其他 Skill）。不了解状态时不许大规模改动。

以实际 Git 仓库为唯一代码基准（见 `../rules/git.md`）：所有测试、构建、提交都针对同一份工作区。

## Modify

按 Plan 改代码。高风险改动前先留 checkpoint：

```bash
git status
git branch
git diff
```

必要时建临时分支或 commit，保证后续修不回来时能回滚。生产配置与测试配置必须分离（见 `../rules/testing.md`）。

## Test

```bash
python ../scripts/test-runner.py --json
```

跑 pytest，脚本会把失败分类为 L1–L6。要求全绿；有失败进入 Recover。测试可测试性要求见 `../rules/testing.md`（时间常量可注入、Mock 外部依赖、生产/测试配置分离）。

## Recover（自救，上限 3 轮）

测试失败 → 读完整错误 → 分类（编译/断言/依赖/环境/真实 Bug/无法确定）→ 尝试修复 → 重测。用脚本记录轮数：

```bash
python ../scripts/recovery.py record-failure   # 本轮失败 +1
python ../scripts/recovery.py status           # 查看当前轮数
python ../scripts/recovery.py record-success   # 修复成功后清零
python ../scripts/recovery.py reset            # 手动清零
```

`MAX_RECOVERY_ATTEMPTS = 3`。连续失败达到 3 轮：立即停止修改，不允许 Push，由 `recovery.py` 生成 `.safecode/diagnostic-report.md`，并请求人工确认。不要陷入改坏→修坏循环。

错误等级与对应行为见 `../rules/recovery.md`：

- L0 正常 / L1 普通测试失败（自动修复） / L2 编译失败（定位修复） / L3 环境异常（尝试恢复） / L4 工作区异常（停并恢复 checkpoint）
- **L5 安全风险：立即停止，不得继续**
- **L6 无法确定：停止并请求人工确认**

## Security Scan（Push 前必跑）

```bash
python ../scripts/security-scan.py --staged --json
```

扫描待提交内容中的 Secret（API key/token/cookie/session/私钥/`.pem`/`.key`/`.env`/数据库凭据/Bilibili `SESSDATA`、`bili_jct` 等）。退出码 0=通过、1=有发现、2=错误。

规则与降误报策略见 `../rules/security.md`。要点：

- 结合字段名、值格式、高熵、是否测试文件、是否明显占位符（`YOUR_API_KEY_HERE`/`example-token`/`test-secret`）判断，不把出现 `token`/`key`/`password` 字样的一律判泄露。
- 发现真实凭据：立即阻止 Push；仅工作区的删除/替换，已进 Git 的先撤销或轮换凭据再谈清历史。
- **L5 一律停止。**

## Review Diff

```bash
git diff
git diff --cached
```

确认本次只有预期改动，检查新增文件是否夹带凭据、大文件或意外产物。配合 `../rules/git.md` 的 Push 前检查链自查：工作区状态 → 分支 → Diff → 新增文件 → 测试 → 安全扫描 → 无危险操作。

## Push

推送前跑总门禁（也可挂 `git-guard.py --pre-push` 到 pre-push hook）：

```bash
python ../scripts/git-guard.py --pre-push
python ../scripts/pre-push.py
```

`pre-push.py` 会依次验证：状态 → 分支 → Diff → 新增文件 → 测试 → 安全扫描 → 允许 Push。

以下高危操作**未获用户明确授权不得自动执行**（见 `../rules/git.md`）：

- `git push --force` / `--force-with-lease`
- 删除或改写 Git 历史（`reset --hard` 到未知提交、`filter-branch`、改写已推送历史等）
- 删除大量项目文件
- 改生产环境、上传私人数据、把本地服务暴露公网

任何拿不准的情况，停止并请求人工确认。L5/L6 不得自行猜测后继续。
