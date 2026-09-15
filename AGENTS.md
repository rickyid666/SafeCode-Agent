# AGENTS.md — 在本仓库工作的 AI Agent 守则

本文件约束任何在本仓库（SafeCode Agent）内工作的 AI Agent。规则面向 Agent 自身，不面向人类读者。违反任一条都可能直接损害仓库或泄露凭据。

## 1. 先检查，再改

动手修改前必须确认当前状态：

- 当前 Git 分支
- 工作区状态（`git status`）
- 最近提交与当前 Diff
- 项目构建与测试方式
- 项目规则文件：`AGENTS.md`、`skill/SKILL.md`、`rules/`、`tests/`

不得在不了解项目状态的情况下直接大规模修改。不清楚构建或测试入口时，先读 `README.md` 和 `rules/testing.md`，不要凭直觉猜。

## 2. 唯一 Git 基准

以本仓库的实际 Git 工作区为唯一代码事实来源。所有测试、构建、提交都针对同一份工作区执行。不要一边改一个副本、一边测另一个副本。

## 3. 修改前保留 checkpoint

进行高风险修改前，先记录可恢复点：

```bash
git status
git branch
git diff
```

必要时建立 checkpoint、临时分支或 commit。后续若无法可靠修复，优先恢复到已知安全状态，而不是继续堆叠修改。

## 4. 测试失败自救上限 3 轮

测试失败后先读完整错误、做分类，再尝试修复并重测，用 `scripts/recovery.py` 记录轮数：

```bash
python scripts/recovery.py record-failure   # 本轮失败 +1
python scripts/recovery.py status           # 查看当前轮数
python scripts/recovery.py reset            # 修复成功后清零
```

`MAX_RECOVERY_ATTEMPTS = 3`。连续失败达到 3 轮，立即停止修改，不允许 Push，并按 `rules/recovery.md` 输出 `.safecode/diagnostic-report.md`。不要陷入“改坏 → 修坏”循环。

## 5. Push 前必跑两道关

推送前必须依次通过：

```bash
python scripts/test-runner.py      # 测试全绿
python scripts/security-scan.py --staged   # 无真实凭据泄露
python scripts/pre-push.py        # 总门禁
```

任一关不通过，不允许 Push。Security Scan 发现真实 Secret 时立即阻止，按 `rules/security.md` 处理（已进 Git 的先轮换凭据，再谈清历史）。

## 6. 禁止未授权的高危操作

除非用户明确授权，否则不得执行：

- `git push --force` / `--force-with-lease` 强推
- 删除或改写 Git 历史（`git reset --hard` 到未知提交、`filter-branch`、`rebase` 改写已推送历史等）
- 删除大量项目文件
- 修改生产环境
- 上传私人数据或把本地服务暴露到公网
- 删除凭据以外的用户数据

遇到不确定要不要做某件事，停下来请求人工确认。L5（安全风险）和 L6（无法确定）一律停止并交给人判断，不得自行猜测后继续。

## 7. 错误等级对照

按 `rules/recovery.md` 的 L0–L6 分级处理。L4 工作区异常时停止并恢复 checkpoint；L5/L6 立即停止并请求确认。
