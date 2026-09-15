# Git 门禁与禁止的高危操作

本规则约束 SafeCode Agent 在提交与推送前后的 Git 行为，核心是把危险操作拦在 Push 之前。

## Push 前检查链

推送前必须按顺序走完以下检查，任何一环不过都不允许 Push：

```text
工作区状态
 ↓
当前分支
 ↓
Diff
 ↓
新增文件
 ↓
测试
 ↓
安全扫描
 ↓
确认没有危险操作
 ↓
允许 Push
```

对应脚本：

```bash
git status                                  # 工作区状态
git branch                                  # 当前分支
git diff ; git diff --cached                # Diff 与已暂存
# 列出未跟踪但将被提交的文件（新增文件）
python scripts/test-runner.py               # 测试
python scripts/security-scan.py --staged    # 安全扫描
python scripts/pre-push.py                  # 总门禁
```

`scripts/pre-push.py` 会依次验证：状态 → 分支 → Diff → 新增文件 → 测试 → 安全扫描 → 允许 Push。建议把它接入 `git push` 流程，也建议把 `git-guard.py --pre-push` 挂到仓库的 pre-push hook 上。

## 禁止自动执行的高危操作

除非用户明确授权，否则 Skill 不得自行执行：

- 删除大量项目文件
- 删除 Git 历史
- 强制 Push（`git push --force` / `--force-with-lease`）
- `git reset --hard` 到未知提交
- 修改生产环境
- 上传私人数据
- 暴露本地服务到公网
- 删除凭据以外的用户数据

清理 Git 历史（如 `filter-branch`、`git rebase` 改写已推送历史）属于高危操作，必须在发现凭据泄露且用户明确授权后进行，并优先完成凭据轮换（见 `rules/security.md`）。

## checkpoint（可恢复点）

进行高风险修改前，记录当前状态以便回滚：

```bash
git status
git branch
git diff
```

必要时建立 checkpoint 或临时分支：

```bash
git stash                       # 暂存当前改动
git checkout -b fix/xxx-tmp     # 临时分支隔离实验性修改
git commit -m "checkpoint: ..." # 明确标注的临时提交
```

后续若无法可靠修复，优先恢复到上述已知安全状态：

```bash
git checkout <原分支>
git stash pop                   # 或 git reset 回 checkpoint
```

不要留着一堆半成品改动继续堆新改动。L4 工作区异常时，按 `rules/recovery.md` 停止并恢复 checkpoint。

## 与脚本的对应关系

```bash
# 配合 git pre-push hook，检测强推/历史改写等危险操作
python scripts/git-guard.py --pre-push

# 总门禁：状态 → 分支 → Diff → 新增文件 → 测试 → 安全扫描 → 允许 Push
python scripts/pre-push.py
```

遇到拿不准的 Git 操作，停止并请求人工确认。
