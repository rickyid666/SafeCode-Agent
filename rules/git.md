# rules/git.md — Git 规则（软约束）

## Push 前检查链

```
工作区状态 -> 当前分支 -> Diff -> 新增文件 -> 测试
 -> 安全扫描 -> 依赖检查 -> 确认没有危险操作 -> 允许 Push
```

入口是 `python scripts/pre-push.py`（或 `safecode pre-push`）。它把每个 Gate 的
Structured JSON 与退出码交给 Decision Resolver 汇总，取最严格的结果。

Git Guard 至少要看这些：

```
branch / git status / staged diff / unstaged diff
untracked files / recent commits / outgoing push content
```

## 高危操作

这些默认不允许 Agent 自动执行：

- `git push --force`（以及任何等价写法）
- `git reset --hard` 到未知提交
- 历史改写：`filter-branch`、`filter-repo`、交互式 rebase
- 大量删除文件 / 删除 Git 历史
- 修改生产环境、删除生产数据
- 上传私密数据、把本地服务暴露到公网
- 任何不可恢复的数据删除

命中之后不是"建议问一下"，而是可执行的 Hard Stop：

```
Agent 请求执行高危操作
 -> SafeCode Preflight
 -> risk = HIGH
 -> HARD STOP
 -> 输出 Structured Authorization Request
 -> 停止当前流程
```

## Hard Stop 不阻塞等待输入

SafeCode 负责判断风险、阻止操作、输出结构化授权请求、停止流程。
展示授权请求、拿到人工批准、决定怎么重新执行，是宿主环境的事。

因此 Hard Stop 的语义是"停止当前流程"，不是"卡在那里等 stdin"。CI、Cron、
后台 Agent 这类无人值守环境必须能直接退出，不能挂住。

## 授权必须绑定具体操作

"用户说可以"不算授权。授权绑定到操作指纹：

```
operation_fingerprint = sha256(
    规范化后的操作 + 仓库身份 + 仓库状态 + 目标 + 相关 diff
)
```

所以：

```
批准 force push A  !=  批准 force push B
```

改一个参数就要重新授权。Approval Token 的字段：

```json
{
  "schema_version": "1.0",
  "token_type": "APPROVAL",
  "operation": "git push --force",
  "operation_fingerprint": "sha256:...",
  "approved_by": "human",
  "issued_at": "2026-09-16T00:00:00Z",
  "expires_at": "2026-09-16T00:10:00Z",
  "nonce": "..."
}
```

验证时必须检查：`token_type`、`operation`、`operation_fingerprint`、有效期、
nonce 是否已用过、仓库/目标绑定。以下一律拒绝：过期、已使用、指纹不匹配、
操作参数变化、仓库或目标不匹配、格式无效。

Token 只授权"已明确描述的单一操作"，不能变成永久解锁 SafeCode 的开关。

## 三层防线，缺一层就等于没有

```
Tier 1  .git/hooks/pre-push -> scripts/pre-push.py   本地
Tier 2  GitHub Actions: test / security / dependency CI
Tier 3  Branch Protection: Required status checks    服务端
```

- 删掉本地 hook 只会让本地保护失效，CI 仍然会拦。
- `git push --no-verify` 可以绕过客户端 hook，因此它**不得被视为安全流程通过**；
  出现即记录为绕过事件。
- CI 跑过了，但对应 job 没被配成 Required Check，就不能声称"Push/Merge 已被服务端强制保护"。

SafeCode 提供 hook 的 install / verify / update 三种生命周期操作。verify 要检查：
`core.hooksPath` 是否指向 `.githooks`、hook 是否存在、是否可执行、是否还在调用当前
SafeCode 版本、有没有被别的脚本替换。

## 受保护分支

`main` / `master`（配置 `git.protected_branches`）默认不接受直推。但它不是
"不可逆的危险操作"，所以处理方式是 **REQUIRE_APPROVAL**，而不是硬拒绝：

```
push 到受保护分支
 -> git-guard 输出结构化授权请求（含 operation_fingerprint）
 -> 阻断本次 push（exit 1，decision=REQUIRE_APPROVAL）
 -> 人工复核后签发一次性 Approval Token
 -> 带着 token 重跑同一个 push -> 指纹匹配、nonce 未用过 -> 放行
```

授权请求里的 `metadata.operation`（例如 `git push refs/heads/main`）就是要拿去签发的
操作字符串；`metadata.operation_fingerprint` 绑定仓库身份、HEAD、目标分支与相关 diff。
换个分支、换个提交，指纹就变了，必须重新授权。

三个实操注意点：

- **签发与核销之间不要动工作区。** 指纹包含工作区是否脏，你在等待门禁跑完时改一个
  文件，token 就失效了（表现是回到 REQUIRE_APPROVAL，而不是报 token 无效——因为
  "指纹不匹配"按"该 token 不能授权本操作"处理）。
- **TTL 要大于门禁总耗时。** token 在流水线最后一步才被核销，前面还有测试；测试跑
  9 分钟的项目，默认 10 分钟就是卡边界，用 `--ttl 30`。
- **服务端还有一道 checks 的门，token 通过不等于推送成功。** Branch Protection 里配了
  Required status checks 之后，服务端要求被推的 commit 本身已经拿到这些 check 的
  success，否则回 `GH006: Protected branch update failed ... required status checks are
  expected`。所以直推 main 的完整流程是两段：

  ```bash
  git push origin HEAD:refs/heads/ci/<topic>   # 先让这个 sha 在 CI 上跑出 test/security
  git push origin main                         # checks 满足后再推，本地 gate + token 照走
  ```

  实测证据：本地门禁全绿、token 指纹匹配、git-guard 返回 ALLOW 的那次推送，仍被服务端
  以 GH006 拒掉；把同一 sha 推到 `ci/<topic>` 等 CI 绿了再推 main 就通过了。

这里没有"裸环境变量开关"。一个 `SAFECODE_ALLOW_MAIN=1` 之类的开关等于永久解锁，
和"授权必须绑定具体操作"直接冲突，所以不存在。要让某个分支彻底不受这条限制，
就把它从 `git.protected_branches` 里去掉——这是配置文件里的显式决定，可审计。

## Checkpoint

改高风险代码之前：

```bash
git status && git branch --show-current && git diff
```

必要时建临时分支或先 commit 一个可恢复点。修不回来时优先恢复到已知安全状态，
而不是继续往上堆修改。

## 提交内容本身也要过检查

- 只检查"本次实际准备提交的内容"，不要拿整个工作区的历史噪音当结论。
- 大批量删除、重命名、二进制大文件、`.env` 之类敏感文件被纳入版本管理，
  都要在 Diff 审查阶段明确看到，不能"顺手提交"。
