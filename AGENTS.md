# AGENTS.md — 在本仓库工作的 Agent 守则

这个仓库的产出是**门禁**，不是文档。任何"新增一条安全规则"的改动，如果只改了
`rules/*.md` 或 `SKILL.md`，等于没做：规则必须落到可执行检测、门禁和回归测试里。

## 开工前

```bash
git status --porcelain
git branch --show-current
git log --oneline -5
python scripts/safecode.py git guard --status
```

在不知道工作区状态、当前分支、最近提交的情况下不要开始大改。工作区代码与远端不一致时
先把基准对齐——**测试、构建、提交必须针对同一份仓库代码**，否则"改了 A、测了 B"。

## 改代码的规矩

1. 动手前记录 `git status` / `git diff`，必要时开临时分支或先 commit 一个可恢复点。
2. 改完跑测试：`python -m pytest tests/ -q`。
3. 失败先读完整错误再分类（L1 断言 / L2 编译 / L3 环境依赖 / L6 无法确定），
   不要看到红就开始改代码。
4. 同一处连续失败 3 次（`max_recovery_attempts`）就停手，输出诊断报告交给人工。
   不要陷入"改坏 -> 修坏 -> 再改坏"。
5. 不确定影响面的操作按 L6 处理：Hard Stop + 请求人工授权，不允许猜。

## 推送前

```bash
python scripts/safecode.py pre-push
```

它会依次跑 Diff 检查、Secret 扫描、依赖检查、测试、Git Guard，再由 Decision Resolver
汇总。任何一步 DENY / REQUIRE_APPROVAL 未获授权 / 无法完成，都不许 Push。

不要用 `git push --no-verify` 绕过本地 hook。它不会让 CI 变成 PASS，只会被记录成
绕过事件。

## 禁止自动执行（需要人工明确授权）

- `git push --force` / 任何形式的历史改写（`filter-branch`、`filter-repo`、交互式 rebase）
- `git reset --hard` 到未知提交
- 批量删除项目文件、删除 Git 历史
- 修改生产环境、删除生产数据
- 上传私人数据、把本地服务暴露到公网
- 任何不可逆的数据删除

这些操作在 SafeCode 里对应 L5 / L6：L5 直接 DENY，L6 输出结构化授权请求并停止。
要放行必须走 Approval Token 流程（绑定 operation fingerprint，一次性，默认 10 分钟过期）。

## 修改安全能力时的清单

新增或修改一条规则，必须同时给出四样东西，缺一不可：

```
Rule -> Detection -> Gate -> Regression Test
```

具体落到：

1. `scripts/safecode_*.py` 里的检测逻辑（Native 语义的放进 `safecode_secret.py` 或
   对应 Gate；外部工具包装放进 `safecode_scanners.py`）
2. 接入的门禁点（`security-scan.py` / `git-guard.py` / `dependency-guard.py` /
   `pre-push.py`，以及需要时 `.github/workflows/`）
3. `tests/` 里的回归测试（黑盒：断言 Structured JSON 与退出码）
4. `README.md` 的 Rule -> Detection -> Gate -> Test 表

只改文档不加测试的 PR 不应该合入。

## 不要破坏的不变量

- Native Security Gate Fail-Closed；检查无法完成一律不 PASS
- `exit != 0` 不得被解释为 ALLOW；JSON 与退出码冲突取更严格的一方
- Schema 无效不得 PASS；`status` 与 `decision` 必须分离
- `DEGRADED != PASS`；STRICT / CI 下 DEGRADED 必须 DENY
- Baseline 只接受指纹匹配、未过期、带 reason 的条目；路径变化视为 NEW
- 已 Push 的 Secret 先 Revoke / Rotate，再谈清理历史
- Hard Stop 不依赖 stdin 阻塞；Approval 必须绑定 operation fingerprint
- 核心不变量不得被 `.safecode.yml` 静默关闭

## 本仓库自身的约定

- 纯标准库，零第三方依赖（测试只用 pytest）。配置解析用内置 YAML 子集解析器，
  遇到不支持的语法直接 exit 2，不猜值。
- stdout 只有一个 JSON 对象；人类日志走 stderr；`--json` 时 stderr 静默。
- 退出码只用 0/1/2/3/4。
- 测试里不要写真实格式的凭据字面量（`sk-` + 32 位、`ghp_` + 36 位、完整 PEM 头等），
  需要样例就在运行时拼接，否则扫描器会扫到仓库自身。
- `.safecode/` 是运行时状态目录（budget / baseline / approvals / events），不要提交。
