# SafeCode Agent

给 AI Coding Agent 加一层真正可执行的安全工程护栏。

SafeCode 不是一段"让 AI 注意安全"的提示词，也不是又一个 Secret Scanner。它是一套
**可执行的 Gate**：在 Agent 连续写代码、跑测试、失败自救、提交推送的过程中，把
"危险操作必须刹车"和"没通过检查就不能进 Git"变成退出码，而不是建议。

```
Agent 修改
  -> Code Check      -> 测试        -> Security Gate
  -> Dependency Gate -> Diff 审查   -> Git Guard
  -> Decision Resolver -> 允许 / 阻断 / 需人工授权
  -> Local Hook -> CI Required Check -> Branch Protection -> Push
```

## 核心原则

**Soft Rules 与 Hard Gates 分离。** `rules/` 是给 Agent 读的说明书，`scripts/` 是门禁。
安全性不能建立在"AI 会遵守提示词"上：Agent 说"我检查过 Secret 了"是不可信的，
`security-scan.py` 的退出码才是可信的。

**Fail-Closed。** 安全检查无法完成 ≠ 安全检查通过。Scanner 不存在、启动失败、
异常退出、超时、输出无法解析、状态未知，全部走失败路径。只有明确、可验证的成功
才算 PASS。

**status 与 decision 分离。** `status` 说"程序/检查做得怎么样"（PASS / FAIL / DEGRADED），
`decision` 说"SafeCode 允不允许下一步"（ALLOW / DENY / REQUIRE_APPROVAL）。
`DEGRADED` 永远不等于 PASS：本地非严格模式可以继续，CI / `--strict` 一律 DENY。

**不确定就不放行。** 无法确认影响的操作按 L6 处理（Hard Stop + 要求人工授权），
不允许 Agent 猜一个结论继续往下跑。

## 快速开始

作为 Skill 安装：

```bash
git clone https://github.com/rickyid666/SafeCode-Agent
# 把 skill/SKILL.md 与 rules/ 挂到你使用的 Agent 的 skill 目录
# 脚本按需直接调用，无需安装：
python scripts/security-scan.py --all
```

接通本地门禁（Push 时真正会被拦）：

```bash
python scripts/hook-manager.py install
python scripts/hook-manager.py verify
```

日常使用：

```bash
python scripts/safecode.py security scan --staged     # Secret / 敏感文件
python scripts/safecode.py security baseline --reason "audited fixture"
python scripts/safecode.py dependency check           # 供应链
python scripts/safecode.py test run                   # 测试 + Flaky 检测
python scripts/safecode.py git guard --status         # Git 状态与危险操作
python scripts/safecode.py pre-push                   # 全量门禁流水线
python scripts/safecode.py recover status             # 自救预算
```

所有脚本都可以独立执行（CI 里通常直接调单个脚本），也都支持统一入口。

推到受保护分支（默认 `main` / `master`）时会被要求人工授权，走一次性 token：

```bash
# 1. 先推一次，会被拦下：stderr 上给出 REQUIRED_APPROVAL 与 operation
git push

# 2. 人工复核后签发一次性 token（默认 10 分钟有效，只能核销一次）
python scripts/safecode_approval.py issue --operation "git push refs/heads/main" \
    --approved-by human --ttl 10 > /tmp/safecode-token.json

# 3. 带 token 重跑同一个 push
SAFECODE_APPROVAL_TOKEN=/tmp/safecode-token.json git push
```

token 绑定 `operation + 仓库身份 + HEAD / 工作区状态 + 目标分支`：换个分支、换个提交、
改一个参数，指纹就变了，必须重新授权。想彻底放开某个分支，就把它从
`.safecode.yml` 的 `protected_branches` 里去掉——没有"绕过一次"的裸开关。

## CLI 契约

```
safecode security scan        -> scripts/security-scan.py
safecode security baseline    -> scripts/security-scan.py --write-baseline
safecode dependency check     -> scripts/dependency-guard.py
safecode test run             -> scripts/test-runner.py
safecode recover              -> scripts/recovery.py
safecode git guard            -> scripts/git-guard.py
safecode pre-push             -> scripts/pre-push.py
safecode hook install|verify|update
safecode approve              -> scripts/git-guard.py approve
safecode decision             -> scripts/decision-resolver.py
```

公共参数：`--config PATH`、`--json`、`--strict`、`--quiet`、`--verbose`、
`--baseline PATH`、`--task-id ID`。

输出约定：**stdout 只有一个 Structured JSON 对象**，人类日志一律写 stderr。
`--json` 时人类日志完全静默，stdout 保持可直接解析。

退出码：

```
0 = 程序执行成功（是否允许继续看 JSON decision + Policy Mode）
1 = 检查明确发现安全/策略问题（含 REQUIRE_APPROVAL 的阻断）
2 = 参数或配置错误
3 = 工具 / Scanner 执行失败
4 = 环境异常
```

## Structured JSON

```json
{
  "schema_version": "1.0",
  "status": "PASS",
  "decision": "ALLOW",
  "severity": "LOW",
  "category": "SECURITY",
  "code": "CHECK_PASSED",
  "message": "Check completed successfully",
  "locations": [],
  "metadata": {}
}
```

正式 Schema 在 `schemas/result-1.0.json`，配置 Schema 在 `schemas/config-1.0.json`，
两者都由 `tests/` 实际校验（找不到 jsonschema 库时用内置的结构化校验器，结论一致）。

JSON 与退出码不一致时取更严格的一方，由 `decision-resolver.py` 统一计算：

```
JSON decision + Exit Code + Policy Mode -> Effective Decision
ALLOW < REQUIRE_APPROVAL < DENY
```

## 项目配置 .safecode.yml

```yaml
schema_version: "1.0"

security:
  mode: default
  native:
    enabled: true
  external_scanners:
    enabled: true
    required_in_ci: true
    # 这份清单必须与 CI 实际安装的工具一致，否则严格模式会因"声明了但不可用"而 DENY
    tools:
      - detect-secrets
  ignore_paths: []
  allow_list: []

recovery:
  max_recovery_attempts: 3
  max_total_test_runs: 20
  max_total_recoveries: 10
  max_total_time: 30m

git:
  protected_branches: [main, master]
  allow_force_push: false
  allow_history_rewrite: false
```

`ignore_paths` 与 `allow_list` 是两件事，不能混用：

- `ignore_paths`：这些路径不进入某个明确声明的扫描范围，必须写进配置、可审计，
  不允许覆盖 `.git`、Git History 或仓库根。
- `allow_list`：某个具体规则的某个已知结果是被确认的例外，必须写
  `rule + path + reason`，可选 `fingerprint` 与 `expires`。`rule: "*"` 会被直接拒绝。

配置本身也是输入：解析失败、Schema 非法、类型错误、试图关闭核心不变量
（`native.enabled: false`、`allow_force_push: true` 等），一律 `exit 2 + FAIL + DENY`，
不会"忽略错误配置继续跑"。

内置的 YAML 解析器只支持 `.safecode.yml` 需要的语法子集（嵌套映射、列表、注释、
引号、布尔/整数/空值、空的 `[]`/`{}`）。锚点、别名、块标量、非空 flow 集合、
多文档一律报错——不猜值。

## 三层防线

```
Tier 1  .githooks/pre-push -> scripts/pre-push.py     本地门禁
Tier 2  GitHub Actions: test / security / dependency  CI Required Check
Tier 3  Branch Protection: Required status checks     服务端强制
```

三层不是同一个脚本部署三次，而是避免单点绕过：删掉本地 hook 仍会被 CI 拦，
CI 通过但没设成 Required Check 就挡不住直接 merge。客户端 hook 挡不住
`git push --no-verify`，所以 SafeCode 不声称本地 hook 是唯一边界——CI 必须
把 `test`、`security` 配成 Required status checks。

### 分支保护怎么配

仓库设置 -> Branches -> 保护 `main`，勾选 Required status checks，填上 job 名：

```
test          .github/workflows/test.yml     单元 / 黑盒测试矩阵
security      .github/workflows/security.yml Secret 扫描（本地 + 外部 Scanner，严格模式）
dependency    .github/workflows/security.yml 依赖供应链
```

`security.yml` 里两个 job 分别是 `security` 与 `dependency`，`test.yml` 里是 `test`。
注意 job 名（`name:` 字段）才是 Required check 里要填的值，光有 workflow 文件不等于
它是 Required check。建议同时关掉 "Allow force pushes" 与 "Allow deletions"。

## Rule → Detection → Gate → Test

每条规则都能追溯到"谁检测、谁拦、谁测"。新增规则时必须同步补齐这四列。

| Rule | Detection | Interception Layer | Test |
|---|---|---|---|
| Secret detected | Native rules + external scanners | Security Gate / pre-push / CI | `test_security.py` |
| Scanner unavailable | scanner wrapper | Decision Resolver / CI | `test_security.py`, `test_dependency.py` |
| Invalid scanner output | JSON parser | Security Gate | `test_security.py` |
| Baseline mismatch / moved path | fingerprint engine | Security Gate | `test_security.py` |
| Shallow history | git history detector | Security Gate | `test_security.py` |
| Dependency drift | `dependency-guard.py` | Dependency Gate / CI | `test_dependency.py` |
| Undeclared dependency | lockfile root vs manifest | Dependency Gate | `test_dependency.py` |
| Invalid `.safecode.yml` | config validator | Policy Engine（exit 2） | `test_config.py` |
| Core invariant disabled in config | config validator | Policy Engine | `test_config.py` |
| Force push | Git Guard | Hard Stop / Hook / CI | `test_git_guard.py` |
| History rewrite | Git Guard | Hard Stop + Approval | `test_git_guard.py` |
| Invalid / expired / replayed approval token | token verifier | Hard Stop | `test_git_guard.py` |
| Operation fingerprint mismatch | fingerprint verifier | Hard Stop | `test_git_guard.py` |
| Missing / tampered hook | hook verifier | Local defense / CI policy | `test_git_guard.py` |
| Test failure | Test Runner | Recovery | `test_runner.py` |
| Flaky test | reproducible rerun algorithm | Recovery policy | `test_runner.py` |
| Budget exhausted | Persistent Budget | Recovery stop | `test_recovery.py` |
| Schema invalid / missing result | result validator | Decision Resolver | `test_schema.py` |
| JSON vs exit code conflict | Decision Resolver | all gates | `test_schema.py` |
| CI failure | Required check | Branch Protection | CI workflows |

## 反复用到的两个机制

**Baseline / Fingerprint。** 每个 finding 有稳定指纹
`sha256(rule_id + normalized_path + finding_type + normalized_match_identity)`，
`normalized_match_identity` 只存哈希前缀，Baseline 里不出现 Secret 明文。
新增 finding、指纹变化、路径变化都算 NEW -> DENY；只有指纹完全一致、未过期、
带 reason 的条目才放行。Baseline 不是关掉检查。

**Approval Token。** 危险操作（force push、历史改写、不可逆删除等）不是"问一句"，
而是 Hard Stop + 结构化授权请求，授权必须绑定
`operation_fingerprint = sha256(操作 + 仓库身份 + 仓库状态 + 目标 + 相关 diff)`。
令牌一次性、默认 10 分钟过期、绑定单一操作，改一个参数就重新要授权。
Hard Stop 不阻塞等 stdin，无人值守环境同样能直接退出。

### 外部 Scanner 声明必须与 CI 安装一致

严格模式 / CI 下，**声明了但不可用**的外部 Scanner 一律 DENY（Fail-Closed）。所以
`.safecode.yml` 的 `security.external_scanners.tools` 列表必须与
`.github/workflows/security.yml` 里真正安装的工具一致。本仓库只声明
`detect-secrets`（PyPI 安装，最稳），要加 `gitleaks` / `trufflehog` 就同时把安装
步骤加进 workflow，否则下次推送就红了。

本地没装任何外部 Scanner 时不会挡住开发：那是 `DEGRADED`，本地可以继续，但
`DEGRADED` 不是 PASS。

### 本仓库自己的例外

SafeCode 要求"例外必须显式、可审计"，它对自己也执行这一条。仓库的 `.safecode.yml`
里有几条 `allow_list`，针对的是启发式外部 Scanner 在 SafeCode 自己身上必然误报的位置：
检测器源码里的占位符词表、文档里的示例写法、测试夹具（值为运行时拼接的合成值）。
每条都限定 `rule + path` 并写明原因，既不是通配也不影响 Native 规则的检测范围。

## 仓库结构

```
SafeCode-Agent/
├── .safecode.yml            本项目自身的配置（self-hosting）
├── schemas/                 result-1.0.json / config-1.0.json
├── skill/SKILL.md           Agent 工作协议
├── rules/                   security / testing / recovery / git
├── scripts/
│   ├── safecode.py          统一 CLI 入口（路由）
│   ├── safecode_common.py   结果协议 / 退出码 / Resolver / Reporter
│   ├── safecode_config.py   .safecode.yml 解析与校验
│   ├── safecode_secret.py   规则集 / 指纹 / Baseline
│   ├── safecode_scanners.py 外部 Scanner 包装
│   ├── safecode_budget.py   Persistent Budget
│   ├── safecode_approval.py Approval Token / Operation Fingerprint
│   ├── security-scan.py     Security Gate
│   ├── dependency-guard.py  供应链 Gate
│   ├── git-guard.py         Git Guard / Hard Stop
│   ├── test-runner.py       测试 + Flaky 检测
│   ├── recovery.py          自救预算
│   ├── hook-manager.py      Hook install / verify / update
│   └── pre-push.py          总门禁流水线
└── tests/                   黑盒测试：断言 JSON 与退出码，不断言实现细节
```

## 测试

```bash
python -m pytest tests/ -v
```

测试以黑盒为主：通过 subprocess 调 CLI，断言 Structured JSON 与退出码。
外部 Scanner 用 PATH 桩（假的 `gitleaks`/`osv-scanner` 可执行文件）测试，
所以不装任何工具也能验证"Scanner 异常必须 DENY"这条不变量。

## 实现取舍（契约没有明说、但必须做决定的地方）

1. **REQUIRE_APPROVAL 的退出码。** 契约说 `Exit != 0 -> 至少 DENY`，又说
   REQUIRE_APPROVAL 表示"程序正常完成、策略要求授权"。两者直接叠加会把授权路径
   压成 DENY，让 Approval Token 机制失效。这里的处理是：REQUIRE_APPROVAL 一律
   `exit 1`（阻断通道，Git 必须拦下来），JSON 里保留 `decision=REQUIRE_APPROVAL`，
   Resolver 对 `status=PASS + decision=REQUIRE_APPROVAL` 保留授权语义，不做降级。
   也就是说：**它一定是阻断的，但不是不可挽救的阻断。**
2. **受保护分支直推是可授权的，不是硬拒绝。** 直推 `main` 会拿到结构化授权请求
   （`PROTECTED_BRANCH_APPROVAL_REQUIRED` + operation fingerprint），人工复核后签发
   一次性 token 即可放行。没有 `SAFECODE_ALLOW_MAIN=1` 这类裸开关——那等于永久解锁，
   和"授权必须绑定具体操作"冲突。想彻底放开某个分支就从 `protected_branches` 去掉。
3. **测试文件不再自动降级。** 上一版把测试/示例文件里的疑似凭据降级为 info 放过。
   那等于给"把真凭据写进测试文件"留了后门。现在只有占位符形态的值不算 finding，
   其余一律按真实 finding 处理，需要例外就写 `allow_list`（带 reason）或 Baseline。
4. **自救预算耗尽用 `exit 1`。** 新契约的退出码只有 0-4，没有给预算耗尽留位置。
   预算耗尽属于"策略问题"，因此 `exit 1 + code=BUDGET_EXHAUSTED + decision=DENY`，
   靠 JSON 的 `code` 与"发现 Secret"区分。
5. **`dependencies:` 配置段是扩展。** 契约的 v1.0 配置模型没有为 Dependency Guard
   定义配置，这里加了 `dependencies:`（`require_lockfile` / `forbidden_packages` /
   `allowed_registries` / `external_scanner`）。校验器允许未知顶层键，所以这不破坏
   v1.0 兼容性。
6. **没有 manifest 时依赖检查返回 PASS。** 仓库里没有任何依赖清单（没有
   package.json / pyproject.toml / go.mod / Cargo.toml）时，供应链没有检查对象，
   这是一次空检查而不是"跳过了检查"。有 manifest 但 Scanner 缺失时依旧按
   Fail-Closed 处理。

## License

MIT
