# rules/security.md — 安全规则（软约束）

这份文档写给 Agent 读。真正拦人的是 `scripts/`，不是这里的句子。凡是这里写了
"必须停止"，对应脚本里必须有会返回非零退出码的检查。

## Push 前必须扫描

跑 `python scripts/security-scan.py --staged`（或统一的 `safecode security scan`）。
它扫的是**本次实际准备提交的内容**：

```bash
git status
git diff
git diff --cached
# 以及尚未被 Git 跟踪的新文件
```

扫描对象：

- API Key / Access Token / GitHub Token / JWT
- Cookie / Session / Password
- 私钥、`.pem`、`.key`、`.p12`、`.env`
- 云服务凭据、数据库连接串
- Bilibili `SESSDATA`、`bili_jct`
- 被跟踪的敏感文件本身

## Native Rules 与 External Scanner 分层

SafeCode 自己拥有的是 Native Rules：统一结果协议、配置校验、核心 Git/Push 策略、
专属高风险凭据（`SESSDATA`、`bili_jct` 等）、指纹与 Baseline、Gate 与 Resolver。

成熟检测能力不重复造：`gitleaks`、`trufflehog`、`detect-secrets` 存在就包装起来用，
统一调用方式、超时、输出解析、指纹与结果映射。

- 外部 Scanner 可用：正常增强扫描。
- 外部 Scanner 不可用：`DEGRADED`。本地非严格模式可以继续，但**这不是 PASS**；
  STRICT / CI 一律 DENY。
- 外部 Scanner 启动失败、异常退出、超时、输出无法解析：不是"没发现问题"，
  按检查失败处理。

第一天本机什么工具都没装也能开发，CI 上必须严格——这两件事靠上面的分层同时成立。

## 误报

不要简单地搜 `token`、`key`、`password`。判定要结合字段名、值格式、是否高熵、
是否像真实凭据、是否在测试/示例文件、是否已被 Git 跟踪。

这些应该放过：

```
YOUR_API_KEY_HERE
YOUR_TOKEN_HERE
sk-test-example-xxxx
password = "example"
token = "test"
```

测试样例、文档示例、fixture 里的假凭据请用明显的占位符。真想保留一个看起来像真的
值，就写进 `allow_list`，带 `reason`，必要时带 `expires`——这是唯一被接受的例外形式。

## Baseline / Fingerprint

Baseline 处理的是"已知、已审计、明确接受"的结果，不是关闭检查。

```
fingerprint = sha256(rule_id + normalized_path + finding_type + normalized_match_identity)
```

- NEW finding -> DENY
- KNOWN + 指纹未变 + 明确批准 -> 可按项目策略允许
- 同 rule 同 path 但指纹变了 -> NEW -> DENY
- finding 换了路径 -> 默认 NEW -> DENY
- Baseline 文件损坏 / 不可读 -> DENY

Baseline 文件要进 Git、可审计、每条有 reason、支持 expires，不允许通配符关掉规则，
不允许写入 Secret 明文。改动 Baseline 本身应走 Review。

## 首次接入必须扫历史

第一次给已有项目装 SafeCode 时，只扫当前 Diff 是不够的：

```
Full Repository Scan + Git History Scan
    -> 发现历史遗留问题
    -> 修复，或明确建立 Baseline
    -> 进入正常工作流（之后主要扫 Diff）
```

否则会出现"2024 年的 Secret 还在历史里，2026 年只改 README，Diff 扫描却是 PASS"。

shallow 仓库无法完成完整历史扫描时 Fail-Closed：先 `git fetch --unshallow`，
再重新扫描。不得以"现有 shallow 历史里没发现 Secret"作为 PASS。

## 发现真实凭据怎么处理

原则：**从文件里删掉 Secret，不等于 Secret 已经安全。**

还没进 Git：

```
阻止 Push -> 移除/替换 -> 重新扫描 -> 重新测试 -> 继续
```

已经 commit 但没 push：

```
阻止 Push -> 移除/替换 -> 清理当前提交/分支历史中的敏感内容 -> 重新扫描
```

已经 push 到远端：按**已经泄露**处理。

```
立即阻止继续 Push
 -> Revoke / Rotate 凭据（优先于一切清理动作）
 -> 检查 Git History 与远端
 -> 评估是否需要 Rewrite（HIGH RISK，需人工确认）
 -> Rewrite 后重新扫描
 -> 确认旧凭据已失效
```

Git History Rewrite 只解决"历史内容暴露"，替代不了凭据轮换，也不能让已推送的凭据
变回安全。Rewrite 会影响协作中的其他仓库使用者，不允许 Agent 静默执行。

## 配置不能被用来关掉安全

`.safecode.yml` 可以降低误报、定义明确例外、调整预算，但不能关掉核心不变量：

- `security.native.enabled: false` 直接判配置非法
- `allow_list` 里的 `rule: "*"` 或 `path: "*"` 直接判配置非法
- `ignore_paths` 不得覆盖 `.git`、Git History 或仓库根
- 配置解析失败、Schema 非法、类型错误 -> `exit 2 + FAIL + DENY`

`allow_list` 也不能覆盖这些：Scanner 不可用、Scanner 执行异常、输出无法解析、
Schema 无效、Hard Stop、Git Guard 失败、CI 失败。
