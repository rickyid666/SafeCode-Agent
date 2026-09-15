# Push 前安全扫描规则

本规则约束 SafeCode Agent 在 Push 之前对待提交内容做 Secret 扫描。目标只有一个：不让真实凭据进远程仓库。

## 扫什么

扫描范围聚焦**本次实际准备提交的内容**，而不是整棵工作树。至少覆盖：

- API Key
- Access Token（含 GitHub Token）
- Cookie / Session
- 密码、私钥
- `.pem`、`.key` 文件
- `.env` 文件及其中内容
- 云服务凭据
- 数据库连接凭据
- 第三方会话凭据，例如 Bilibili 的 `SESSDATA`、`bili_jct`

同时把以下纳入检查，避免漏掉新增的敏感载体：

```bash
git status
git diff
git diff --cached
新增文件（untracked 但将被 add 的文件）
```

## 怎么降误报

不要把任何出现 `token`、`key`、`password` 字样的字符串都判为泄露。真实凭据要结合多个维度判断：

1. **字段名**：是否像凭据名（`api_key`、`secret`、`token`、`password`、`SESSDATA`、`bili_jct`、`private_key` 等）。
2. **值的格式**：是否符合该凭据的已知格式（JWT 三段式、GitHub token 的 `ghp_` 前缀、Base64/十六进制定长等）。
3. **高熵**：值是否足够随机、信息量大，而不是人类可读的短语。
4. **是否测试文件**：测试/示例代码里的假凭据权重应降低。
5. **是否占位符**：明显占位符不应报警，例如：

```text
YOUR_API_KEY_HERE
example-token
test-secret
```

判断逻辑建议：字段名像凭据 + 值格式匹配 + 高熵 + 非测试文件 + 非明显占位符，才判为真实泄露。只命中其中一两项（如仅出现 `key` 字样但值是一段普通英文）的，标记为可疑但不阻断，必要时请求人工确认。

## 发现真实凭据的处理流程

```text
发现 Secret
 ↓
立即阻止 Push
 ↓
判断是否进入 Git
 ├─ 仅工作区（未 add / 未 commit）
 │    ↓
 │  删除或替换为占位符
 │    ↓
 │  重新扫描
 │
 └─ 已 Commit / 已 Push
      ↓
      立即撤销或轮换该凭据（优先于一切清理动作）
      ↓
      评估 Git 历史泄露范围
      ↓
      必要时清理历史（需用户明确授权）
      ↓
      重新扫描
```

核心原则：**从文件里删掉 Secret，不等于 Secret 已经安全。** 一旦已经 Push 到远程，原凭据可能已被拉取或缓存，应优先撤销/轮换原凭据，再回头清理历史。清理历史属于高危操作，必须用户明确授权，不得自动执行。

## 与脚本的对应关系

```bash
python scripts/security-scan.py --staged --json
```

退出码：0=通过，1=有发现（真实或可疑凭据），2=运行错误。`--staged` 扫已暂存、`--worktree` 扫工作区、`--all` 全扫。Push 前用 `--staged`；人工全量排查可用 `--all`。

L5 风险在错误等级表中对应“安全风险”，发现真实凭据即属 L5：立即停止，不得继续 Push。
