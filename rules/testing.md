# 测试优先级与可测试性设计

本规则约束 SafeCode Agent 的自动化测试策略。测试优先覆盖核心业务逻辑，而不是一上来追求 UI 全覆盖。

## 测试优先级

1. 核心逻辑单元测试
2. 状态机测试
3. 多任务 / 并发测试
4. Web E2E
5. CLI E2E
6. Android / 桌面端构建测试

先保证 1–3 稳定，再做 4–6 的端到端验证。

## 可测试性设计

不要把等待时间硬编码进业务逻辑。把时间、Sleep、网络请求等外部依赖抽象出来，使测试可以注入更短的值或 Mock。

反例（生产写死，测试跑得慢且不可控）：

```python
LIKE_INTERVAL = 1.0
WAIT_LIVE_INTERVAL = 5.0
RETRY_INTERVAL = 3.0
REQUEST_TIMEOUT = 10.0
```

正例（常量可注入，测试用小值）：

```python
LIKE_INTERVAL = 1.0
WAIT_LIVE_INTERVAL = 5.0
RETRY_INTERVAL = 3.0
REQUEST_TIMEOUT = 10.0

# 测试环境覆盖为更短的值
LIKE_INTERVAL = 0.01
WAIT_LIVE_INTERVAL = 0.01
RETRY_INTERVAL = 0.01
```

更理想的方式是把时间、Sleep、网络请求等外部依赖抽象成可替换的接口，测试时注入 Mock，而不是只靠调小常量。

**生产配置与测试配置必须明确分离。** 测试用假凭据、短间隔、Mock 后端；生产用真实配置。不要把测试配置误带进生产分支。

## 推荐核心测试清单

至少覆盖：

- 单任务启动
- 单任务停止
- waiting 状态
- waiting → running 转换
- running → stopped 转换
- 开播轮询
- 异常重试
- 任务取消
- 多房间互不污染（并发隔离）
- 请求闸门（限流/并发控制）
- 配置错误
- 网络异常

## Web E2E 流程

```text
启动 Web
 ↓
创建任务
 ↓
waiting
 ↓
模拟开播
 ↓
running
 ↓
模拟点赞
 ↓
停止
 ↓
stopped
```

## CLI E2E 流程

```text
启动 CLI
 ↓
传入房间
 ↓
创建任务
 ↓
模拟开播
 ↓
running
 ↓
停止
 ↓
正常退出
```

## 与脚本的对应关系

```bash
python scripts/test-runner.py --json
```

`test-runner.py` 跑 pytest，并把失败分类为 L1–L6（见 `rules/recovery.md`）。测试全绿后才允许进入安全扫描与 Push；有失败先走自愈流程。
