# SafeCode Agent

一个面向 AI Coding Agent 的通用安全开发 Skill。它本身不替你写业务代码，而是给 Agent 套上一条能刹车的工程工作流：

```text
检查 → 修改 → 测试 → 失败自救 → 安全扫描 → Diff 审查 → Push → CI 再验证
```

让 Agent 可以连续开发、自动测试、失败自愈，同时在遇到安全风险、拿不准的问题或连续失败时自动停下，而不是蒙头乱改、把 Secret 推到远程、或者在不确定时执行高危 Git 操作。

## 项目定位

SafeCode Agent 不是某个具体项目的专属逻辑，而是一层可复用的安全工作流。任何支持 Skills 的 Agent 都能把它装进自己的开发流程里，得到同一套约束：

- 改之前先看清项目状态
- 所有操作围绕唯一 Git 基准
- 高风险修改前留 checkpoint
- 测试失败最多自救 3 轮
- Push 前必跑安全扫描和 pre-push 门禁
- 危险操作一律刹车，拿不准就问人

## 核心原则

1. **先检查，再修改。** 在不了解分支、工作区、Diff、构建与测试方式、项目规则文件（`AGENTS.md`/`CLAUDE.md` 等）之前，不得大规模改动代码。
2. **唯一工作基准。** 以实际 Git 仓库为唯一代码事实来源。测试、构建、提交都必须针对同一份仓库代码，避免“改了 A、测了 B”的假阳性/假阴性。
3. **修改前保留可恢复点。** 高风险改动前记录 `git status` / `git branch` / `git diff`，必要时建 checkpoint 或临时分支。修不回来就回到已知安全状态，而不是继续堆改动。

## 快速开始

### 作为 Skill 安装

把本仓库放进支持 Skills 的 Agent 的 skill 搜索路径，或使用对应安装命令加载 `skill/SKILL.md`（`name: safecode-agent`）。Agent 在开发任务开始时加载该 Skill，随后按 Plan → Inspect → Modify → Test → Recover → Security Scan → Review Diff → Push 的顺序工作。

### 脚本怎么跑

仓库 `scripts/` 下是可被 Skill 和本地手动调用的工具，统一用 Python 3 运行：

```bash
# 扫描待提交内容里的 Secret；退出码 0=通过 1=有发现 2=错误
python scripts/security-scan.py --staged --json

# 跑 pytest，并把失败分类成 L1-L6
python scripts/test-runner.py --json

# 配合 git pre-push hook，检测强推/历史改写等危险操作
python scripts/git-guard.py --pre-push

# 自救轮数计数；连续失败 3 轮后拒绝继续并生成 .safecode/diagnostic-report.md
python scripts/recovery.py record-failure
python scripts/recovery.py status
python scripts/recovery.py reset

# 总门禁：状态 → 分支 → Diff → 新增文件 → 测试 → 安全扫描 → 允许 Push
python scripts/pre-push.py
```

建议把 `git-guard.py --pre-push` 挂到仓库的 `pre-push` hook 上，把 `pre-push.py` 作为本地提交前/推送前的整体闸门。

## 仓库结构

```text
SafeCode-Agent/
├── README.md            # 本文件
├── LICENSE              # MIT
├── AGENTS.md            # 给在本仓库工作的 AI Agent 的守则
│
├── skill/
│   └── SKILL.md         # 可安装的 Agent Skill 定义
│
├── rules/
│   ├── security.md      # Push 前安全扫描规则
│   ├── testing.md       # 测试优先级与可测试性设计
│   ├── recovery.md      # 失败自救流程与错误等级
│   └── git.md           # Git 门禁与禁止的高危操作
│
├── scripts/
│   ├── security-scan.py # Secret 扫描
│   ├── git-guard.py     # 危险 Git 操作检测
│   ├── test-runner.py   # 测试运行与失败分级
│   ├── recovery.py      # 自救轮数计数与诊断报告
│   └── pre-push.py      # 推送前总门禁
│
├── tests/               # 上述脚本自身的测试
│
└── .github/workflows/   # CI：security.yml / test.yml
```

## CI 说明

CI 是 Agent 工作流在远端的兜底，不依赖 Agent 自觉。推荐的最终形态：

```text
Agent 修改
    ↓
代码检查
    ↓
单元测试
    ↓
集成测试
    ↓
Web E2E
    ↓
CLI E2E
    ↓
Security Scan
    ↓
Diff / Git 检查
    ↓
全部通过
    ↓
允许 Push / Merge
```

Release 则进一步走 Tag → Build → Test → Security Scan → Artifact → Release。

CI 只要有一环失败（尤其 Security Scan 或测试），就不允许合并或发布。本地已经跑过的检查，CI 再跑一遍是为了确认交给远端的是真实通过的状态。

## 项目目标

不追求让 AI “绝对不出错”，而是：让错误尽早暴露，让错误可以恢复，让危险操作能够刹车，让成功的修改经过测试和安全检查后再进入 Git。
