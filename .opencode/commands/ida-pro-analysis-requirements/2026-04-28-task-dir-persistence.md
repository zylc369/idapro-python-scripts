# 上下文持久化方案：压缩后 TASK_DIR 精确恢复

> 日期: 2026-04-28
> 来源: 复盘 binary-analysis Agent 多次使用过程中，压缩后 TASK_DIR 丢失导致分析中断的问题
> 状态: Phase 0 方案文档

---

## §1 背景与目标

### 问题

BinaryAnalysis Agent 在分析过程中会动态创建任务目录（`$TASK_DIR`），所有中间文件写入该目录。当对话过长触发压缩时，LLM 总结器可能丢失 `$TASK_DIR` 的值，导致后续分析无法继续。

### 根因分析

```
信息流断裂点：

1. Agent 创建 TASK_DIR（shell 变量）
2. TASK_DIR 存在于对话历史中（文本）
3. 对话过长 → 触发压缩
4. LLM 总结器概括对话 → 可能丢失 TASK_DIR ← 断裂点
5. 压缩后 Agent 不知道 TASK_DIR → 分析中断
```

**核心矛盾**：TASK_DIR 是动态创建的运行时状态，不存在于任何持久化存储中，完全依赖 LLM 的记忆。

### 目标

1. **精确匹配**：每个 session 精确对应一个 TASK_DIR，多轮对话、多轮压缩后依然精确
2. **并发支持**：多个会话并行分析不同二进制，互不干扰
3. **用户可切换**：用户要求使用新任务目录时，映射自动更新
4. **不依赖 LLM 复制**：链路中不依赖 LLM 从文本中复制粘贴字符串

### 约束

- 不增加压缩上下文体积（不能扫描整个 workspace 注入）
- 改动范围可控，不引入新的架构层

---

## §2 技术方案

### API 能力调研（含 oh-my-openagent 参考）

#### OpenCode Plugin Hook API

| Hook | sessionID | 类型 | 调用时机 |
|------|-----------|------|---------|
| `experimental.session.compacting` | `input.sessionID` | `string`（必填） | 每次压缩前 |
| `experimental.chat.system.transform` | `input.sessionID` | `string?`（可选） | 每轮 LLM 调用前 |
| `shell.env` | `input.sessionID` | `string?`（可选） | Agent 执行 bash 命令时 |
| `event: session.created` | `properties.info.id` | `string` | 会话创建 |
| `event: session.deleted` | `properties.info.id` | `string` | 会话删除 |
| `event: session.compacted` | `properties.sessionID` | `string` | 压缩完成 |

#### oh-my-openagent 参考实现

| 模式 | 实现方式 | 文件 |
|------|---------|------|
| 状态持久化 | 内存 `Map<sessionID, State>` | 全局使用，纯内存 |
| compaction 恢复 | `capture(sessionID)` 保存 → `inject(sessionID)` 注入 → `session.compacted` 事件恢复 | `compaction-context-injector/hook.ts` |
| TODO 保存/恢复 | `capture(sessionID)` 快照 → `session.compacted` 事件 `restore(sessionID)` | `compaction-todo-preserver/hook.ts` |
| 环境变量注入 | `tool.execute.before` 修改 `output.args.command`（在命令前加 export） | `non-interactive-env/non-interactive-env-hook.ts` |
| 文件持久化（唯一例外） | `~/.local/share/opencode/storage/interactive-bash-session/{sessionID}.json` | `interactive-bash-session/storage.ts` |

#### 关键结论

1. **sessionID 在 compaction 前后不变** — oh-my-openagent 所有恢复逻辑都基于同一 sessionID
2. **shell.env 可以注入环境变量到 Agent 的 bash 进程** — oh-my-openagent 没使用此 hook，但 `@opencode-ai/plugin` 接口支持
3. **oh-my-openagent 没有 "session → 工作目录" 映射** — 因为它假设所有 session 在同一项目目录下。我们需要这个映射是因为每个分析任务有独立的 TASK_DIR

### 方案：sessionID 映射 + shell.env 注入 + 映射自动更新

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  A. shell.env hook（Agent 每次执行 bash 时触发）                     │
│     → Plugin 注入 SESSION_ID=<sessionID> 到环境变量                 │
│     → Agent 的 bash 进程中 $SESSION_ID 自动可用                     │
│     → Agent 的 Python 脚本通过 os.environ['SESSION_ID'] 读取        │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  B. Agent 创建 TASK_DIR（或切换到新目录）                            │
│     → Python 脚本从环境变量读取 SESSION_ID                           │
│     → 写 .task_sessions/{sessionID}.json                           │
│     → 同一 session 多次执行会覆盖旧值（用户要求新目录时自动切换）     │
│     → 完全不需要 LLM 手动复制字符串                                  │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  C. compacting hook（每次压缩时触发）                                │
│     → Plugin 用 input.sessionID 查 .task_sessions/{sessionID}.json │
│     → 精确找到 TASK_DIR → 显式注入到压缩上下文                      │
│     → 标记"不可省略"，LLM 总结器必须保留                             │
│     → 多轮压缩都能查到（因为 sessionID 不变，映射持久化在文件中）     │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  D. session.deleted 事件                                             │
│     → Plugin 删除 .task_sessions/{sessionID}.json                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 数据格式

**`.task_sessions/` 目录**（位于 `~/bw-ida-pro-analysis/workspace/`）：

每个 session 一个独立文件，避免并发写入数据竞争：

```
workspace/.task_sessions/
  ├── session_abc123.json    ← { "task_dir": "/home/.../20260428_143052_a3b1" }
  └── session_def456.json    ← { "task_dir": "/home/.../20260428_150823_c7d9" }
```

- 文件名: `{sessionID}.json`（sessionID 来自 OpenCode 运行时，compaction 前后不变。假设 sessionID 不含路径分隔符，OpenCode 通常使用 UUID 格式）
- 内容: `{ "task_dir": "<TASK_DIR 绝对路径>" }`
- 每个会话读写自己的文件，不存在并发竞争
- 同一会话创建新 TASK_DIR 时覆盖自己的文件（自动切换）
- session.deleted 时删除对应文件

### 对 6 个关键问题的回答

**Q1: 结合 oh-my-openagent REVIEW**

oh-my-openagent 的 compaction 恢复模式是 `capture → compact → restore`，全用内存 Map。我们用文件持久化（`.task_sessions/{sessionID}.json`）是因为 TASK_DIR 需要跨进程（Plugin 进程 vs Agent bash 进程）共享，内存 Map 做不到。用每 session 独立文件而非单一 JSON 文件，避免并发写入数据竞争。

**Q2: 当前实现是否合适**

当前 `findActiveTask` 盲猜逻辑不合适：
- 多个 in_progress 时放弃 → 无法精确匹配
- 用户要求新目录时无法感知 → Q4 无法解决
- 并行会话时可能匹配到别人的任务 → Q5 无法解决

**Q3: 多轮压缩后如何保证找到**

sessionID 在 compaction 前后不变（oh-my-openagent 已验证）。映射持久化在 `.task_sessions/{sessionID}.json` 文件中，不受进程重启、内存清理影响。compacting hook 每次 compression 都能用同一 sessionID 查到同一个 TASK_DIR。

**Q4: 用户要求新任务目录时是否生效**

Agent 创建新 TASK_DIR 的代码会覆盖 `.task_sessions/{sessionID}.json` 的内容。下次压缩时 compacting hook 查到的就是新目录。

**Q5: 多个会话并发分析**

每个 session 有独立的映射文件（`workspace/.task_sessions/{sessionID}.json`），两个会话各自读写自己的文件，不存在并发竞争。compacting hook 用 `input.sessionID` 精确查找对应文件，不会混淆。

**Q6: 多轮对话、多轮压缩后精确匹配**

```
第 1 轮对话: Agent 创建 TASK_DIR → 注册映射 { "sid_abc": "/path/A" }
第 1 次压缩: compacting hook 查 "sid_abc" → 找到 /path/A → 注入
  → LLM 总结器保留 TASK_DIR = /path/A
第 2 轮对话: Agent 继续使用 /path/A
第 2 次压缩: compacting hook 查 "sid_abc" → 找到 /path/A → 注入
  → LLM 总结器保留 TASK_DIR = /path/A
...
第 N 次压缩: 同上，始终精确匹配
```

sessionID 不变 + 文件持久化 = 无限次压缩后仍然精确。

### 降级策略

| 情况 | 原因 | 行为 |
|------|------|------|
| `shell.env` 的 sessionID 为 undefined | OpenCode 框架异常 | Agent 注册时读到空字符串 → 映射无效 → 降级 |
| Agent 未执行注册（sessionID 为空或跳过） | Agent 未按 prompt 执行 | compacting hook 查不到映射文件 → 依赖 LLM 总结器 |
| 映射文件损坏/丢失 | 文件系统异常 | compacting hook 查不到 → 降级到自愈 |
| 以上全部失败 | 极端情况 | Agent 自愈规则：find_task.py + 问用户 |

三层降级：映射精确匹配 → LLM 总结器 → find_task.py 问用户

---

## §3 实现规范

### §3.1 实施步骤

**步骤 1. Plugin 新增 `shell.env` hook**
- 文件: `.opencode/plugins/binary-analysis.mjs`
- 改动: 新增 `"shell.env"` hook，注入 `SESSION_ID` 到 `output.env`
- 预估行数: ~10 行
- 验证点: `node --check` 通过
- 依赖: 无

**步骤 2. Plugin 新增映射读写函数 + compacting hook 精确查找 + 删除旧逻辑**
- 文件: `.opencode/plugins/binary-analysis.mjs`
- 改动:
  - 新增常量 `TASK_SESSIONS_DIR = join(WORKSPACE_DIR, ".task_sessions")`
  - 新增 `getTaskDir(sessionID)`: 读取 `.task_sessions/{sessionID}.json`，返回 task_dir 或 null
  - 新增 `removeTaskSession(sessionID)`: 删除 `.task_sessions/{sessionID}.json`
  - compacting hook 中用 `input.sessionID` 查对应映射文件，找到则注入 TASK_DIR
  - 删除旧的 `findActiveTask()` 函数
  - 清理不再使用的 import（`readdirSync`, `statSync`）
- 预估行数: +25 -35（净减少 ~10 行）
- 验证点: `node --check` 通过 + compacting hook 使用 sessionID 查文件而非盲猜
- 依赖: 无

**步骤 3. Plugin event hook — 修复 sessionID 取值 + session.deleted 清理映射**
- 文件: `.opencode/plugins/binary-analysis.mjs`
- 改动:
  - 修复 event hook 中 sessionID 的取值：`session.created`/`session.deleted` 事件的 properties 是 `{ info: Session }`，sessionID 在 `props.info?.id` 中，而非 `props.sessionID`
  - 修复后 `session.deleted` 事件中调用 `removeTaskSession(sessionID)` 删除对应映射文件
- 预估行数: ~5 行（修改现有 event hook）
- 验证点: `node --check` 通过 + event hook 使用 `props.info?.id ?? props.sessionID` 兼容两种格式
- 依赖: 步骤 2

**步骤 4. Agent prompt — 任务目录创建加入映射注册**
- 文件: `.opencode/agents/binary-analysis.md`
- 改动:
  - 修改"任务目录约定"的 TASK_DIR 创建命令，在创建目录后增加注册步骤
  - Python 脚本通过 `os.environ.get('SESSION_ID', '')` 读取环境变量中的 sessionID
  - 写入 `.task_sessions/{sessionID}.json`
  - 需要同时提供 bash 和 PowerShell 两套模板
  - 更新注释：从"盲猜"改为"通过 sessionID 映射精确匹配"
- 预估行数: ~12 行（修改现有代码块）
- 验证点: 行数 < 450 + Python 代码通过 `os.environ` 读取 SESSION_ID + bash/PowerShell 双模板
- 依赖: 步骤 1（shell.env 确保 SESSION_ID 可用）

**步骤 5. Agent prompt — 自愈规则增加映射恢复层**
- 文件: `.opencode/agents/binary-analysis.md`
- 改动: 自愈规则中，$TASK_DIR 恢复增加优先级：先通过 `$SESSION_ID` 查 `.task_sessions/{sessionID}.json`，查不到再用 find_task.py
- 预估行数: ~5 行（修改现有自愈规则）
- 验证点: 三层降级链路清晰（映射文件 → LLM 总结器 → find_task.py → 问用户）
- 依赖: 步骤 1（shell.env 确保 SESSION_ID 可用）

### 改动范围表

| 文件 | 改动类型 | 预估行数 |
|------|---------|---------|
| `.opencode/plugins/binary-analysis.mjs` | 修改 | +35 -35 |
| `.opencode/agents/binary-analysis.md` | 修改 | +17 -5 |

**不新增文件。不修改 Python 脚本（find_task.py 已存在）。不修改知识库。**

### 编码规则

1. 映射文件存储在 `.task_sessions/` 目录下，每个 session 一个独立 JSON 文件
2. 读写映射文件失败不影响主流程（静默降级）
3. `shell.env` hook 中 sessionID 为 undefined 时不注入
4. compacting hook 中查不到映射文件时不注入（静默降级）
5. Agent prompt 中注册命令通过 `os.environ.get('SESSION_ID', '')` 读取，空字符串时不注册
6. `SESSION_ID` 由 shell.env hook 注入到环境变量，不需要在 Agent prompt 的"变量初始化"中赋值
7. bash 中用 `$SESSION_ID`，PowerShell 中用 `$env:SESSION_ID`

---

## §4 验收标准

### 功能验收

| 验收项 | 预期结果 | 验证方式 |
|--------|---------|---------|
| shell.env 注入 | Agent bash 进程中 `echo $SESSION_ID` 输出非空 | Agent 执行时检查 |
| 映射注册 | 创建 TASK_DIR 后 `.task_sessions/{sessionID}.json` 存在且内容正确 | 检查文件内容 |
| 压缩注入 | compacting hook 输出中包含正确的 TASK_DIR | 日志检查 |
| 并行隔离 | 两个会话的映射文件互不干扰 | 检查 `.task_sessions/` 目录有两个独立文件 |
| 会话清理 | session.deleted 后映射条目被删除 | 检查文件 |
| 用户切换目录 | 创建新 TASK_DIR 后映射更新为新路径 | 检查文件 |
| 多轮压缩 | N 次压缩后仍能查到正确的 TASK_DIR | 连续触发压缩验证 |

### 回归验收

| 验收项 | 预期结果 |
|--------|---------|
| 环境信息注入 | system.transform 仍正常注入 IDA/编译器/Python 包信息 |
| 压缩规则注入 | COMPACT_RULES + COMPACTION_CONTEXT_PROMPT 仍正常注入 |
| Agent prompt 行数 | < 450 行 |

### 架构验收

- 无循环依赖
- Plugin 只依赖 `workspace/.task_sessions/` 目录（每个 session 一个文件）
- Agent 只依赖 `SESSION_ID` 环境变量（由 Plugin shell.env hook 注入）
- 整条链路不依赖 LLM 手动操作

---

## §5 与现有需求文档的关系

| 文档 | 关系 |
|------|------|
| `2026-04-22-plugin-and-architecture-improvements.md` | Plugin 架构已建立，本需求在此基础上新增 shell.env hook |
| `2026-04-27-ecdlp-compression-parallel.md` | 已实现 compacting hook 的环境信息注入，本需求增加 TASK_DIR 精确恢复能力（替换盲猜逻辑） |

---

## 附录 A: sessionID 生命周期验证

来源: oh-my-openagent 源码分析

```
session.created  → sessionID = "abc123"
    ↓
第 1 轮对话（多轮 tool 调用，每次 shell.env 都拿到 "abc123"）
    ↓
第 1 次压缩:
  compacting hook input.sessionID = "abc123"  ← 不变
  session.compacted event.sessionID = "abc123"  ← 不变
    ↓
第 2 轮对话（shell.env 仍然拿到 "abc123"）
    ↓
第 2 次压缩:
  compacting hook input.sessionID = "abc123"  ← 不变
    ↓
... 无限次压缩，sessionID 始终不变
    ↓
session.deleted → sessionID = "abc123"  ← 清理映射
```

## 附录 B: shell.env hook 类型签名

```typescript
"shell.env"?: (
  input: {
    cwd: string
    sessionID?: string
    callID?: string
  },
  output: {
    env: Record<string, string>  // 注入的环境变量
  }
) => Promise<void>
```

使用方式: `output.env["SESSION_ID"] = input.sessionID`
