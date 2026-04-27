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

确保压缩后 Agent 能**精确**恢复到正确的 TASK_DIR，不盲猜、不降级。

### 约束

- 支持多个会话并行分析不同二进制
- 不增加压缩上下文体积（不能扫描整个 workspace 注入）
- 不依赖 LLM 手动复制粘贴字符串
- 改动范围可控，不引入新的架构层

---

## §2 技术方案

### API 能力调研结论

| Hook | sessionID | 可靠性 |
|------|-----------|--------|
| `experimental.session.compacting` | `input.sessionID: string`（必填） | ✅ 每次压缩都能拿到 |
| `experimental.chat.system.transform` | `input.sessionID?: string`（可选） | ⚠️ 通常有，但可能 undefined |
| `shell.env` | `input.sessionID?: string`（可选） | ⚠️ 通常有，可以注入到 shell 环境变量 |
| `event: session.created` | `properties.info.id: string` | ✅ 完整 Session 对象 |
| `event: session.deleted` | `properties.info.id: string` | ✅ 完整 Session 对象 |
| `event: session.compacted` | `properties.sessionID: string` | ✅ |

**关键发现**：`shell.env` hook 可以把 sessionID 注入到 shell 环境变量中。Agent 执行 bash 命令时，Python 脚本能通过 `os.environ['SESSION_ID']` 直接获取，**完全不需要 LLM 手动复制**。

### 方案：sessionID 映射 + shell.env 注入

```
┌─────────────────────────────────────────────────────────────┐
│ 1. session.created 事件                                      │
│    → Plugin 无需操作（sessionID 在后续 hook 中获取）          │
├─────────────────────────────────────────────────────────────┤
│ 2. shell.env hook（Agent 每次执行 bash 时触发）               │
│    → Plugin 注入 SESSION_ID=<sessionID> 到环境变量           │
│    → Agent 的 bash 进程中 $SESSION_ID 自动可用               │
├─────────────────────────────────────────────────────────────┤
│ 3. Agent 创建 TASK_DIR                                       │
│    → Python 脚本读 $SESSION_ID（环境变量）                    │
│    → 写 .task_sessions.json: { sessionID: taskDir }          │
│    → 无需 LLM 手动复制任何值                                 │
├─────────────────────────────────────────────────────────────┤
│ 4. compacting hook（压缩时触发）                              │
│    → Plugin 用 input.sessionID 查 .task_sessions.json       │
│    → 精确找到 TASK_DIR → 显式注入到压缩上下文                │
│    → "不可省略" 标记，LLM 总结器必须保留                      │
├─────────────────────────────────────────────────────────────┤
│ 5. session.deleted 事件                                       │
│    → Plugin 从 .task_sessions.json 删除对应条目              │
└─────────────────────────────────────────────────────────────┘
```

### 数据格式

**`.task_sessions.json`**（位于 `~/bw-ida-pro-analysis/workspace/`）：

```json
{
  "session_abc123": "/home/user/bw-ida-pro-analysis/workspace/20260428_143052_a3b1",
  "session_def456": "/home/user/bw-ida-pro-analysis/workspace/20260428_150823_c7d9"
}
```

- Key: sessionID（来自 OpenCode 运行时）
- Value: TASK_DIR 绝对路径
- 多个会话并行时各自写入各自的 key，不冲突

### 降级策略

| 情况 | 行为 |
|------|------|
| shell.env 的 sessionID 为 undefined | Agent 注册映射时 sessionID 为空字符串 → 映射无效 → 降级到自愈 |
| Agent 未注册映射（sessionID 为空或其他原因） | compacting hook 查不到 → 依赖 LLM 总结器保留 |
| 两者都失败 | Agent 自愈规则：find_task.py + 问用户 |

---

## §3 实现规范

### §3.1 实施步骤

**步骤 1. Plugin 新增 `shell.env` hook — 注入 SESSION_ID 环境变量**
- 文件: `.opencode/plugins/binary-analysis.mjs`
- 预估行数: ~15 行
- 验证点: `node --check` 通过 + 手动确认 hook 结构正确
- 依赖: 无

**步骤 2. Plugin compacting hook — 用 sessionID 查映射注入 TASK_DIR**
- 文件: `.opencode/plugins/binary-analysis.mjs`
- 预估行数: ~20 行（含映射读写函数）
- 验证点: `node --check` 通过
- 依赖: 步骤 1

**步骤 3. Plugin event hook — session.deleted 清理映射**
- 文件: `.opencode/plugins/binary-analysis.mjs`
- 预估行数: ~5 行
- 验证点: `node --check` 通过
- 依赖: 步骤 2

**步骤 4. Agent prompt — 任务目录约定加入映射注册**
- 文件: `.opencode/agents/binary-analysis.md`
- 预估行数: ~10 行（修改现有 TASK_DIR 创建代码，增加注册步骤）
- 验证点: 行数 < 450 + 创建命令逻辑正确
- 依赖: 步骤 1（shell.env 确保 SESSION_ID 可用）

**步骤 5. Agent prompt — 自愈规则引用 find_task.py**
- 文件: `.opencode/agents/binary-analysis.md`
- 预估行数: ~5 行（已有，确认无误）
- 验证点: 自愈流程完整（映射 → LLM 总结器 → find_task.py → 问用户）
- 依赖: 步骤 4

**步骤 6. 删除旧的盲猜逻辑**
- 文件: `.opencode/plugins/binary-analysis.mjs`
- 预估行数: -15 行（删除 findActiveTask 函数及相关代码）
- 验证点: `node --check` 通过 + 不再有 findActiveTask
- 依赖: 步骤 2、3

### 改动范围表

| 文件 | 改动类型 | 预估行数 |
|------|---------|---------|
| `.opencode/plugins/binary-analysis.mjs` | 修改 | +40 -15 |
| `.opencode/agents/binary-analysis.md` | 修改 | +15 -5 |

**不新增文件。不修改 Python 脚本。不修改知识库。**

### 编码规则

1. `.task_sessions.json` 读写用 `readJsonSafe`/`writeJsonSafe`，失败不影响主流程
2. `shell.env` hook 中 sessionID 为 undefined 时不注入
3. compacting hook 中查不到映射时不注入（不报错）
4. Agent prompt 中注册命令用 `sys.argv` 或 `os.environ` 读取 SESSION_ID，不依赖 LLM 复制字符串

---

## §4 验收标准

### 功能验收

| 验收项 | 预期结果 |
|--------|---------|
| shell.env 注入 | Agent bash 进程中 `echo $SESSION_ID` 输出非空 |
| 映射注册 | 创建 TASK_DIR 后 `.task_sessions.json` 中有对应条目 |
| 压缩注入 | compacting hook 输出中包含正确的 TASK_DIR |
| 并行隔离 | 两个会话的映射互不干扰 |
| 会话清理 | session.deleted 后映射条目被删除 |

### 回归验收

| 验收项 | 预期结果 |
|--------|---------|
| 环境信息注入 | system.transform 仍正常注入 IDA/编译器/Python 包信息 |
| 压缩规则注入 | COMPACT_RULES + COMPACTION_CONTEXT_PROMPT 仍正常注入 |
| Agent prompt 行数 | < 450 行 |

### 架构验收

- 无循环依赖
- Plugin 只依赖 `workspace/.task_sessions.json`（已存在的目录）
- Agent 只依赖 `SESSION_ID` 环境变量（由 Plugin 注入）

---

## §5 与现有需求文档的关系

| 文档 | 关系 |
|------|------|
| `2026-04-22-plugin-and-architecture-improvements.md` | Plugin 架构已建立，本需求在此基础上增强 shell.env hook |
| `2026-04-27-ecdlp-compression-parallel.md` | 已实现 compacting hook 的环境信息注入，本需求增加 TASK_DIR 精确恢复能力 |
