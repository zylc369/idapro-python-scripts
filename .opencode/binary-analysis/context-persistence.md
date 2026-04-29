# BinaryAnalysis 上下文持久化方案

## 问题

OpenCode 长对话中存在三类上下文丢失问题：
1. **规则丢失**: 多轮交互后 Agent 不再遵守 BinaryAnalysis 规则
2. **知识丢失**: 压缩后之前发现的分析结论（如"二进制有 bug，需要 r==1"）丢失
3. **环境丢失**: 每轮对话无法感知 IDA 路径、编译器、工具包等环境信息

## 当前方案：Plugin + Agent 架构

### 架构

```
.opencode/
├── agents/binary-analysis.md           # Agent prompt（分析编排规则）
└── plugins/security-analysis.ts          # Plugin（上下文持久化）
```

### Plugin 使用的 Hooks

| Hook | 作用 | 触发时机 |
|------|------|---------|
| `experimental.session.compacting` | 注入分析状态保留提示 + 关键规则 | 上下文压缩前 |
| `experimental.chat.system.transform` | 注入环境信息（IDA路径、编译器、工具包） | 每轮对话 |
| `event` | 管理 session 生命周期（created/deleted/compacted） | session 状态变化 |

### Hook API 签名（基于 oh-my-openagent 源码确认）

```typescript
// system.transform: 修改系统提示
(input: { sessionID?: string; model: { id: string; providerID: string; [key: string]: unknown } },
 output: { system: string[] }) => Promise<void>
// 使用 output.system.push(content) 注入

// compacting: 压缩时注入上下文
(input: { sessionID: string },
 output: { context: string[] }) => Promise<void>
// 使用 output.context.push(content) 注入

// event: 响应 session 生命周期事件
(input: { event: { type: string; properties?: Record<string, unknown> } }) => Promise<void>
// 事件类型: session.created, session.deleted, session.compacted
```

### 数据流

1. **环境信息**（每轮）: `~/bw-security-analysis/config.json` + `env_cache.json` → Plugin 读取 → `system.transform` 注入到系统提示
2. **分析规则**（压缩时）: Plugin 内置 COMPACT_RULES → `compacting` hook 注入到压缩 prompt
3. **分析状态**（压缩时）: Plugin 注入结构化提示 → 告知压缩模型保留分析结论
4. **知识库**（按需）: Agent 通过 Read 工具按需加载 `knowledge-base/` 下的文档

### 环境数据缓存

- 环境检测结果缓存到 `~/bw-security-analysis/env_cache.json`，有效期 24 小时
- 检测脚本: `scripts/detect_env.py`
- Agent prompt 中有环境检测阶段指引

### 知识库按需加载

知识库文件位于 `knowledge-base/`，Agent prompt 中的"知识库索引"表列出每个文件的触发条件。Agent 不会在分析开始时全部加载，而是根据场景标签按需读取。

## 扩展方向

- **分析状态持久化**: 将分析中的关键发现写入 `~/bw-security-analysis/workspace/<task_id>/findings.json`，跨 session 复用
- **压缩后自动恢复**: 通过 `event` hook 的 `session.compacted` 事件，自动读取 findings.json 并注入
