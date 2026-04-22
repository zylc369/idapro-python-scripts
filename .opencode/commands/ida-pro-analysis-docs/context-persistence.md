# 上下文持久化方案

## 问题

OpenCode 的 `/ida-pro-analysis` 命令仅在用户显式调用时注入完整 prompt。多次上下文压缩后：
- 用户不再使用 `/ida-pro-analysis` 前缀 → AI 失去所有规则/知识
- 即使使用前缀，长时间对话中规则可能被遗忘
- 之前分析的关键发现（如"二进制有 bug，需要 r==1"）在压缩后丢失

## 当前方案：规则摘要

在 `ida-pro-analysis.md` 的输出格式中增加"规则摘要"：
- 每次输出分析结果时附加简短摘要（~5行）
- 摘要包含：验证标准、环境状态、技术选型提醒
- 确保即使上下文被压缩，关键规则仍存在于最近的对话中

### 摘要内容

```
[规则提醒] ① 禁止作弊式验证 | ② 环境: <compiler> + <packages> | ③ 计算密集型用 C | ④ ECDLP: technology-selection.md + ecdlp-solving.md
```

## 长期方案

### 方案 A: OpenCode Hook 机制

如果 OpenCode 支持在每轮对话开始时自动执行钩子：
- 自动注入 `ida-pro-analysis.md` 的关键规则
- 不需要用户每次使用 `/ida-pro-analysis` 前缀

**评估**: 需要查看 OpenCode 文档确认是否支持。

### 方案 B: 自定义 Agent

如果 OpenCode 支持自定义 agent：
- 创建一个始终保持 `ida-pro-analysis` 上下文的 agent
- 用户与此 agent 交互时，始终遵守 ida-pro-analysis 规则

**评估**: 需要查看 OpenCode 文档确认是否支持。

### 方案 C: 关键发现持久化

将分析过程中的关键发现写入文件（而非仅存在于对话上下文中）：
- 发现写入 `~/bw-ida-pro-analysis/workspace/<task_id>/findings.json`
- 每次分析开始时读取上次任务的 findings
- 避免"二进制有 bug 需要特殊条件"这类发现丢失

## 可行性风险

如果 OpenCode 不支持 hook 机制，方案 H 只能做到"每次输出附加摘要"，不能完全解决上下文丢失问题。此时：
1. 依赖用户在长时间对话中定期使用 `/ida-pro-analysis` 前缀刷新规则
2. 依赖 `findings.json` 持久化关键发现
3. 环境检测结果通过缓存文件持久化（已实现）
