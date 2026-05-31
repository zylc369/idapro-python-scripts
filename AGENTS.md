# AGENTS.md — OpenCode 安全分析项目指南

基于 OpenCode 的多 Agent 安全分析集合：二进制逆向分析 + 移动端应用分析 + Web 安全分析 + AI 安全分析。

## Agent 索引

| Agent | 职责 |
|-------|------|
| `security-coordinator` | 复合安全任务编排（自动分发到专业 Agent） |
| `binary-analysis` | 二进制逆向分析（PC 端 exe/dll/so） |
| `mobile-analysis` | 移动端应用分析（APK/IPA） |
| `web-analysis` | Web 安全分析 |
| `ai-security-analysis` | AI 安全分析（LLM 提示注入 + 越狱攻击） |
| `security-analysis-evolve` | 体系进化（复盘、需求生成、代码实施、审计） |
