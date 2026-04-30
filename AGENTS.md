# AGENTS.md — OpenCode 安全分析项目指南

基于 OpenCode 的多 Agent 安全分析集合：IDA Pro 二进制逆向 + 移动端应用分析。

## Agent 索引

| Agent | 切换方式（Tab 键） | 职责 |
|-------|-------------------|------|
| `binary-analysis` | Tab 选择 | IDA Pro 二进制逆向（PC 端 exe/dll/so） |
| `mobile-analysis` | Tab 选择 | 移动端应用分析（APK/IPA） |

## 目录结构

Plugin 和 Agent 位于 OpenCode 扩展目录（项目级 `.opencode/` 或全局 `~/.config/opencode/`）：

```
.opencode/                                # 或 ~/.config/opencode/
├── agents/                               # Agent prompt（Tab 切换时加载）
├── plugins/security-analysis.ts          # 上下文持久化 Plugin
├── binary-analysis/                      # 逆向分析核心工具与知识库
│   └── scripts/detect_env.py             # 环境检测脚本
└── mobile-analysis/                      # 移动端工具与知识库（knowledge-base/）
```

## 测试

| 命令 | 说明 |
|------|------|
| `pytest` | Python 测试（`ai/` 模块等） |
| `bats test/shell/` | shell 测试 |

## 特殊说明

- 日志、注释使用中文
- `ai/opencode.py` 不依赖 IDA 运行时，有独立 pytest 测试
- IDAPython 文档: https://python.docs.hex-rays.com/
