# AGENTS.md — IDA Pro Python 插件项目指南

## 项目概述

基于 IDAPython 的 IDA Pro 插件脚本，用于辅助移动端逆向分析。

## 目录结构

```
ai/              # AI 辅助工具（opencode 非交互封装，不依赖 IDA 运行时）
analysis_details/ # 反汇编分析产物（.asm/.c 文件）
demo.py          # 示例脚本
disassembler/    # 反汇编操作脚本（每个 .py 可附带同名 .sh 无头 wrapper）
shell/library/   # 可复用的 shell 库（IDA 路径检测、数据库锁检测等）
docs/            # 文档与需求
rules/           # 详细规则文档（按需加载）
test/            # Python 测试 + shell 测试（test/shell/*.bats）
utils/           # 公共工具函数
vendor/          # 只读子模块（IDA SDK、示例代码等参考资源）
requirements.txt # IDE 类型存根依赖（非运行时依赖）
```

> `.venv/` 为本地开发环境，`requirements.txt` 仅含 IDE 类型存根（`idapro`），非运行时依赖。

## Build / Test / Run

本项目是 IDAPython 脚本集合，无传统构建步骤。

| 命令 | 说明 |
|------|------|
| `pytest` | 运行 Python 测试（`ai/` 模块等，不依赖 IDA 运行时） |
| `pytest test/test_opencode.py` | 运行单个测试文件 |
| `pytest test/test_opencode.py::TestSingleLinePrompt::test_success` | 运行单个测试用例 |
| `pytest -k "test_success"` | 按名称过滤运行测试 |
| `bats test/shell/` | 运行 shell 脚本测试（需安装 [bats-core](https://github.com/bats-core/bats-core)） |

> IDAPython 脚本（`disassembler/`、`demo.py`）无法脱离 IDA Pro 环境运行，没有单元测试。仅 `ai/` 等不依赖 IDA 运行时的模块有 pytest 测试。

## 外部参考资源

- **IDAPython 示例索引**：`vendor/ida-sdk/src/plugins/idapython/examples/index.md`
- **IDAPython 示例源码**：`vendor/ida-sdk/src/plugins/idapython/examples/`
- **IDAPython 参考文档**：https://python.docs.hex-rays.com/

## 编码规范

IDAPython 脚本编码规范详见 [`rules/coding-conventions.md`](rules/coding-conventions.md)。
包含：导入规则、脚本文件头、日志规范、代码风格、IDAPython 模块速查、脚本运行方式、headless 自动化指南。

## 特殊说明

- 新脚本应按功能命名（如 `list_encrypted_strings.py`）。
- 日志、注释都应该使用中文。
- `ai/opencode.py` 提供 `run_opencode(prompt)` 函数，可在 IDAPython 脚本内调用 OpenCode 进行 AI 辅助分析。该模块不依赖 IDA 运行时，有独立的 pytest 测试。
