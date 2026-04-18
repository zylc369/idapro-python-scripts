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

> IDAPython 脚本（`disassembler/`、`demo.py`）无法脱离 IDA Pro 环境运行，没有单元测试。仅 `ai/` 等不依赖 IDA 运行时的模块有 pytest 测试；shell wrapper（`.sh`）通过 `test/shell/*.bats` 测试，使用 mock `idat` 验证命令构造。

## 脚本运行方式（IDA Pro 内）

### 1. 对话框模式（IDA GUI 内，无参数）

无参数执行时弹出 `ida_kernwin.Form` 对话框，用户填写参数后执行：

```python
exec(open("disassembler/dump_func_disasm.py", encoding="utf-8").read())
```

### 2. CLI 模式（IDA GUI 内，通过 sys.argv 传参）

通过 `sys.argv` 传参跳过对话框，直接执行。`_parse_cli_argv(sys.argv)` 解析 `--use-mode cli --addr <值> --output <值>` 格式：

```python
import sys
sys.argv = ["", "--use-mode", "cli", "--addr", "main", "--output", "/tmp/output/"]
exec(open("disassembler/dump_func_disasm.py", encoding="utf-8").read())
```

### 3. Headless / 无头模式（命令行，通过 idat -A -S 调用）

脱离 IDA GUI，使用 `idat` 命令行执行，通过**环境变量**传参：

```bash
IDA_FUNC_ADDR=main IDA_OUTPUT=/tmp/output.asm \
  idat -A -S"disassembler/dump_func_disasm.py" binary.i64
```

实现要点：用 `ida_kernwin.cvar.batch` 判断无头（headless）模式，`os.environ` 读取环境变量，`ida_auto.auto_wait()` 等待分析完成，`ida_pro.qexit(exit_code)` 退出。

> **关键**：无头（headless）入口逻辑**必须在模块级执行**，不能放在 `if __name__ == "__main__"` 内。原因是 IDA 通过 `ida_idaapi.py` 的 `exec(code, g)` 执行 `-S` 指定的脚本，此时 `__name__` 被设为脚本文件名而非 `"__main__"`。

**新建无头（headless）脚本时**，参阅 [`rules/headless-automation-guide.md`](rules/headless-automation-guide.md)，包含完整的 .py 三模式实现 + .sh wrapper 编写指南。

## 外部参考资源

- **IDAPython 示例索引**：`vendor/ida-sdk/src/plugins/idapython/examples/index.md`
- **IDAPython 示例源码**：`vendor/ida-sdk/src/plugins/idapython/examples/`
- **IDAPython 参考文档**：https://python.docs.hex-rays.com/

## 编码规范

### 导入规则（强制，仅限 IDAPython 脚本）

以下规则继承自 IDAPython 官方示例规范，适用于 `disassembler/`、`demo.py` 等 IDA 内运行脚本。`ai/`、`test/` 等不依赖 IDA 的普通 Python 模块不受此限制。

| 规则 | 说明 | 正确 | 错误 |
|------|------|------|------|
| 禁止 `import idc` | `idc` 语义模糊 | `import ida_nalt` | `import idc` |
| 禁止 `import idaapi` | 隐藏符号来源 | `import ida_funcs` | `import idaapi` |
| 禁止 `from X import Y` | 必须通过模块前缀引用 | `ida_kernwin.msg("hi")` | `from ida_kernwin import msg` |
| 字符串用双引号 | 所有字符串字面量 | `"hello"` | `'hello'` |

**例外**：字符串本身包含 `"` 且转义后影响可读性时可用单引号。

### 脚本文件头（强制）

每个脚本文件**必须**以 docstring 头部开始：

```python
"""summary: 一句话概述脚本功能（不以句号结尾）

description:
  详细说明脚本用途、使用方法、注意事项等。

level: beginner|intermediate|advanced
"""
```

- `summary:` 不以 `.` 结尾，首选 `list something...` 形式
- `level:` 标示使用难度
- description 中应说明所有支持的运行模式（对话框 / CLI / 无头）及示例

### 日志规范（强制）

脚本**必须**打印详细的中文执行日志，方便在 IDA Output 窗口或 headless 日志中排查问题：

```python
# 日志前缀约定
ida_kernwin.msg(f"[*] 正在执行某操作: {detail}\n")     # 进行中
ida_kernwin.msg(f"[+] 操作成功: {result}\n")            # 成功
ida_kernwin.msg(f"[!] 警告或错误: {reason}\n")           # 警告/失败
```

**要求**：
- 每个关键步骤都必须有 `[*]` 日志（函数解析、文件写入、模式检测等）
- 成功和失败都要有对应日志（`[+]` / `[!]`）
- 日志内容使用中文，包含足够的上下文信息（函数名、地址、路径等）
- 无头（headless）模式的日志尤为重要（无 GUI，日志是唯一的排查手段）

### 代码风格

- 内部辅助函数以 `_` 前缀标记（如 `_parse_cli_argv`、`_resolve_output_path`）
- 禁止空 `except` 块（`except: pass`）
- 捕获异常后必须：向上抛出、记录完整堆栈、或向用户返回清晰错误提示
- IDAPython 脚本中函数返回 `True/False` 表示成功/失败是常见模式，应遵循

## 常用 IDAPython 模块速查

| 模块 | 用途 |
|------|------|
| `ida_kernwin` | UI、消息输出（`msg`）、动作注册、快捷键、Form 对话框 |
| `ida_funcs` | 函数查询与操作 |
| `ida_bytes` / `ida_xref` / `ida_segment` | 字节读写 / 交叉引用 / 段信息 |
| `ida_nalt` / `ida_typeinf` / `ida_hexrays` | 导入表 / 类型系统 / 反编译器 |
| `ida_lines` / `ida_gdl` | 反汇编行 / 流图与调用图 |
| `ida_auto` / `ida_pro` | `auto_wait`（无头等待分析）/ `qexit`（无头退出） |
| `ida_name` / `ida_loader` | 符号名查询 / 文件加载与导出 |
| `idautils` | 高级工具（Functions、Strings、CodeRefsTo 等迭代器） |
| `ida_idaapi` | 基础常量（BADADDR 等）— 仅引用常量时可用 |

## 功能类别与参考示例

编写新脚本时，根据功能类型参考 `vendor/ida-sdk/src/plugins/idapython/examples/` 下对应目录的示例。分类决策参阅 [`rules/script-classification.md`](rules/script-classification.md)。

反汇编 → `examples/disassembler/` · 反编译 → `examples/decompiler/` · UI → `examples/ui/` · 类型 → `examples/types/` · 调试器 → `examples/debugger/`

## 特殊说明

- 新脚本应按功能命名（如 `list_encrypted_strings.py`）。
- 脚本中如需用户交互，使用 `ida_kernwin.ask_str`、`ida_kernwin.ask_yn` 等函数。
- 日志、注释都应该使用中文。
- `ai/opencode.py` 提供 `run_opencode(prompt)` 函数，可在 IDAPython 脚本内调用 OpenCode 进行 AI 辅助分析（参见 `disassembler/dump_func_disasm.py` 的 `_call_ai_decompiler` 实现）。该模块不依赖 IDA 运行时，有独立的 pytest 测试。
