# IDAPython 脚本编码规范

> 适用于 `disassembler/`、`demo.py`、`.opencode/binary-analysis/scripts/` 等 IDA 内运行脚本。
> `ai/`、`test/` 等不依赖 IDA 的普通 Python 模块不受此限制。

## 导入规则（强制）

| 规则 | 说明 | 正确 | 错误 |
|------|------|------|------|
| 禁止 `import idc` | `idc` 语义模糊 | `import ida_nalt` | `import idc` |
| 禁止 `import idaapi` | 隐藏符号来源 | `import ida_funcs` | `import idaapi` |
| 禁止 `from ida_xxx import Y` | 必须通过模块前缀引用 | `ida_kernwin.msg("hi")` | `from ida_kernwin import msg` |
| `ida_idaapi` 仅引用常量 | 如 BADADDR | `ida_idaapi.BADADDR` | `ida_idaapi.get_inf_structure()` |
| 字符串用双引号 | 所有字符串字面量 | `"hello"` | `'hello'` |

**例外**：允许 `from _base import ...` 和 `from _utils import ...`。字符串本身包含 `"` 且转义后影响可读性时可用单引号。

## 脚本文件头（强制）

每个脚本文件**必须**以 docstring 头部开始：

```python
"""summary: 一句话概述脚本功能（不以句号结尾）

description:
  详细说明脚本用途、使用方法、注意事项等。

usage:
  python script.py --param value

level: beginner|intermediate|advanced
"""
```

## 日志规范（强制）

```python
ida_kernwin.msg(f"[*] 正在执行某操作: {detail}\n")     # 进行中
ida_kernwin.msg(f"[+] 操作成功: {result}\n")            # 成功
ida_kernwin.msg(f"[!] 警告或错误: {reason}\n")           # 警告/失败
```

**要求**：
- 每个关键步骤必须有 `[*]` 日志
- 成功和失败都要有对应日志（`[+]` / `[!]`）
- 日志内容使用中文，包含足够上下文（函数名、地址、路径等）
- 无头模式的日志尤为重要（无 GUI，日志是唯一排查手段）

## 代码风格

- 内部辅助函数以 `_` 前缀标记（如 `_parse_cli_argv`）
- 禁止空 `except` 块（`except: pass`）
- 捕获异常后必须处理：抛出 / 记录完整堆栈 / 返回清晰错误
- 函数返回 `True/False` 表示成功/失败
- 新脚本必须有 docstring 头部
- 无头入口逻辑必须在模块级执行（不能放在 `if __name__ == "__main__"` 内）

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

## 脚本运行方式

### 1. 对话框模式（IDA GUI 内，无参数）

```python
exec(open("disassembler/dump_func_disasm.py", encoding="utf-8").read())
```

### 2. CLI 模式（IDA GUI 内，通过 sys.argv 传参）

```python
import sys
sys.argv = ["", "--use-mode", "cli", "--addr", "main", "--output", "/tmp/output/"]
exec(open("disassembler/dump_func_disasm.py", encoding="utf-8").read())
```

### 3. Headless / 无头模式（命令行，通过 idat -A -S 调用）

```bash
IDA_FUNC_ADDR=main IDA_OUTPUT=/tmp/output.asm \
  idat -A -S"disassembler/dump_func_disasm.py" binary.i64
```

> **关键**：无头入口逻辑**必须在模块级执行**。IDA 通过 `exec(code, g)` 执行 `-S` 指定的脚本，`__name__` 被设为脚本文件名而非 `"__main__"`。

**新建无头脚本时**，参阅 [`rules/headless-automation-guide.md`](rules/headless-automation-guide.md)。
