# AGENTS.md — IDA Pro Python 插件项目指南

## 项目概述

基于 IDAPython 的 IDA Pro 插件脚本，用于辅助移动端逆向分析。

## 目录结构

```
├── ai/              # AI 辅助工具（opencode 封装等）
├── analysis_details/ # 反汇编分析产物（.asm/.c 文件）
├── demo.py          # 示例脚本
├── disassembler/    # 反汇编操作脚本
├── docs/            # 文档与需求
├── rules/           # 详细规则文档（按需加载）
├── test/            # 测试
├── utils/           # 公共工具函数
├── requirements.txt # IDE 类型存根依赖
└── AGENTS.md        # 本文件
```

## Build / Test / Run

本项目是 IDAPython 脚本集合，无传统构建步骤。

| 命令 | 说明 |
|------|------|
| `pytest` | 运行全部测试 |
| `pytest test/test_opencode.py` | 运行单个测试文件 |
| `pytest test/test_opencode.py::TestSingleLinePrompt::test_success` | 运行单个测试用例 |
| `pytest -k "test_success"` | 按名称过滤运行测试 |

> **注意**：IDAPython 脚本（`disassembler/`、`demo.py`）无法脱离 IDA Pro 环境运行，没有单元测试。仅 `ai/` 等不依赖 IDA 运行时的模块有测试。

### 脚本运行方式（IDA Pro 内）

1. **File → Script file...**：选择 `.py` 文件执行
2. **File → Script command...**：粘贴代码到输入框执行
3. **Output 窗口/IDAPython 控制台**：`exec(open("path/to/script.py", encoding="utf-8").read())`

## 外部参考资源

- **IDAPython 示例索引**：`/Users/aserlili/Documents/Codes/ida-sdk/src/plugins/idapython/examples/index.md`
- **IDAPython 示例源码**：`/Users/aserlili/Documents/Codes/ida-sdk/src/plugins/idapython/examples/`
- **IDAPython 参考文档**：https://python.docs.hex-rays.com/

## 编码规范

### 导入规则（强制）

以下规则继承自 IDAPython 官方示例规范，**必须严格遵守**：

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

- `summary:` 不以 `.` 结尾
- `summary:` 首选 `list something...` 形式，而非 `listing something...`
- `level:` 标示使用难度

### Python 版本与兼容性

- Python 3.x（IDA Pro 7.x+ 内置 Python 3）
- 使用 `print()` 函数，不使用 `print` 语句
- 类型注解不是必须的，但在复杂函数中推荐使用

### 命名与代码风格

- 函数/变量：`snake_case`
- 类：`PascalCase`
- 常量：`UPPER_SNAKE_CASE`
- 缩进：4 空格
- 每行不超过 120 字符
- 使用 f-string 格式化字符串

### 错误处理

- 禁止空 `except` 块（`except: pass`）
- 捕获异常后必须：向上抛出、记录完整堆栈、或向用户返回清晰错误提示
- IDAPython 脚本中函数返回 `True/False` 表示成功/失败是常见模式，应遵循

## 功能类别与参考示例

编写新脚本时，根据功能类型参考对应目录下的示例：

### 反汇编操作 → `examples/disassembler/`

- 枚举导入：`list_imports.py`
- 枚举字符串：`list_strings.py`
- 枚举函数与交叉引用：`list_segment_functions.py`
- 枚举补丁字节：`list_patched_bytes.py`
- 转储函数流图：`dump_flowchart.py`
- 列出函数信息：`dump_func_info.py`
- 查找字符串：`find_string.py`
- 监听 IDB/IDP 事件：`log_idb_events.py`、`log_idp_events.py`

### 反编译操作 → `examples/decompiler/`

- 反编译当前函数：`vds1.py`
- 生成微码：`vds13.py`
- 转储语句块：`vds7.py`
- 修改反编译输出：`vds6.py`
- 反编译器事件钩子：`vds_hooks.py`
- 生成整个文件的 C 代码：`produce_c_file.py`
- 修改局部变量：`vds_modify_user_lvars.py`

### UI 操作 → `examples/ui/`

- 注册快捷键：`add_hotkey.py`（原型阶段）、`actions.py`（完整版）
- 添加菜单：`misc/add_menus.py`
- 自定义表格视图：`tabular_views/custom/choose.py`
- 自定义列表视图：`listings/custom_viewer.py`
- 图形视图：`graphs/custom_graph_with_actions.py`
- PyQt 集成：`pyqt/populate_pluginform_with_pyqt_widgets.py`
- UI 事件钩子：`uihooks/log_misc_events.py`
- 进度对话框：`waitbox/show_and_hide_waitbox.py`
- 定时器：`register_timer.py`

### 类型操作 → `examples/types/`

- 解析创建结构体：`create_struct_by_parsing.py`
- 编程创建结构体：`create_struct_by_member.py`、`create_structure_programmatically.py`
- 列举结构体成员：`list_struct_member.py`
- 列举枚举成员：`list_enum_member.py`
- 修改栈变量：`change_stkvar_name.py`、`change_stkvar_type.py`
- 函数栈帧信息：`list_frame_info.py`
- 函数原型：`list_func_details.py`

### 调试器操作 → `examples/debugger/`

- 打印寄存器：`misc/print_registers.py`（如有）
- 打印调用栈：`misc/print_call_stack.py`（如有）
- 调试器事件钩子：`dbghooks/`（如有）
- Appcall：`appcall/`（如有）

### 杂项 → `examples/misc/`

- IDAPython 初始化回调：`idapythonrc.py`
- 扩展 IDC 运行时：`extend_idc.py`

> 示例路径基于 `/Users/aserlili/Documents/Codes/ida-sdk/src/plugins/idapython/examples/`。

## 常用 IDAPython 模块速查

| 模块 | 用途 |
|------|------|
| `ida_kernwin` | UI 操作、消息输出、动作注册、快捷键 |
| `ida_funcs` | 函数查询与操作 |
| `ida_bytes` | 字节级读写与搜索 |
| `ida_xref` | 交叉引用查询 |
| `ida_segment` | 段信息查询 |
| `ida_nalt` | 导入表、字符串类型等 |
| `ida_typeinf` | 类型系统操作（结构体、枚举、类型信息） |
| `ida_hexrays` | 反编译器 API |
| `ida_lines` | 反汇编行生成与颜色标签 |
| `ida_gdl` | 流图与调用图 |
| `ida_auto` | 自动分析控制 |
| `ida_loader` | 文件加载与导出 |
| `idautils` | 高级工具函数（Functions、Strings、CodeRefsTo 等） |
| `ida_idaapi` | 基础常量（BADADDR 等）— 仅引用常量时可用 |

## 脚本分类标准

> **按需加载**：创建新脚本需要确定分类时，参阅 [`rules/script-classification.md`](rules/script-classification.md)。

## 特殊说明

- 新脚本应按功能命名（如 `list_encrypted_strings.py`）。
- 脚本中如需用户交互，使用 `ida_kernwin.ask_str`、`ida_kernwin.ask_yn` 等函数。
- 日志、注释都应该使用中文。
- `.venv/` 为本地开发环境，`requirements.txt` 仅含 IDE 类型存根（`idapro`），非运行时依赖。
