# AGENTS.md — idapro python插件项目指南

## 项目概述

基于 IDAPython 的 IDA Pro 插件脚本。

## 目录结构

```
├── main.py         # 入口脚本（占位）
├── README.md       # 编码规范（本文件的超集）
└── AGENTS.md       # 本文件
```

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

## 脚本运行方式

在 IDA Pro 中有三种执行方式：

1. **File → Script file...**：选择 `.py` 文件执行
2. **File → Script command...**：粘贴代码到输入框执行
3. **Output 窗口/IDAPython 控制台**：`exec(open("path/to/script.py", encoding="utf-8").read())`

## 脚本分类标准

以下分类标准提取自 IDAPython 官方示例仓库（`ida-sdk/src/plugins/idapython/examples/`）的目录组织方式。新脚本**必须**根据其核心功能放入对应子目录。

### 分类判定原则

1. **按核心功能判定**：脚本的主要目的是什么，就归入哪个目录。即使脚本同时涉及多个领域，也以**主要功能**为准。
2. **按主要依赖模块判定**：当功能边界模糊时，以脚本**最依赖的 IDAPython 模块**作为分类依据。
3. **无法归入已有类别 → `misc/`**：不属于任何明确类别的脚本放入 `misc/`。

### 各目录分类标准

#### `disassembler/` — 反汇编操作

**判定条件（满足任一即可）**：

- 脚本的核心目的是**查询、枚举、搜索反汇编数据**（如函数列表、导入表、字符串、交叉引用、补丁字节、流图等）
- 主要操作反汇编列表（listing）的**读取与展示**
- 涉及 IDB/IDP 事件监听（`IDB_Hooks`、`IDP_Hooks`），且**不涉及反编译器**
- 自定义反汇编行前缀、自定义数据类型与格式

**关键模块信号**：`ida_bytes`、`ida_funcs`、`ida_xref`、`ida_segment`、`ida_nalt`、`ida_gdl`、`ida_lines`、`idautils`（用于 Functions/Strings/CodeRefs 等迭代器）、`ida_idp`（IDB_Hooks/IDP_Hooks）

**典型操作**：`list_*`、`dump_*`、`find_*`、`log_*_events`（非调试器/反编译器事件）

**反例**（不要放这里）：
- 反编译 C 伪代码 → `decompiler/`
- 仅为了 UI 展示而读取反汇编数据 → `ui/`
- 操作结构体/枚举类型定义 → `types/`

#### `decompiler/` — 反编译操作

**判定条件（满足任一即可）**：

- 脚本的核心目的是**调用反编译器**（`ida_hexrays.decompile`、`gen_microcode`）或操作反编译输出（C-tree、微码）
- 操作反编译器特有的数据结构：`cfunc_t`、`ctree_visitor_t`、`mba_t`、`minsn_t`、`cexpr_t`、`cinsn_t`
- 使用 `Hexrays_Hooks` 监听反编译器事件
- 安装反编译器优化规则（`optinsn_t`、`optblock_t`、`udc_filter_t`）
- 修改反编译输出的局部变量（`modify_user_lvars`、`user_lvar_modifier_t`）

**关键模块信号**：`ida_hexrays`（必须有 `import ida_hexrays`）

**典型操作**：反编译函数、生成/转储微码、遍历 C-tree、修改反编译输出文本、反编译器事件钩子

**反例**：
- 只读取函数信息但不反编译 → `disassembler/`
- 仅为了 UI 而在反编译窗口添加操作 → `ui/`

#### `ui/` — 用户界面操作

**判定条件（满足任一即可）**：

- 脚本的核心目的是**创建、修改或操控 UI 组件**（窗口、菜单、工具栏、表格、图形视图、列表视图等）
- 注册动作（`register_action`、`action_handler_t`）且主要目的是在 UI 中添加交互功能
- 使用 `UI_Hooks` 或 `View_Hooks` 监听 UI 事件
- 使用 PyQt/PySide6 与 IDA 的 dockable widget 集成
- 操控颜色渲染（`get_lines_rendering_info`、line coloring）
- 使用 `Choose` 类创建表格选择器、使用 `simplecustviewer_t` 创建自定义列表

**关键模块信号**：`ida_kernwin`（大量使用 `action_desc_t`、`action_handler_t`、`UI_Hooks`、`Choose`、`simplecustviewer_t`）、`ida_graph`（GraphViewer）

**ui/ 内部可进一步细分**（按需创建子目录）：
- `ui/forms/` — 表单与用户输入对话框
- `ui/graphs/` — 图形视图操作
- `ui/listings/` — 自定义列表视图
- `ui/tabular_views/` — 表格选择器（Choose）
- `ui/pyqt/` — PyQt/PySide6 集成
- `ui/uihooks/` — UI 事件钩子
- `ui/waitbox/` — 进度对话框
- `ui/misc/` — 菜单等杂项 UI 操作

**反例**：
- 脚本仅在反编译窗口上操作，但核心是反编译逻辑 → `decompiler/`
- 脚本仅用 `ida_kernwin.msg()` 输出信息，无 UI 交互 → 按主要功能归类（通常 `disassembler/`）

#### `types/` — 类型系统操作

**判定条件（满足任一即可）**：

- 脚本的核心目的是**创建、修改、查询类型定义**（结构体、联合体、枚举、类型库、函数原型等）
- 使用 `ida_typeinf` 的类型 API：`tinfo_t`、`udt_type_data_t`、`udm_t`、`parse_decls`、`apply_tinfo` 等
- 操作函数栈帧变量（`ida_frame`）的名称/类型
- 创建/修改类型库文件（`.til`）
- 实现自定义调用约定（`custom_callcnv_t`）

**关键模块信号**：`ida_typeinf`（核心依赖）、`ida_frame`（栈帧操作）

**典型操作**：`create_*struct*`、`create_*enum*`、`list_*_member`、`change_stkvar_*`、`apply_*tinfo`、`import_type`

**反例**：
- 仅读取函数原型但不操作类型系统 → `disassembler/`
- 在反编译器中修改局部变量类型 → `decompiler/`（用 `modify_user_lvars`）

#### `debugger/` — 调试器操作

**判定条件（满足任一即可）**：

- 脚本的核心目的是**驱动调试会话**（启动/暂停/单步/继续）或**查询调试状态**（寄存器、调用栈）
- 使用 `ida_dbg` 模块控制调试流程
- 使用 `DBG_Hooks` 监听调试器事件
- 使用 `ida_idd.Appcall` 在被调试进程中执行代码
- 查询被调试进程的符号、模块信息

**关键模块信号**：`ida_dbg`、`ida_idd`（Appcall）、`DBG_Hooks`

**debugger/ 内部可进一步细分**：
- `debugger/misc/` — 打印寄存器、调用栈等简单查询
- `debugger/dbghooks/` — 调试器事件钩子与自动步进
- `debugger/appcall/` — 在被调试进程中执行代码

**反例**：
- 仅读取反汇编信息而不涉及调试器 → `disassembler/`

#### `misc/` — 杂项

**判定条件（满足任一即可）**：

- 脚本**不属于以上任何类别**
- 涉及 IDAPython 初始化（`idapythonrc.py`）
- 扩展 IDC 运行时（`add_idc_func`）
- 插件基础设施（64位转换、合并功能等）

**misc/ 内部可进一步细分**：
- `misc/cvt64/` — 64位数据库转换
- `misc/merge/` — 插件合并功能

#### `idbs/` — 测试用数据库

用于存放测试用的 IDB/I64 文件，非脚本目录。仅当脚本需要附带测试数据库时使用。

### 分类决策流程图

```
脚本是否 import ida_hexrays 并调用反编译器?
├─ 是 → decompiler/
└─ 否 → 脚本是否使用 ida_dbg 或 ida_idd?
    ├─ 是 → debugger/
    └─ 否 → 脚本是否大量使用 ida_kernwin 的 UI API
            (action_desc_t, UI_Hooks, Choose, simplecustviewer_t)?
        ├─ 是 → ui/
        └─ 否 → 脚本是否操作 ida_typeinf 的类型系统
                (tinfo_t, udt_type_data_t, parse_decls)?
            ├─ 是 → types/
            └─ 否 → 脚本是否查询/枚举反汇编数据?
                ├─ 是 → disassembler/
                └─ 否 → misc/
```

### 特殊说明

- `main.py` 当前为 PyCharm 自动生成的占位文件，开发时应替换为实际入口。
- `.venv/` 为本地开发环境。
- 新脚本应按功能命名（如 `list_encrypted_strings.py`）。
- 脚本中如需用户交互，使用 `ida_kernwin.ask_str`、`ida_kernwin.ask_yn` 等函数。
- 日志、注释都应该使用中文。
