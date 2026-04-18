# 脚本分类标准

以下分类标准提取自 IDAPython 官方示例仓库（`vendor/ida-sdk/src/plugins/idapython/examples/`）的目录组织方式。新脚本**必须**根据其核心功能放入对应子目录。

## 分类判定原则

1. **按核心功能判定**：脚本的主要目的是什么，就归入哪个目录。即使脚本同时涉及多个领域，也以**主要功能**为准。
2. **按主要依赖模块判定**：当功能边界模糊时，以脚本**最依赖的 IDAPython 模块**作为分类依据。
3. **无法归入已有类别 → `misc/`**：不属于任何明确类别的脚本放入 `misc/`。

## 各目录分类标准

### `disassembler/` — 反汇编操作

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

### `decompiler/` — 反编译操作

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

### `ui/` — 用户界面操作

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

### `types/` — 类型系统操作

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

### `debugger/` — 调试器操作

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

### `misc/` — 杂项

**判定条件（满足任一即可）**：

- 脚本**不属于以上任何类别**
- 涉及 IDAPython 初始化（`idapythonrc.py`）
- 扩展 IDC 运行时（`add_idc_func`）
- 插件基础设施（64位转换、合并功能等）

**misc/ 内部可进一步细分**：
- `misc/cvt64/` — 64位数据库转换
- `misc/merge/` — 插件合并功能

### `idbs/` — 测试用数据库

用于存放测试用的 IDB/I64 文件，非脚本目录。仅当脚本需要附带测试数据库时使用。

## 分类决策流程图

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
