# IDA Pro AI 智能分析命令 — 工具脚本

本目录包含 `/ida-pro-analysis` 命令配套的 IDAPython 工具脚本，专为 opencode AI 编排场景设计。

## 数据与代码分离

| 类别 | 位置 | 说明 |
|------|------|------|
| **代码**（本目录） | `.opencode/commands/ida-pro-analysis-scripts/` | 版本控制，git 管理 |
| **数据** | `~/bw-ida-pro-analysis/` | 运行时产物，不提交 |

```
# 代码（git 仓库）
.opencode/commands/ida-pro-analysis-scripts/
├── _base.py         # 公共基础设施（日志、环境变量、headless 入口、JSON 输出）
├── _utils.py        # 共享业务工具（thunk 追踪、数据读取、地址解析）
├── query.py         # 查询操作（12 种查询类型）
├── update.py        # 更新操作（4 种操作类型）
├── README.md        # 本文件
└── scripts/         # 沉淀脚本库（AI 生成的经验证脚本）
    └── registry.json # 脚本注册表
```

## 调用方式

所有脚本通过 `idat -A -S` headless 模式调用，通过环境变量传参：

```bash
# 查询操作
IDA_QUERY=<类型> IDA_OUTPUT=<输出路径> [IDA_FUNC_ADDR=<地址>] [IDA_PATTERN=<模式>] \
  "<ida_path>/idat" -A -S"<脚本绝对路径>" -L<日志路径> <目标文件>

# 更新操作
IDA_OPERATION=<操作> IDA_OUTPUT=<输出路径> [其他参数] \
  "<ida_path>/idat" -A -S"<脚本绝对路径>" -L<日志路径> <目标文件>
```

## query.py 查询类型

**注意**：`decompile`、`disassemble`、`func_info` 会自动追踪 thunk 链到真实函数。

| IDA_QUERY 值 | 说明 | 额外参数 |
|-------------|------|---------|
| `entry_points` | 枚举入口点（智能识别 exe/dll/so） | 无 |
| `functions` | 按模式匹配函数 | `IDA_PATTERN` |
| `decompile` | 反编译函数（返回 C 伪代码，自动追踪 thunk） | `IDA_FUNC_ADDR` |
| `disassemble` | 反汇编函数（自动追踪 thunk） | `IDA_FUNC_ADDR` |
| `func_info` | 函数详细信息（调用者/被调用者/字符串） | `IDA_FUNC_ADDR` |
| `xrefs_to` | 交叉引用（谁引用了它） | `IDA_ADDR` 或 `IDA_FUNC_ADDR` |
| `xrefs_from` | 交叉引用（它引用了谁） | `IDA_FUNC_ADDR` |
| `strings` | 搜索字符串及引用位置 | `IDA_PATTERN`（子串匹配） |
| `imports` | 列出所有导入函数 | 无 |
| `exports` | 列出所有导出函数 | 无 |
| `segments` | 列出所有段信息 | 无 |
| `read_data` | 读取全局数据 | `IDA_ADDR` + `IDA_READ_MODE` + `IDA_READ_SIZE` + `IDA_DEREF` |

### read_data 读取模式

| `IDA_READ_MODE` | 说明 | 额外参数 |
|-----------------|------|---------|
| `auto`（默认） | 自动判断数据类型 | `IDA_READ_SIZE`（默认 64） |
| `string` | 读取 null-terminated 字符串 | 无 |
| `bytes` | 读取原始字节（hex + ASCII） | `IDA_READ_SIZE`（默认 64） |
| `pointer` | 读取指针值 | `IDA_DEREF=1` 解引用 |

## update.py 操作类型

| IDA_OPERATION 值 | 说明 | 额外参数 |
|-----------------|------|---------|
| `rename` | 重命名符号 | `IDA_OLD_NAME` + `IDA_NEW_NAME` |
| `set_func_comment` | 设置函数注释 | `IDA_FUNC_ADDR` + `IDA_COMMENT` |
| `set_line_comment` | 设置行内注释 | `IDA_ADDR` + `IDA_COMMENT` |
| `batch` | 批量操作 | `IDA_BATCH_FILE`（JSON 文件路径） |

通用参数：`IDA_DRY_RUN=1` 只预览不执行。

## 输出格式

所有脚本输出结构化 JSON 到 `IDA_OUTPUT` 指定的路径：

```json
{
  "success": true,
  "query": "entry_points",
  "data": { ... },
  "error": null
}
```

## 编码规则

- 使用 `from _base import run_headless, log, ...` 导入公共模块
- headless 入口在模块级执行（不在 `if __name__` 内）
- 禁止 `import idc`、`import idaapi`、`from ida_xxx import yyy`
- 字符串使用双引号
- 日志使用中文，包含 `[*]`/`[+]`/`[!]` 前缀
- 必须调用 `auto_wait()` 和 `qexit()`（由 `run_headless` 自动处理）
