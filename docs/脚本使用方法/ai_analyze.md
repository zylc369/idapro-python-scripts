# AI 辅助分析

使用 AI 分析函数及其内部引用的所有符号，自动重命名和生成注释。

## 架构

| 文件 | 职责 |
|------|------|
| `ai_utils.py` | 共享工具函数（函数匹配、符号提取、AI 调用、BFS 遍历） |
| `ai_rename.py` | AI 辅助符号重命名（AIRenamer 类 + 批量编排） |
| `ai_comment.py` | AI 辅助注释生成（AICommenter 类 + 批量编排） |
| `ai_analyze.py` | 统合入口（对话框 / CLI / headless / 终端四模式，无需 shell wrapper） |

扩展新功能时，只需：
1. 在 `disassembler/` 下创建新的 `ai_xxx.py` 模块
2. 在 `ai_analyze.py` 的 `_ACTIONS` 列表中添加一条注册
3. 在 `_IN_IDA` 块中添加对应的 `_handle_xxx` 处理函数并 `_register_handler`

## 功能标志（可任意组合）

| 标志 | 说明 |
|------|------|
| `--rename` | AI 辅助符号重命名（函数、局部变量、全局数据、结构体字段） |
| `--comment` | AI 辅助注释生成（函数摘要 + 行内注释，汇编 + 伪代码双写） |

可同时指定 `--rename --comment`，此时对每个函数先执行重命名再生成注释，
使注释基于重命名后的代码，提升注释质量。

## 重命名范围

| 符号类型 | 示例 | 重命名 API |
|----------|------|-----------|
| 函数名 | `sub_XXXXX` | `ida_name.set_name()` |
| 局部变量 | `v1`、`v2` | Hex-Rays `modify_user_lvars()` |
| 全局数据 | `dword_XXXXX`、`qword_XXXXX`、`off_XXXXX` | `ida_name.set_name()` |
| 结构体字段 | `field_0`、`field_4` | `tinfo_t.rename_udm()` |

## 前置条件

- IDA Pro 已加载数据库（.i64 / .idb）
- 已安装 opencode CLI 并加入 PATH（AI 调用依赖）
- 局部变量和结构体字段重命名需要 Hex-Rays Decompiler 插件
- 终端模式需要 IDA Pro 的 `idat` 命令行工具

## 使用方式

### 1. 对话框模式（IDA GUI 内，无参数）

```python
exec(open("disassembler/ai_analyze.py", encoding="utf-8").read())
```

弹出对话框，勾选功能（重命名/注释）、输入函数名或通配符模式。

### 2. CLI 模式（IDA GUI 内，通过 sys.argv 传参）

仅重命名：

```python
import sys
sys.argv = ["", "--rename", "--pattern", "main_0", "--recursive"]
exec(open("disassembler/ai_analyze.py", encoding="utf-8").read())
```

仅注释：

```python
import sys
sys.argv = ["", "--comment", "--pattern", "sub_wer*", "--dry-run"]
exec(open("disassembler/ai_analyze.py", encoding="utf-8").read())
```

重命名 + 注释：

```python
import sys
sys.argv = ["", "--rename", "--comment", "--pattern", "main_0", "--recursive", "--max-depth", "3"]
exec(open("disassembler/ai_analyze.py", encoding="utf-8").read())
```

### 3. 终端模式（命令行，直接 python 调用，自动调用 idat）

脚本自动检测运行环境：IDA 内直接执行分析逻辑，终端内自动调用 `idat` 做 headless 分析。

仅重命名：

```bash
python disassembler/ai_analyze.py --rename -p "main_0" -i binary.i64 -r
```

仅注释：

```bash
python disassembler/ai_analyze.py --comment -p "main_0" -i binary.i64
```

重命名 + 注释：

```bash
python disassembler/ai_analyze.py --rename --comment -p "main_0" -i binary.i64 -r --max-depth 3
```

仅预览（不实际执行）：

```bash
python disassembler/ai_analyze.py --rename -p "main_0" -i binary.i64 --dry-run
```

指定日志文件路径：

```bash
python disassembler/ai_analyze.py --rename --comment -p "main_0" -i binary.i64 -l /tmp/analyze.log
```

指定 IDA Pro 安装路径：

```bash
python disassembler/ai_analyze.py --rename -p "main_0" -i binary.i64 --ida-path /path/to/ida
```

### 4. Headless 模式（直接使用 idat，不经过终端模式）

```bash
IDA_ACTIONS=rename IDA_PATTERN="main_0" \
  idat -A -S"disassembler/ai_analyze.py" binary.i64

IDA_ACTIONS=rename,comment IDA_PATTERN="main_0" IDA_RECURSIVE=1 IDA_MAX_DEPTH=3 \
  idat -A -S"disassembler/ai_analyze.py" binary.i64
```

## CLI 参数说明

```
python disassembler/ai_analyze.py --rename [--comment] --pattern <值> --input <路径> [选项]

功能标志:
  --rename                AI 辅助符号重命名
  --comment               AI 辅助注释生成
  （可同时指定，每个函数内先 rename 后 comment）

通用参数:
  --pattern, -p <值>       必填，函数名或通配符模式
  --dry-run                可选，仅预览 AI 建议，不实际执行
  --recursive, -r          可选，递归分析被调用的自动命名函数
  --max-depth <N>          可选，递归最大深度（默认 2）

终端模式专用参数:
  --input, -i <路径>       目标文件（终端模式必填）
  --ida-path <路径>        IDA Pro 安装目录路径（默认: 自动检测或交互输入）
  --log, -l <路径>         日志文件路径（默认: 当前目录/ai_analyze.log）
```

## 环境变量说明（headless 模式）

| 变量 | 说明 |
|------|------|
| `IDA_ACTIONS` | 必填，逗号分隔的动作列表，如 `rename` / `comment` / `rename,comment` |
| `IDA_PATTERN` | 必填，函数名或通配符模式 |
| `IDA_DRY_RUN` | 可选，设置为任意非空值启用仅预览模式 |
| `IDA_RECURSIVE` | 可选，设置为任意非空值启用递归分析 |
| `IDA_MAX_DEPTH` | 可选，递归最大深度（默认 2） |

## 通配符模式示例

| 模式 | 含义 |
|------|------|
| `main` | 精确匹配名为 main 的函数 |
| `sub_12345` | 精确匹配指定函数 |
| `sub_123*` | 匹配所有以 `sub_123` 开头的函数 |
| `sub_*` | 匹配所有自动生成的 sub_ 函数 |
| `*AES*` | 匹配名称中包含 AES 的函数 |

> 通配符匹配最多返回 100 个函数，超过时请使用更精确的模式。

## 注意事项

- AI 分析需要网络连接（通过 opencode CLI 调用）
- 每个函数每个动作各一次 AI 调用（`--rename --comment` = 两次调用）
- 建议先用 `--dry-run` 预览 AI 建议质量，确认满意后再实际执行
- 局部变量重命名需要 Hex-Rays 反编译器，无此插件时跳过
- 结构体字段重命名通过类型系统 API，会影响所有引用该字段的位置
- 递归深度不宜过大（建议不超过 3），否则耗时可能很长
- 终端模式首次运行时会交互式询问 IDA Pro 路径，之后保存到 `.config/ida_config.json`
