# AI 辅助符号重命名

使用 AI 分析函数及其内部引用的所有符号，自动将自动生成名称重命名为有意义的名称。

支持精确函数名和通配符模式匹配（如 `sub_123*`），可批量处理，可递归分析。

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

## 工作流程

1. 按函数名或通配符模式匹配目标函数
2. 反编译函数，提取所有可重命名符号（函数、局部变量、全局数据、结构体字段）
3. 将反编译代码 + 符号列表一起发送给 AI，一次性获取所有命名建议
4. 验证 AI 建议的名称合法性后分类执行重命名
5. 在函数地址处添加注释记录 AI 的分析依据
6. 若启用递归，继续分析被调用的自动命名函数

## 使用方式

### 1. 对话框模式（IDA GUI 内，无参数）

```python
exec(open("disassembler/ai_rename_functions.py", encoding="utf-8").read())
```

弹出对话框，输入函数名或通配符模式，可勾选递归和仅预览。

### 2. CLI 模式（IDA GUI 内，通过 sys.argv 传参）

精确名称 + 递归分析：

```python
import sys
sys.argv = ["", "--use-mode", "cli", "--pattern", "main_0", "--recursive"]
exec(open("disassembler/ai_rename_functions.py", encoding="utf-8").read())
```

通配符 + 仅预览：

```python
import sys
sys.argv = ["", "--use-mode", "cli", "--pattern", "sub_wer*", "--dry-run"]
exec(open("disassembler/ai_rename_functions.py", encoding="utf-8").read())
```

### 3. 编程方式调用（IDA GUI 内）

```python
exec(open("disassembler/ai_rename_functions.py", encoding="utf-8").read())
rename_functions("main_0", dry_run=False, recursive=True, max_depth=3)
```

### 4. 命令行 headless 模式（通过 .sh wrapper）

分析指定函数及其调用的所有 sub_ 函数：

```bash
./disassembler/ai_rename_functions.sh -p "main_0" -i binary.i64 -r
```

仅预览：

```bash
./disassembler/ai_rename_functions.sh -p "main_0" -i binary.i64 --dry-run
```

递归 + 自定义深度：

```bash
./disassembler/ai_rename_functions.sh -p "main_0" -i binary.i64 -r --max-depth 3
```

## CLI 参数说明

| 参数 | 说明 |
|------|------|
| `--use-mode cli` | 必填，指定 CLI 模式 |
| `--pattern <值>` | 必填，函数名或通配符模式 |
| `--dry-run` | 可选，仅预览 AI 建议，不实际重命名 |
| `--recursive` | 可选，递归分析被调用的自动命名函数 |
| `--max-depth <N>` | 可选，递归最大深度（默认 2） |

## 环境变量说明（headless 模式）

| 变量 | 说明 |
|------|------|
| `IDA_PATTERN` | 必填，函数名或通配符模式 |
| `IDA_DRY_RUN` | 可选，设置为任意非空值启用仅预览模式 |
| `IDA_RECURSIVE` | 可选，设置为任意非空值启用递归分析 |
| `IDA_MAX_DEPTH` | 可选，递归最大深度（默认 2） |

## .sh wrapper 参数说明

```
用法: ai_rename_functions.sh --pattern <函数名或模式> --input <目标文件> [选项]

必填参数:
  -p, --pattern    <值>   函数名（如 main）或通配符模式（如 sub_123*）
  -i, --input      <路径>  目标二进制文件或 .i64 数据库路径

可选参数:
  -r, --recursive         递归分析目标函数调用的自动命名函数（sub_XXXXX）
      --max-depth <N>     递归最大深度（默认: 2）
  -l, --log        <路径>  日志文件路径（默认: 当前执行目录/ai_rename_functions.log）
      --ida-path   <路径>  IDA Pro 安装目录路径（默认: 自动检测）
      --dry-run            仅预览 AI 建议，不实际重命名
  -h, --help               显示帮助信息
```

## 通配符模式示例

| 模式 | 含义 |
|------|------|
| `main` | 精确匹配名为 main 的函数 |
| `sub_12345` | 精确匹配指定函数 |
| `sub_123*` | 匹配所有以 `sub_123` 开头的函数 |
| `sub_*` | 匹配所有自动生成的 sub_ 函数 |
| `*AES*` | 匹配名称中包含 AES 的函数 |

> 通配符匹配最多返回 100 个函数，超过时请使用更精确的模式。

## AI 输出格式

AI 返回一个 JSON，包含函数名建议和所有符号的命名建议：

```json
{
  "function": "prompt_and_validate_credentials",
  "reasoning": "函数提示用户输入用户名和密码，调用验证函数...",
  "confidence": "high",
  "symbols": {
    "sub_140001596": "validate_credentials",
    "v1": "username",
    "v2": "password",
    "dword_14000XXXX": "max_retries",
    "MyStruct.field_4": "checksum"
  }
}
```

AI 只会返回它能确定用途的符号，不确定的不会包含。

## 注意事项

- AI 分析需要网络连接（通过 opencode CLI 调用）
- 每个函数一次 AI 调用，同时处理函数名 + 所有内部符号
- 建议先用 `--dry-run` 预览 AI 建议质量，确认满意后再实际执行
- 局部变量重命名需要 Hex-Rays 反编译器，无此插件时跳过
- 结构体字段重命名通过类型系统 API，会影响所有引用该字段的位置
- 递归深度不宜过大（建议不超过 3），否则耗时可能很长
