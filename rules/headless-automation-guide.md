# Headless 自动化逆向指南

## 架构概述

Headless 自动化的核心是 **.py（业务逻辑）+ .sh（运维胶水）** 二层结构：

| 层 | 职责 | 运行环境 |
|---|---|---|
| `.py` | IDAPython 业务逻辑（反汇编、导出等） | IDA 内部（idat 加载执行） |
| `.sh` | 构造 `idat` 命令行、路径解析、环境检测 | 终端 bash |

**为什么需要 .sh？** IDAPython 脚本依赖 `ida_funcs`、`ida_kernwin` 等专有模块，不能直接 `python xxx.py` 执行，必须由 `idat`（IDA 命令行版本）加载运行。而 `idat` 命令行本身写起来繁琐（路径检测、数据库锁检测、相对路径转换），所以 .sh 封装了这些脏活。

**最终调用链：** 用户执行 `.sh` → .sh 构造 `idat -A -S"xxx.py"` 命令 → idat 加载 .py → .py 通过环境变量读取参数 → .py 执行业务逻辑 → .py 调用 `ida_pro.qexit()` 退出。

## 参考实现

| 文件 | 说明 |
|---|---|
| `disassembler/dump_func_disasm.py` | 完整参考实现（支持全部三种模式） |
| `disassembler/dump_func_disasm.sh` | 对应的 shell wrapper |
| `shell/library/detect_ida_path.sh` | IDA 安装路径检测库 |
| `shell/library/detect_db_lock.sh` | IDA 数据库锁检测库 |

## 新建 Headless 脚本的步骤

### 第一步：编写 .py 业务脚本

.py 脚本需要同时支持三种运行模式：

1. **对话框模式**（IDA GUI 内，无参数）→ 弹 `ida_kernwin.Form`
2. **CLI 模式**（IDA GUI 内，`sys.argv` 传参）→ 跳过对话框直接执行
3. **Headless 模式**（终端 `idat` 调用，环境变量传参）→ 等待分析 + 执行 + 退出

#### 必须遵循的模式

```python
# ===== headless 入口（模块级，不能放在 if __name__ == "__main__" 内）=====
_batch = bool(ida_kernwin.cvar.batch)          # True = headless 模式
_env = _parse_env_args()                        # 从环境变量读参数

if _batch and _env is not None:
    _run_headless(_env[0], _env[1])             # 等待分析 → 执行 → qexit
elif _batch:
    # headless 但缺少必要环境变量 → 报错退出
    ida_pro.qexit(1)
elif __name__ == "__main__":
    # GUI 内执行：尝试 CLI 参数解析，失败则弹对话框
    ...
```

#### `_run_headless()` 的固定结构

```python
def _run_headless(param1, param2):
    import ida_auto
    import ida_pro

    ida_kernwin.msg("[*] headless 模式: 等待 IDA 自动分析完成...\n")
    ida_auto.auto_wait()
    ida_kernwin.msg("[*] headless 模式: 自动分析完成，开始执行\n")

    success = do_business_logic(param1, param2)

    exit_code = 0 if success else 1
    ida_kernwin.msg(f"[{'+'if success else '!'}] headless 模式: {'成功' if success else '失败'} (exit code {exit_code})\n")
    ida_pro.qexit(exit_code)
```

#### 环境变量命名约定

| 环境变量 | 用途 | 示例 |
|---|---|---|
| `IDA_FUNC_ADDR` | 函数名或十六进制地址 | `main` / `0x401000` |
| `IDA_OUTPUT` | 输出文件或目录路径 | `/tmp/output.asm` |

新增脚本需要新参数时，遵循 `IDA_` 前缀 + `UPPER_SNAKE_CASE` 命名。

#### 关键注意事项

1. **headless 入口必须在模块级执行**。IDA 通过 `ida_idaapi.py` 的 `exec(code, g)` 执行 `-S` 指定的脚本，此时 `__name__` 是脚本文件名而非 `"__main__"`，所以 `if __name__ == "__main__"` 永远为 False。
2. **必须调用 `ida_auto.auto_wait()`**。idat 启动后需要等待 IDA 完成自动分析，否则函数、交叉引用等数据不完整。
3. **必须调用 `ida_pro.qexit(exit_code)`**。headless 模式没有 GUI 关闭按钮，不调用 `qexit` 进程不会退出。
4. **`import ida_auto` 和 `import ida_pro`** 可以在 `_run_headless` 内部延迟导入，避免非 headless 模式加载不必要模块。
5. **使用 `ida_kernwin.cvar.batch` 判断是否 headless**，`True` 表示 headless，`False` 表示 GUI。

### 第二步：编写 .sh shell wrapper

.sh 的职责是封装 idat 命令行的构造细节。标准结构：

```bash
#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CALL_DIR="$(pwd)"
REPO_ROOT="${REPO_ROOT:-"$(cd "$SCRIPT_DIR/.." && pwd)"}"
readonly PYTHON_SCRIPT="$SCRIPT_DIR/xxx.py"   # 指向对应的 .py

source "$SCRIPT_DIR/../shell/library/detect_ida_path.sh"
source "$SCRIPT_DIR/../shell/library/detect_db_lock.sh"

# 1. 解析命令行参数 (--addr, --input, --output, --log 等)
# 2. 校验必填参数
# 3. 将相对路径转为绝对路径（idat 需要绝对路径）
# 4. 调用 execute_idat 函数
```

#### `execute_idat()` 的固定结构

```bash
execute_idat() {
    local ida_dir
    ida_dir=$(detect_ida_path "${ida_path:-}") || return 1    # 检测 IDA 路径
    check_db_lock "$input_file" || return 1                     # 检测数据库锁

    mkdir -p "$(dirname "$output")"
    mkdir -p "$(dirname "$log_path")"

    IDA_FUNC_ADDR="$addr" \
    IDA_OUTPUT="$output" \
    "$ida_dir/idat" -v -A \
        -L"$log_path" \
        -S"$PYTHON_SCRIPT" \
        "$input_file"
}
```

#### idat 关键参数说明

| 参数 | 说明 |
|---|---|
| `-A` | 自动模式，不弹任何对话框 |
| `-S"script.py"` | 加载完成后执行指定脚本（路径相对于当前目录） |
| `-L"/path/to/log"` | 日志输出文件（idat 自身日志，非脚本 `msg` 输出） |
| `-v` | 可选，显示详细输出 |
| 最后一个位置参数 | 目标二进制文件或 `.i64` 数据库路径（必须绝对路径） |

#### 可复用的 shell 库

| 库 | 用途 | 关键函数 |
|---|---|---|
| `shell/library/detect_ida_path.sh` | IDA 安装路径检测 | `detect_ida_path [显式路径]` |
| `shell/library/detect_db_lock.sh` | IDA 数据库锁检测 | `check_db_lock <input_file>` |

**`detect_ida_path`** 检测策略（按优先级）：
1. 显式传入路径 → 直接校验（目录下必须有 `ida` 和 `idat` 可执行文件）
2. 配置文件 `$REPO_ROOT/.config/ida_config.json` 的 `ida_path` 字段 → 需要 `jq` 命令
3. 交互式提示用户输入 → 输入后自动保存到配置文件

**`check_db_lock`** 检测策略：
1. 从 input 文件路径推导 `.id0` 文件路径（`.i64` → `.id0`，`.idb` → `.id0`）
2. `.id0` 不存在 → 数据库从未打开，跳过检测
3. 用 `lsof` 或 `python3 fcntl` 检查 `.id0` 是否被其他进程锁定

### 第三步：验证

```bash
# 基本验证
./xxx.sh --addr main --input /path/to/binary.i64

# 带输出路径
./xxx.sh --addr 0x401000 --output /tmp/result.asm --input /path/to/binary.i64

# 检查日志
cat /tmp/xxx.log
```

## 常见错误与排查

| 问题 | 原因 | 解决 |
|---|---|---|
| `if __name__ == "__main__"` 内代码不执行 | IDA 用 `exec()` 执行脚本，`__name__` 不是 `"__main__"` | headless 入口放模块级 |
| 函数/交叉引用数据不完整 | 未等待 IDA 自动分析完成 | 调用 `ida_auto.auto_wait()` |
| idat 执行完毕不退出 | 未调用 `qexit` | 调用 `ida_pro.qexit(exit_code)` |
| "数据库被锁定"错误 | IDA GUI 正在使用同一数据库 | 关闭 GUI 或等其退出 |
| `ModuleNotFoundError: ida_xxx` | 用 `python` 而非 `idat` 执行脚本 | 必须通过 `idat -S` 加载 |
| 相对路径找不到文件 | idat 工作目录可能与脚本预期不同 | .sh 中将所有路径转为绝对路径 |
