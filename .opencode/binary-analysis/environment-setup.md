# 环境搭建指南

> 逆向分析工具链安装指南，按平台分类。

## 虚拟环境策略

Python 第三方包（capstone、unicorn、gmpy2、frida）安装在专用虚拟环境中，**不污染全局 Python**。

- **venv 位置**: `~/bw-security-analysis/.venv`
- **自动管理**: `detect_env.py` 自动创建 venv 并安装依赖
- **缓存**: 环境检测结果缓存在 `~/bw-security-analysis/env_cache.json`，24 小时有效期
- **手动安装**:
  ```bash
  # Linux/macOS
  ~/bw-security-analysis/.venv/bin/python -m pip install <包名>

  # Windows
  ~/bw-security-analysis/.venv/Scripts/python.exe -m pip install <包名>
  ```
- **重建 venv**: 删除 `~/bw-security-analysis/.venv` 和 `~/bw-security-analysis/env_cache.json`，重新运行 `detect_env.py --force`

**三类 Python 环境**:

| 环境 | 用途 | 可执行文件 |
|------|------|-----------|
| 系统 Python | detect_env.py、内联一行命令 | `python3`/`python` |
| venv Python | 需要第三方包的独立脚本（Unicorn、Frida、gui_verify） | `$BA_PYTHON` |
| IDA Python | IDAPython 脚本（query.py、update.py 等） | `$IDAT` |

## capstone vs IDA Pro — 为什么要装 capstone？

IDA Pro 自带反汇编引擎，但 **capstone 是独立的反汇编框架**，用于 Unicorn 模拟执行：
- Unicorn 依赖 capstone 进行指令解码
- capstone 可在 Python 进程中独立使用（不需要 IDA 运行时）
- 用途：算法验证（Unicorn 模拟原函数）、CTF 快速脚本、脱离 IDA 的自动化分析

总结：IDA Pro 用于交互式分析，capstone + Unicorn 用于自动化验证。两者互补，不冲突。

## 编译器选择：VS Build Tools vs MinGW

**只安装 VS Build Tools 即可**，理由：
- Windows 逆向目标多为 MSVC 编译，VS Build Tools 的 CRT/SEH 与目标一致
- MinGW 的 CRT 与 MSVC 不兼容，链接可能出问题
- `__umul128` 等 intrinsics 只有 MSVC 有（MinGW 用 `__int128`，也可用但不如 intrinsics 直观）
- IDA Pro 自带 Python 也是 MSVC 编译的，与 VS Build Tools 生态一致

如果确实需要 MinGW（如交叉编译 Linux 目标），可以额外安装，但不是必需的。

## 必需工具

| 工具 | 用途 | 必需性 |
|------|------|--------|
| IDA Pro | 反汇编/反编译平台 | **必需** |
| Python 3.8+ | 脚本执行环境 | **必需** |
| C/C++ 编译器 | 高性能求解器编译 | **必需**（计算密集型任务） |

## 推荐工具

| 工具 | pip 包名 | 用途 |
|------|---------|------|
| capstone | `capstone` | 反汇编引擎（Unicorn 依赖） |
| unicorn | `unicorn` | CPU 模拟器（算法验证） |
| gmpy2 | `gmpy2` | 大整数运算（密码学） |
| frida | `frida` | 动态 Hook 框架 |

---

## Windows

### C/C++ 编译器：VS Build Tools

1. 下载：https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. 安装时勾选"使用 C++ 的桌面开发"
3. 安装完成后，`detect_env.py` 会自动检测

验证：
```cmd
dir "C:\Program Files (x86)\Microsoft Visual Studio" /s /b | findstr vcvarsall.bat
```

### Python 包

> 自动安装到 venv（`~/bw-security-analysis/.venv`），一般无需手动操作。

手动安装到 venv（自动安装失败时）：
```cmd
~/bw-security-analysis/.venv/Scripts/python.exe -m pip install capstone unicorn gmpy2 frida
```

### 常见问题

- **frida 安装失败**：需要 Rust 编译环境，或尝试 `pip install frida --no-build-isolation`
- **gmpy2 安装失败**：需要 MPIR 库，建议用 conda：`conda install -c conda-forge gmpy2`
- **python3 命令不存在**：Windows 上 IDA 自带 Python 注册为 `python`，非 `python3`

---

## Linux (Debian/Ubuntu)

### C/C++ 编译器

```bash
sudo apt update && sudo apt install -y build-essential libgmp-dev
```

### Python 包

> 自动安装到 venv，一般无需手动操作。

手动安装到 venv：
```bash
~/bw-security-analysis/.venv/bin/python -m pip install capstone unicorn gmpy2 frida
```

验证：
```bash
gcc --version && ~/bw-security-analysis/.venv/bin/python -c "import capstone; print('capstone OK')"
```

### 常见问题

- **gmpy2 需要系统 GMP**：`sudo apt install libgmp-dev`
- **frida 需要 Node.js**：部分功能需要 Node.js 运行时

---

## macOS

### C/C++ 编译器

```bash
xcode-select --install
```

### Python 包

> 自动安装到 venv，一般无需手动操作。

手动安装到 venv：
```bash
~/bw-security-analysis/.venv/bin/python -m pip install capstone unicorn gmpy2 frida
```

验证：
```bash
clang --version && ~/bw-security-analysis/.venv/bin/python -c "import capstone; print('capstone OK')"
```

---

## 自动检测

所有平台统一使用环境检测脚本：

```bash
# 检测全部工具（默认）
python3 detect_env.py --force

# 仅检测 binary-analysis 需要的工具
python3 detect_env.py --force --agent binary-analysis

# 仅检测 mobile-analysis 需要的工具
python3 detect_env.py --force --agent mobile-analysis
```

成功输出：
```json
{"success": true, "data": {...}, "errors": []}
```

如有缺失工具，脚本会给出具体安装指引。

## 配置文件结构

`~/bw-security-analysis/config.json` 结构：

```json
{
  "ida_path": "<IDA Pro 安装路径>",
  "tools": {
    "tool_name": {
      "path": "<可执行文件路径或裸名>",
      "agents": ["agent-name"],
      "required": true,
      "version_cmd": ["--version"],
      "description": "工具描述"
    }
  }
}
```

- `tools` 字段为可选，仅移动端分析需要配置
- `path` 支持裸名（如 `apktool`，通过 PATH 查找）或绝对路径
- `agents` 指定哪些 Agent 需要此工具，`detect_env.py --agent` 按此过滤
