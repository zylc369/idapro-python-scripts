# 环境搭建指南

> 逆向分析工具链安装指南，按平台分类。

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

```cmd
pip install capstone unicorn gmpy2 frida
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

```bash
pip3 install capstone unicorn gmpy2 frida
```

验证：
```bash
gcc --version && python3 -c "import capstone; print('capstone OK')"
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

```bash
pip3 install capstone unicorn gmpy2 frida
```

验证：
```bash
clang --version && python3 -c "import capstone; print('capstone OK')"
```

---

## 自动检测

所有平台统一使用环境检测脚本：

```bash
python3 detect_env.py --force
```

成功输出：
```json
{"success": true, "data": {...}, "errors": []}
```

如有缺失工具，脚本会给出具体安装指引。
