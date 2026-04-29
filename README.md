# Binary-Analysis Agent

基于 IDA Pro + AI 的二进制逆向分析助手。输入 IDA 数据库路径和分析需求，Agent 自动编排查询、反编译、动态分析、验证等流程，完成逆向分析任务。

## 它能做什么

- **逆向分析**：分析算法、定位关键函数、理解程序逻辑
- **符号重命名 & 注释**：AI 自动将 `sub_XXXXX`、`v1` 等自动命名重命名为有意义的名称，生成中文注释
- **加壳检测 & 脱壳**：自动检测加壳，支持 IDA 调试器 dump、Frida 动态脱壳
- **算法验证**：通过 Unicorn 模拟执行、Hook 注入、GUI 自动化等方式验证分析结果
- **动态分析**：调试器断点、Frida 插桩、进程 Patch

## 快速开始

### 1. 安装前置条件

| 依赖 | 用途 | 必需 |
|------|------|------|
| [OpenCode](https://opencode.ai) | Agent 运行平台 | 是 |
| IDA Pro（含 Hex-Rays 反编译器） | 反汇编/反编译 | 是 |
| Python 3.8+ | 脚本执行 | 是 |
| C/C++ 编译器 | 高性能求解器（计算密集型任务） | 推荐 |

详细环境搭建指南见 [`.opencode/binary-analysis/environment-setup.md`](.opencode/binary-analysis/environment-setup.md)。

### 2. 使用方式

在项目目录下启动 OpenCode，直接用自然语言描述分析需求：

```
> 分析 crackme.exe，找到注册验证逻辑并绕过

> 分析 /path/to/target.i64 中 sub_401000 的算法

> 这个二进制用了什么壳？帮我脱壳
```

Agent 会自动：
1. 检测环境（IDA 路径、编译器、Python 工具包）
2. 收集基础信息（段、入口点、导入表、字符串、加壳检测）
3. 规划分析方案
4. 执行分析并验证结果

### 3. 典型使用场景

| 场景 | 示例输入 |
|------|---------|
| 分析未知函数 | "分析 sub_401000 做了什么" |
| 寻找验证逻辑 | "找到 license 验证函数，分析验证算法" |
| 绕过保护 | "绕过这个 CrackMe 的注册检查" |
| 脱壳 | "检测并脱壳这个二进制" |
| 算法还原 | "还原 0x402000 处的加密算法" |
| 批量重命名 | "重命名 sub_401* 下所有函数" |

## 工作原理

```
用户 ──→ OpenCode ──→ Binary-Analysis Agent
                         │
                    阶段 0: 环境检测
                    阶段 A: 信息收集（自动）
                    阶段 B: 分析规划（输出方案）
                    阶段 C: 执行与监控
                         │
                    ┌────┼────┐
                    ▼    ▼    ▼
                 query  update scripts
                 .py    .py   /*.py
                    │    │    │
                    ▼    ▼    ▼
                  idat -A -S <script> <target>
                    │
                    ▼
               IDA 数据库
```

Agent 通过 `idat` headless 模式间接操作 IDA 数据库，不直接操作 GUI。所有操作通过环境变量传参，结果以结构化 JSON 返回。

## 可用工具脚本

### 查询操作（`query.py`）

| 查询类型 | 说明 | 关键参数 |
|----------|------|---------|
| `entry_points` | 枚举入口点 | 无 |
| `functions` | 按模式匹配函数 | `IDA_PATTERN` |
| `decompile` | 反编译函数 | `IDA_FUNC_ADDR` |
| `disassemble` | 反汇编函数 | `IDA_FUNC_ADDR` |
| `func_info` | 函数详情（调用者/被调用者/字符串） | `IDA_FUNC_ADDR` |
| `xrefs_to` | 谁引用了它 | `IDA_ADDR` 或 `IDA_FUNC_ADDR` |
| `xrefs_from` | 它引用了谁 | `IDA_FUNC_ADDR` |
| `strings` | 搜索字符串及引用位置 | `IDA_PATTERN` |
| `imports` | 列出导入函数 | 无 |
| `exports` | 列出导出函数 | 无 |
| `segments` | 段信息（含异常信号） | 无 |
| `read_data` | 读取全局数据 | `IDA_ADDR` + `IDA_READ_MODE` |
| `packer_detect` | 加壳检测 | 无 |

### 更新操作（`update.py`）

| 操作类型 | 说明 | 关键参数 |
|----------|------|---------|
| `rename` | 重命名符号 | `IDA_OLD_NAME` + `IDA_NEW_NAME` |
| `set_func_comment` | 函数注释 | `IDA_FUNC_ADDR` + `IDA_COMMENT` |
| `set_line_comment` | 行注释 | `IDA_ADDR` + `IDA_COMMENT` |
| `batch` | 批量操作 | `IDA_BATCH_FILE`（JSON） |

通用：`IDA_DRY_RUN=1` 只预览不执行。

### 专用脚本

| 脚本 | 用途 |
|------|------|
| `initial_analysis.py` | 一键初始分析（段/入口/导入/字符串/壳检测/场景分类） |
| `debug_dump.py` | IDA 调试器脱壳 dump（PE/ELF） |
| `detect_env.py` | 环境检测（IDA/Python/编译器） |
| `gui_verify.py` | Win32 GUI 自动化验证 |
| `process_patch.py` | 进程 Patch + 值捕获 |

### GUI 自动化工具

| 脚本 | 用途 |
|------|------|
| `gui_launch.py` | 启动/等待/终止目标程序 |
| `gui_capture.py` | 截图 |
| `gui_act.py` | 键鼠操作（click/type/hotkey/scroll） |

## AI 辅助分析脚本（IDA GUI 内使用）

除了 Agent 自动编排外，以下脚本可在 IDA GUI 内手动使用：

| 脚本 | 功能 | 详细文档 |
|------|------|---------|
| `disassembler/ai_analyze.py` | AI 重命名 + 注释（四模式运行） | [`docs/脚本使用方法/ai_analyze.md`](docs/脚本使用方法/ai_analyze.md) |
| `disassembler/dump_func_disasm.py` | 函数反汇编导出 + AI 反编译 | 脚本头部 docstring |
| `disassembler/frida_unpack.py` | PE 脱壳（Frida 动态插桩） | 脚本头部 docstring |

### AI 辅助分析快速示例

**IDA GUI 内对话框模式：**

```python
exec(open("disassembler/ai_analyze.py", encoding="utf-8").read())
```

**终端命令行：**

```bash
python disassembler/ai_analyze.py --rename --comment -p "main_0" -i binary.i64 -r
```

## 项目结构

```
.opencode/
  agents/binary-analysis.md     # Agent prompt（分析编排规则）
  plugins/security-analysis.ts    # Plugin（上下文持久化 + 环境注入）
  binary-analysis/              # Agent 工具脚本
    _base.py                    #   公共基础模块
    _utils.py                   #   共享业务工具
    _analysis.py                #   共享分析逻辑
    query.py                    #   查询操作（13 种类型）
    update.py                   #   更新操作（4 种类型）
    scripts/                    #   沉淀脚本 + 工具脚本
      registry.json             #     脚本注册表
      initial_analysis.py       #     初始分析流水线
      debug_dump.py             #     调试器 dump
      detect_env.py             #     环境检测
      gui_*.py                  #     GUI 自动化工具
      process_patch.py          #     进程 Patch
    knowledge-base/             #   知识库（按需加载）
      analysis-planning.md      #     分析规划模板
      templates.md              #     命令模板（bash + PowerShell）
      packer-handling.md        #     加壳处理
      dynamic-analysis.md       #     动态分析
      crypto-validation-patterns.md  # 密码学验证
      verification-patterns.md  #     结果验证模式
      ...更多知识库文档
    environment-setup.md        #   环境搭建指南
    context-persistence.md      #   上下文持久化方案
disassembler/                   # IDA GUI 内使用的脚本
  ai_analyze.py                 #   AI 辅助分析统合入口
  ai_rename.py                  #   AI 符号重命名
  ai_comment.py                 #   AI 注释生成
  ai_utils.py                   #   AI 分析工具函数
  dump_func_disasm.py           #   反汇编导出
  frida_unpack.py               #   PE 脱壳
ai/opencode.py                  # OpenCode 非交互封装
docs/                           # 文档
rules/                          # 编码规范
test/                           # 测试
```

## 数据与代码分离

| 类别 | 位置 | 说明 |
|------|------|------|
| **代码** | `.opencode/binary-analysis/`（git 管理） | 版本控制 |
| **数据** | `~/bw-security-analysis/`（不提交） | 运行时产物 |

```
~/bw-security-analysis/
  config.json              # IDA 路径等配置
  env_cache.json           # 环境检测缓存（24h 有效期）
  .venv/                   # Python 虚拟环境（capstone/unicorn/frida 等）
  workspace/               # 分析任务目录
    <timestamp>_<id>/      #   每次分析一个目录
      initial.json         #   初始分析结果
      result.json          #   查询/更新结果
      idat.log             #   idat 日志
```

## 知识库

Agent 内置 18 个知识库文档，按需加载（不在分析开始时全部读取），涵盖：

| 知识库 | 触发条件 |
|--------|---------|
| 分析规划 | 每次分析启动后 |
| 命令模板 | 构造 idat 命令时 |
| 加壳处理 | 检测到加壳 |
| 动态分析 | 需要调试/运行时分析 |
| 密码学验证 | 检测到密码学特征 |
| 算法验证（Unicorn） | 需要模拟执行验证 |
| Frida Hook | IDA 调试器失败时 |
| GUI 自动化 | GUI 程序验证 |
| 进程 Patch | 需要写入补丁/捕获内存 |
| 技术选型 | 算法实现/性能敏感计算 |

## 测试

```bash
pytest                                    # Python 测试（ai/ 模块，不依赖 IDA）
pytest test/test_opencode.py              # 单个测试文件
pytest -k "test_success"                  # 按名称过滤
bats test/shell/                          # Shell 测试（需 bats-core）
```

## 编码规范

- 禁止 `import idc`、`import idaapi`、`from ida_xxx import yyy`
- 字符串使用双引号
- 日志使用中文，`[*]`/`[+]`/`[!]` 前缀
- 详见 [`rules/coding-conventions.md`](rules/coding-conventions.md)

## 参考资源

- **IDAPython 示例**：`vendor/ida-sdk/src/plugins/idapython/examples/`
- **IDAPython 官方文档**：https://python.docs.hex-rays.com/
- **OpenCode 文档**：https://opencode.ai
