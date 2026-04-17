# 需求：IDA Pro AI 智能分析命令（v3）

> 基于 v2 审计报告修订，修正 7 个关键问题、落地 5 个改进建议。
> v3 补充：脚本沉淀机制、执行过程可见性、不复用现有脚本（新建专用工具体系）。

## 1. 背景与目标

### 1.1 背景

当前项目已具备以下能力：

- **IDAPython 脚本集**（`disassembler/`）：反汇编导出、AI 辅助重命名、AI 辅助注释等，支持 IDA GUI 内运行和 `idat` 无头（headless）运行
- **AI 调用封装**（`ai/opencode.py`）：通过 `opencode run` 非交互模式调用 AI
- **Shell 工具库**（`shell/library/`）：IDA 路径检测、数据库锁检测、日志工具

但这些能力分散在各个独立脚本中，用户需要记忆不同脚本的用法、参数格式，无法用一个统一入口完成从"提出问题"到"获得分析结果"的完整链路。

### 1.2 目标

创建一个 **opencode 自定义命令**（`/ida-pro-analysis`），让用户在 AI 工具中以自然语言描述分析需求，命令自动：

1. **理解意图**：从 `$ARGUMENTS` 中解析出文件路径和分析需求，判断需求类型（查询型 / 分析型）
2. **制定计划**：将需求映射到具体的 idat 调用步骤
3. **执行分析**：通过 Bash 工具调用 `idat` 无头模式执行 IDAPython 脚本，查询/更新 IDA 数据库
4. **迭代优化**：验证结果正确性，如有问题则在重试上限内修复重新执行
5. **持久化**：将分析结果更新到 IDA 数据库（注释、重命名），保存任务存档
6. **反馈结果**：将分析结论清晰呈现给用户

### 1.3 典型使用场景

用户输入格式：`/ida-pro-analysis <文件路径> <分析需求描述>`

| 场景 | 用户输入示例 | 需求类型 | 期望输出 |
|------|-------------|---------|---------|
| 算法逆向 | `/ida-pro-analysis lesson1.exe.i64 分析 main_0 函数的 user_name 和 password 验证逻辑，找出通过验证的输入值` | 分析型 | 具体的用户名和密码值 |
| 入口分析 | `/ida-pro-analysis lesson1.exe.i64 找到所有入口函数` | 查询型 | main、init 等入口列表及其地址 |
| SO 入口分析 | `/ida-pro-analysis lesson1.so.i64 找到所有入口并分析其行为，更新注释到数据库` | 分析型 | JNI_OnLoad、init 等入口列表、行为摘要，IDA 中可查看注释 |
| DLL 导出分析 | `/ida-pro-analysis lesson1.dll.i64 列出所有导出函数及其功能` | 查询型 | 导出函数列表与功能描述 |
| 漏洞定位 | `/ida-pro-analysis target.i64 检查 sub_401000 中是否存在缓冲区溢出风险` | 分析型 | 风险点地址与原因分析 |
| 交叉引用追踪 | `/ida-pro-analysis app.i64 追踪哪些函数引用了字符串 "password"` | 查询型 | 引用链路和上下文分析 |

> **注意**：
>
> 1. 入口分析需要 AI 根据文件类型（exe/dll/so）智能判断入口类型（main、init、JNI_OnLoad、导出函数等），然后选择对应的查询方式。
> 2. 更新相关函数的注释是指更新到 IDA Pro 的数据库文件中，方便后续通过 IDA Pro 查看。
> 3. 上述为举例，分析需求不限于此。

---

## 2. 技术方案

### 2.1 命令架构

**单文件命令**，不拆分子模块（理由：opencode 的 `@` 文件引用是命令加载时一次性展开到 prompt，不存在"依次加载"，拆分子模块只会增加 prompt 长度、增加 AI 迷失风险）。

```
.opencode/commands/
└── ida-pro-analysis.md          # 单一命令文件
```

命令文件结构（从上到下依次为 prompt 内容）：

1. **环境预加载**：通过 `!`shell 输出注入 idat 路径、项目根目录等运行时信息
2. **角色与能力定义**：AI 的角色、可用工具、约束
3. **参数解析规则**：如何从 `$ARGUMENTS` 提取文件路径和需求
4. **执行流程**：按需求类型选择执行策略，每个步骤输出进度信息
5. **工具脚本清单与调用模板**：可用脚本（`query.py`、`update.py`、`scripts/` 沉淀脚本）及其参数格式
6. **脚本生成与沉淀规则**：AI 生成新脚本时的骨架模板、编码规则、沉淀流程
7. **输出格式与安全规则**

### 2.2 参数解析规则（修正 v2 问题 2）

使用 `$ARGUMENTS`（完整原始字符串），**不使用** `$1`/`$2` 等位置参数。

命令 prompt 中的解析指导：

```
用户输入: $ARGUMENTS

解析规则:
1. 找到第一个文件路径式的 token（以 / 开头，或以 .i64/.idb/.exe/.dll/.so 结尾）→ 这是 IDA 数据库文件路径
2. 该路径之前的文本（如有）忽略
3. 该路径之后的所有文本 → 分析需求描述
4. 如果没有检测到文件路径 → 提示用户需要先提供文件路径
```

### 2.3 环境预加载（修正 v2 问题 3）

在命令 prompt 的 frontmatter 之后、正文之前，通过 opencode 的 `!`shell 输出机制注入运行时信息：

```markdown
## 运行环境

IDA Pro 路径: !\`python3 -c "import json,sys;print(json.load(open('.config/ida_config.json'))['ida_path'])"\`
项目根目录: !\`pwd\`
```

这样 AI 在收到 prompt 时就已经知道 idat 的完整路径（含空格），无需额外查询。AI 构造 idat 命令时必须用引号包裹路径。

### 2.4 需求类型与执行策略（改进建议 5）

AI 在执行前先判断需求类型，选择对应的执行策略：

| 需求类型 | 判断依据 | 执行策略 |
|---------|---------|---------|
| **查询型** | 要求"列出"、"找到"、"搜索"已有信息，不涉及推理 | 单次 idat 调用 → 读取输出 → 格式化返回 |
| **分析型** | 要求"分析"、"推导"、"检查"等涉及推理的任务 | 多轮查询 + AI 推理 + 可能的数据库更新 |
| **混合型** | 既有查询又有分析（如"找到入口并分析行为"） | 先查询再分析，组合两种策略 |

### 2.5 执行流程（修正 v2 问题 5：增加终止条件）

```
┌─────────────────┐
│ 1. 解析参数       │  从 $ARGUMENTS 提取文件路径 + 需求描述
│   输出: [1/N]    │  → 用户可见进度
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 2. 预检查         │  文件存在性 + 数据库锁检测
│   输出: [2/N]    │  → 用户可见进度
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 3. 判断需求类型    │  查询型 / 分析型 / 混合型
│   输出: [3/N]    │  → 用户可见：需求类型 + 计划步骤数
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 4. 制定计划       │  选择脚本 + 构造调用参数
└────────┬────────┘
         │
         ▼
┌─────────────────┐  ┌───────────────────────────────────┐
│ 5. 执行          │──│ 输出进度 → idat 调用 → 读取输出    │
│   输出: [i/N]    │  │ → 输出完成信息                     │
└────────┬────────┘  └───────────────────────────────────┘
         │
         ▼
┌─────────────────┐
│ 6. 审计          │  返回码=0？输出非空？结果匹配需求？
│    ├─ 通过 → 继续
│    └─ 不通过 → 输出失败原因 → 重试（回到步骤 4）
└────────┬────────┘
         │ 最多重试 3 次
         ▼
┌─────────────────┐
│ 7. 持久化（可选） │  如需求涉及更新数据库 → 调用更新脚本
│   输出: [i/N]    │  → 用户可见：正在更新数据库...
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 8. 沉淀（可选）   │  如生成了新脚本 → 保存到 scripts/ + 更新 registry.json
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 9. 保存存档       │  写 summary.json
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 10. 格式化输出    │  返回分析结果给用户
└─────────────────┘
```

**循环控制规则**：

| 参数 | 值 | 说明 |
|------|---|------|
| 最大重试次数 | 3 | 同一步骤连续失败 3 次则放弃 |
| 单次 idat 超时 | 300 秒 | Bash 工具调用 idat 时的 timeout |
| 累计耗时上限 | 15 分钟 | 超过则终止并返回已有结果 |
| 审计通过条件 | 返回码=0 且 输出文件存在且非空 | 基本正确性保障 |
| 放弃后行为 | 返回已有结果 + 说明失败原因 | 不静默失败 |

### 2.6 核心设计原则

1. **无头模式为主**：所有 IDA 操作通过 `idat -A -S` 执行，不依赖 IDA GUI
2. **脚本驱动**：分析操作封装为独立的 IDAPython 工具脚本（`disassembler/ida_tool/` 目录），AI 通过 Bash 调用 idat 执行这些脚本
3. **不复用现有脚本**：现有脚本（`dump_func_disasm.py`、`ai_analyze.py` 等）运行模式不同，新建专用工具脚本
4. **AI 编排**：命令提示词引导 AI 选择/组合/按需生成脚本，AI 充当"编排器"
5. **结果可验证**：每步执行后通过返回码和输出文件判断成功/失败
6. **脚本沉淀**：AI 生成的新脚本经验证后保存到 `scripts/` 库，越用越聪明
7. **过程可见**：每个步骤输出进度信息，用户不会看到长时间无响应

---

## 3. 命令实现规范

### 3.1 命令文件格式

命令使用 Markdown 格式，符合 opencode 自定义命令规范：

```markdown
---
description: IDA Pro AI 智能分析 — 输入 IDA 数据库路径和分析需求，自动完成逆向分析
---

（命令提示词内容，参见 2.1 的结构）
```

### 3.2 命令提示词核心要素

#### 3.2.1 角色与能力边界

- AI 作为"逆向分析编排器"，负责理解需求、选择工具、编排执行、返回结果
- 可用工具：Bash（执行 idat 命令）、Read（读取输出文件）、Write（生成临时脚本）、Glob/Grep（查找脚本）
- AI 不能直接操作 IDA GUI，必须通过 idat headless + IDAPython 脚本间接操作

#### 3.2.2 idat 调用模板

AI 执行任何 IDA 操作的固定模式：

```bash
# 查询操作
IDA_QUERY=<查询类型> IDA_OUTPUT=<输出路径> IDA_PATTERN=<可选> IDA_FUNC_ADDR=<可选> \
  "<ida_path>/idat" -A -S"<项目根>/disassembler/ida_tool/query.py" -L<日志路径> <目标文件>

# 更新操作
IDA_OPERATION=<操作类型> IDA_BATCH_FILE=<批量操作JSON路径> IDA_OUTPUT=<输出路径> \
  "<ida_path>/idat" -A -S"<项目根>/disassembler/ida_tool/update.py" -L<日志路径> <目标文件>
```

**注意事项**：
- `<ida_path>` 含空格时必须用双引号包裹
- 所有路径必须转为绝对路径
- `-S` 参数的脚本路径必须是绝对路径
- 日志路径（`-L`）的父目录必须存在
- 执行前应检测数据库锁：检查 `.id0` 文件是否被占用（当输入为 `.i64`/`.idb` 时）

#### 3.2.3 预检查

每次执行 idat 前必须进行预检查：

1. **文件存在性**：目标文件路径存在且可读
2. **数据库锁检测**：如果目标为 `.i64`/`.idb`，检查对应的 `.id0` 文件是否被其他进程锁定。检测方法：
   ```bash
   # 从 .i64 推导 .id0 路径，然后用 python fcntl 检测
   python3 -c "
   import fcntl, sys, os
   id0 = sys.argv[1].rsplit('.', 1)[0] + '.id0'
   if os.path.exists(id0):
       try:
           with open(id0, 'r') as f:
               fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
               fcntl.flock(f, fcntl.LOCK_UN)
           print('UNLOCKED')
       except (IOError, OSError):
           print('LOCKED')
           sys.exit(1)
   else:
       print('NO_ID0')
   " "<目标文件路径>"
   ```
3. **输出目录**：`mkdir -p` 确保输出目录和日志目录存在

#### 3.2.4 错误诊断

idat 执行失败时的诊断步骤：

1. 检查返回码（`$?`）
2. 读取 `-L` 指定的日志文件末尾 50 行
3. 检查输出文件是否存在且非空
4. 常见错误模式：
   - `Resource temporarily unavailable` → 数据库被锁定
   - `ModuleNotFoundError` → 脚本路径错误
   - `qexit(1)` 或 exit code 1 → 脚本内部错误，查看日志定位

#### 3.2.5 执行过程可见性

AI 在执行过程中**必须**向用户输出进度信息，让用户知道任务没有卡死。具体要求：

**每个关键步骤执行前，输出进度行**：

```
[*] [1/5] 正在解析用户输入...
[*] [2/5] 正在预检查（文件存在性、数据库锁）...
[*] [3/5] 正在查询入口点（idat 执行中，约需 10-30 秒）...
[*] [4/5] 正在分析查询结果...
[*] [5/5] 正在格式化输出...
```

**idat 执行期间**（耗时最长的环节），AI 应告知用户预计等待时间和当前状态：

```
[*] 正在调用 idat 执行查询，此步骤通常需要 10-30 秒...
[*] idat 执行完成，正在读取结果...
```

**多步骤任务**（分析型需求），每完成一步都输出进度：

```
[*] 步骤 1/3 完成: 查询到 3 个入口函数
[*] 步骤 2/3: 正在反编译 main 函数（idat 执行中）...
[*] 步骤 2/3 完成: 反编译成功
[*] 步骤 3/3: 正在分析验证逻辑...
```

**原则**：

1. 用户不应看到超过 30 秒的无输出间隔
2. 涉及 idat 调用时必须提示"执行中"（因为 idat 启动需要时间）
3. 出错时立即输出错误信息，不要等到最后
4. 进度信息直接输出到对话中（用户在 opencode TUI 中可见）

#### 3.2.6 日志规范

命令执行过程的日志分为三层，**同时服务于 AI 和用户**：

| 层级 | 位置 | 受众 | 内容 |
|------|------|------|------|
| **进度输出** | AI 对话中直接输出 | 用户 | 步骤编号、当前动作、预计耗时（参见 3.2.5） |
| **idat 日志** | `-L` 指定的路径 | AI + 用户（事后排查） | IDAPython 脚本执行细节（`[*]`/`[+]`/`[!]` 前缀，中文） |
| **任务存档** | `analysis_intermediate/<task_id>/summary.json` | 用户（历史存档） | 最终结果摘要、数据库修改记录 |

**idat 日志的关键要求**：

- 工具脚本（`query.py`、`update.py`、`scripts/*.py`）内部日志必须详细，记录每个关键操作
- 日志前缀约定：`[*]` 进行中、`[+]` 成功、`[!]` 警告/失败
- 日志使用中文，包含上下文信息（函数名、地址、路径等）
- AI 在 idat 执行失败时，应读取日志文件进行错误诊断并向用户展示关键错误信息

#### 3.2.7 AI 的最终输出格式

```
## 分析摘要
（一句话说明分析结论）

## 详细结果
（按函数/地址组织的分析细节）

## 操作记录（如有数据库更新）
- 重命名: sub_401000 → validate_password
- 函数注释: 0x401000 "验证用户名和密码"

## 置信度说明
- 确定的事实: （来自 IDA 数据库的精确信息）
- 推测: （AI 基于上下文的推理，标注置信度）
```

---

## 4. 工具脚本体系

### 4.1 为什么不复用现有脚本

现有脚本（`disassembler/ai_analyze.py`、`dump_func_disasm.py` 等）的运行模式是 **命令行为前端、opencode 为后端**：用户在终端执行 shell 脚本 → shell 调用 idat → IDAPython 脚本内部再调用 opencode（通过 `ai/opencode.py`）来完成 AI 分析。

本需求的运行模式完全相反：**opencode 为前端、IDAPython 脚本为后端工具**：用户在 opencode 中输入命令 → opencode 的 AI 编排执行 → AI 调用 idat 运行 IDAPython 脚本 → 脚本返回结构化结果给 AI。

关键差异：

| 维度 | 现有脚本 | 本需求脚本 |
|------|---------|-----------|
| 调用者 | shell / IDA GUI | opencode AI（通过 Bash 工具） |
| 输出方向 | 脚本内部调 AI（`ai/opencode.py`） | AI 调脚本（脚本结果给 AI） |
| 输出格式 | 文件（`.asm`、`.c`） | 结构化 JSON（给 AI 解析） |
| 交互模式 | 三模式（对话框/CLI/headless） | 纯 headless（无 GUI） |
| 日志受众 | IDA Output 窗口 / 终端用户 | AI + 用户双受众 |

因此，本需求应**新建专用工具脚本**，不复用现有脚本。现有脚本继续服务于它们原有的使用场景。

### 4.2 实现前提与依赖关系

**关键**：命令的实现前提是核心工具脚本先完成。交付顺序：

```
工具脚本（ida_tool/ 目录）
    ↓
命令文件（.opencode/commands/ida-pro-analysis.md）
    ↓
端到端验证（用典型场景逐一测试）
    ↓
使用中持续沉淀新脚本（脚本库自动增长）
```

### 4.3 工具脚本目录结构

```
disassembler/ida_tool/               # 专用工具脚本目录（仅供 ida-pro-analysis 命令使用）
├── _base.py                         # 公共基础设施（骨架、环境变量解析、JSON 输出、日志）
├── query.py                         # 查询操作（入口点、函数、反编译、交叉引用等）
├── update.py                        # 更新操作（重命名、注释、批量操作）
├── scripts/                         # 沉淀脚本库（AI 生成的脚本经过验证后保存在此）
│   ├── registry.json                # 脚本注册表（名称、功能描述、参数格式）
│   ├── analyze_auth.py              # 示例：分析认证逻辑的沉淀脚本
│   └── find_crypto_constants.py     # 示例：查找加密常量的沉淀脚本
└── README.md                        # 工具脚本使用说明（供 AI 和人阅读）
```

### 4.4 公共基础模块 `_base.py`

提供所有工具脚本共享的基础设施，**所有新建工具脚本必须 import 此模块**：

```python
# _base.py 提供的功能：
# 1. run_headless(business_func) — headless 入口模板
# 2. write_json_output(output_path, result) — JSON 输出
# 3. env_str(key, default="") — 读取环境变量
# 4. env_bool(key) — 读取布尔环境变量
# 5. log(msg) — 日志输出（中文、[*]/[+]/[!] 前缀）
```

工具脚本只需关注业务逻辑，基础设施由 `_base.py` 统一处理（环境变量解析、`auto_wait`、`qexit`、JSON 输出、异常兜底）。

### 4.5 核心工具脚本

#### 4.5.1 查询脚本 `query.py`

**用途**：查询 IDA 数据库信息，输出 JSON 供 AI 解析。通过环境变量 `IDA_QUERY` 指定查询类型。

**支持的查询类型**：

| 查询类型 | 说明 | 参数 |
|---------|------|------|
| `entry_points` | 枚举所有入口点（根据文件类型智能识别：exe→main/init，dll→DllMain/导出，so→JNI_OnLoad/init/导出） | 无 |
| `functions` | 按模式匹配函数列表 | `IDA_PATTERN` |
| `decompile` | 反编译指定函数（返回 C 伪代码） | `IDA_FUNC_ADDR` |
| `disassemble` | 反汇编指定函数 | `IDA_FUNC_ADDR` |
| `func_info` | 查询单个函数的详细信息（签名、调用者、被调用者、字符串引用、大小等） | `IDA_FUNC_ADDR` |
| `xrefs_to` | 查询指定地址/函数的交叉引用（谁引用了它） | `IDA_ADDR` 或 `IDA_FUNC_ADDR` |
| `xrefs_from` | 查询指定函数调用了哪些函数 | `IDA_FUNC_ADDR` |
| `strings` | 搜索字符串及其引用位置 | `IDA_PATTERN`（搜索模式，支持子串匹配） |
| `imports` | 列出所有导入函数 | 无 |
| `exports` | 列出所有导出函数 | 无 |
| `segments` | 列出所有段信息 | 无 |

**调用方式**：

```bash
IDA_QUERY=entry_points IDA_OUTPUT=/tmp/result.json \
  "<ida_path>/idat" -A -S"<项目根>/disassembler/ida_tool/query.py" \
  -L/tmp/idat.log <目标文件>
```

**输出格式**（写入 `IDA_OUTPUT`）：

```json
{
  "success": true,
  "query": "entry_points",
  "data": { ... },
  "error": null
}
```

#### 4.5.2 更新脚本 `update.py`

**用途**：更新 IDA 数据库（重命名、注释等），操作后自动保存数据库。通过环境变量 `IDA_OPERATION` 指定操作类型。

**支持的操作类型**：

| 操作类型 | 说明 | 参数 |
|---------|------|------|
| `rename` | 重命名符号（函数/全局数据） | `IDA_OLD_NAME` + `IDA_NEW_NAME` |
| `set_func_comment` | 设置函数注释 | `IDA_FUNC_ADDR` + `IDA_COMMENT` |
| `set_line_comment` | 设置行内注释 | `IDA_ADDR` + `IDA_COMMENT` |
| `batch` | 批量执行多个操作 | `IDA_BATCH_FILE`（JSON 文件路径） |

**batch 操作的 JSON 格式**：

```json
{
  "operations": [
    {"type": "rename", "old_name": "sub_401000", "new_name": "validate_password"},
    {"type": "set_func_comment", "func_addr": "0x401000", "comment": "验证用户密码"},
    {"type": "set_line_comment", "addr": "0x401050", "comment": "比较密码长度"}
  ]
}
```

**调用方式**：

```bash
IDA_OPERATION=batch IDA_BATCH_FILE=/tmp/ops.json IDA_OUTPUT=/tmp/result.json \
  "<ida_path>/idat" -A -S"<项目根>/disassembler/ida_tool/update.py" \
  -L/tmp/idat.log <目标文件>
```

**设计要点**：

- 每个查询/操作类型对应一个独立的处理函数
- 公共逻辑由 `_base.py` 提供（环境变量解析、headless 入口、JSON 输出、日志）
- 包含详细的中文执行日志（`[*]`/`[+]`/`[!]` 前缀）
- 更新操作执行后调用 `ida_loader.save_database` 持久化修改

### 4.6 脚本沉淀机制（AI 越用越聪明）

#### 4.6.1 核心思路

当 AI 发现 `query.py` / `update.py` 无法覆盖需求时，会生成新的专用脚本。这些脚本**不应是用完即弃的临时文件**，而应经过验证后沉淀到脚本库（`ida_tool/scripts/`）中：

1. **首次遇到新需求** → AI 生成脚本 → 执行 → 验证结果
2. **验证通过** → 脚本沉淀到 `scripts/` 目录 + 注册到 `registry.json`
3. **后续遇到相同需求** → AI 优先查找 `registry.json` → 直接调用已有脚本（更快、更可靠）

这样命令会越用越聪明：首次可能需要生成脚本（耗时较长），后续相同类型的需求可以直接调用沉淀脚本（快速准确）。

#### 4.6.2 脚本注册表 `scripts/registry.json`

```json
{
  "scripts": [
    {
      "name": "analyze_auth",
      "file": "analyze_auth.py",
      "description": "分析函数中的认证/验证逻辑，提取硬编码的用户名、密码等凭证",
      "params": ["IDA_FUNC_ADDR"],
      "example_call": "IDA_FUNC_ADDR=main_0 IDA_OUTPUT=/tmp/result.json idat -A -S.../scripts/analyze_auth.py ...",
      "added_at": "2026-04-17",
      "verified": true
    },
    {
      "name": "find_crypto_constants",
      "file": "find_crypto_constants.py",
      "description": "在二进制中搜索已知加密算法的特征常量（AES S-Box、MD5 init、SHA256 K 等）",
      "params": [],
      "example_call": "IDA_OUTPUT=/tmp/result.json idat -A -S.../scripts/find_crypto_constants.py ...",
      "added_at": "2026-04-17",
      "verified": true
    }
  ]
}
```

#### 4.6.3 沉淀流程

```
AI 生成新脚本
    ↓
执行并通过语法校验
    ↓
执行并验证结果正确性
    ↓
写入 scripts/<功能名>.py（遵循 _base.py 骨架）
    ↓
更新 registry.json（名称、描述、参数、示例调用）
    ↓
后续使用时 AI 通过 registry.json 发现该脚本
```

**命令 prompt 中的指令**：

```
当你发现现有 query.py / update.py 无法满足需求时：
1. 先检查 scripts/registry.json 中是否已有可用的沉淀脚本
2. 如果没有，则使用 _base.py 骨架生成新脚本
3. 新脚本执行成功后，将其保存到 scripts/ 目录并更新 registry.json
4. 保存前确保脚本有清晰的 docstring 说明用途和参数
```

#### 4.6.4 脚本质量保障

沉淀到 `scripts/` 的脚本必须：

1. 基于 `_base.py` 骨架，使用 `run_headless()` 入口
2. 通过语法检查：`python3 -c "compile(...)"`
3. 输出符合标准 JSON 格式（`{"success": bool, "data": ..., "error": ...}`）
4. 有完整的 docstring（`summary` + `description`）
5. 包含中文日志
6. 在 `registry.json` 中有准确的描述和调用示例

### 4.7 AI 生成脚本的编码规则

命令 prompt 中应包含以下关键规则：

| 规则 | 说明 | 正确 | 错误 |
|------|------|------|------|
| 禁止 `import idc` | `idc` 语义模糊 | `import ida_nalt` | `import idc` |
| 禁止 `import idaapi` | 隐藏符号来源 | `import ida_funcs` | `import idaapi` |
| 禁止 `from X import Y`（IDA 模块） | IDAPython 模块必须通过前缀引用 | `ida_kernwin.msg("hi")` | `from ida_kernwin import msg` |
| 允许 `from _base import`（本项目模块） | `ida_tool/` 内部的公共模块可以直接导入 | `from _base import run_headless` | 不导入直接重写 headless 入口 |
| 字符串用双引号 | 所有字符串字面量 | `"hello"` | `'hello'` |
| headless 入口在模块级 | 不在 `if __name__ == "__main__"` 内 | 见骨架模板 | `if __name__ == "__main__": _run_headless()` |
| 必须调用 `auto_wait()` | 等待 IDA 自动分析完成 | 见骨架模板 | 跳过 |
| 必须调用 `qexit()` | headless 模式不调用则不退出 | 见骨架模板 | 跳过 |
| 输出为 JSON | 写入 `IDA_OUTPUT` 指定文件 | `json.dump(result, f)` | `print()` |
| 日志使用中文 | 包含上下文信息 | `ida_kernwin.msg("[*] 正在分析函数: xxx\n")` | `ida_kernwin.msg("analyzing\n")` |
| 使用 `_base.py` | 继承公共基础设施 | `from _base import run_headless` | 自己实现 headless 入口 |

---

## 5. 中间文件管理方案（简化版，修正 v2 问题 6）

### 5.1 方案设计

opencode 命令是单次会话执行，不需要复杂的跨会话状态管理。简化为：

```
analysis_intermediate/
└── <timestamp>_<短hash>/       # 如 20260417_143052_a1b2
    ├── summary.json            # 任务存档（命令结束时一次性写入）
    ├── idat.log                # idat 执行日志（-L 参数输出）
    └── query_result.json       # 查询结果（IDA_OUTPUT 指定的文件）
```

### 5.2 summary.json 结构

只在命令执行结束时写入一次，作为历史存档：

```json
{
  "binary_path": "/path/to/binary.i64",
  "user_request": "分析 main_0 函数的验证逻辑",
  "completed_at": "2026-04-17T14:35:10",
  "status": "success",
  "steps_executed": 3,
  "ida_modifications": [
    {"type": "rename", "old": "sub_401000", "new": "validate_user"},
    {"type": "func_comment", "addr": "0x401000", "comment": "验证用户名和密码"}
  ],
  "analysis_summary": "main_0 函数通过 strcmp 比较用户输入..."
}
```

### 5.3 设计原则

1. **轻量级**：不做实时状态管理，summary.json 只是事后存档
2. **IDA 数据库即状态**：重命名、注释等中间信息直接写入 IDA 数据库，下次分析时即可读取
3. **不做断点恢复**：如需跨会话恢复，作为未来增强功能
4. **不保留冗余数据**：查询结果文件只保留最后一次的，不累积

---

## 6. 端到端执行示例（改进建议 1）

### 示例 1：查询型 — 列出所有入口函数

```
用户输入: /ida-pro-analysis /Users/aserlili/Downloads/lesson1.exe.i64 找到所有入口函数

用户在 TUI 中看到的实时输出:
────────────────────────────────────
[*] [1/4] 正在解析用户输入...
[*] 文件: /Users/aserlili/Downloads/lesson1.exe.i64
[*] 需求: 找到所有入口函数（查询型）
[*] [2/4] 正在预检查...
[+] 文件存在: ✓  数据库锁: ✓
[*] [3/4] 正在查询入口点（idat 执行中，约需 10-30 秒）...
[+] idat 执行完成（耗时 18 秒）
[*] [4/4] 正在格式化输出...

## 分析摘要
lesson1.exe.i64 中找到 3 个入口函数。

## 详细结果
| 名称 | 地址 | 类型 |
|------|------|------|
| main | 0x00401000 | 主函数 |
| _init | 0x00401050 | 初始化函数 |
| __libc_start_main | 0x00401100 | C 运行时入口 |
────────────────────────────────────
```

### 示例 2：分析型 — 分析验证逻辑

```
用户输入: /ida-pro-analysis /Users/aserlili/Downloads/lesson1.exe.i64 分析 main_0 函数的 user_name 和 password 验证逻辑

用户在 TUI 中看到的实时输出:
────────────────────────────────────
[*] [1/7] 正在解析用户输入...
[*] 文件: /Users/aserlili/Downloads/lesson1.exe.i64
[*] 需求: 分析 main_0 函数的验证逻辑（分析型）
[*] [2/7] 正在预检查...
[+] 文件存在: ✓  数据库锁: ✓
[*] [3/7] 正在查询 main_0 函数信息（idat 执行中，约需 10-30 秒）...
[+] idat 执行完成（耗时 15 秒），已获取反编译代码
[*] [4/7] 正在分析验证逻辑...
[*] [5/7] 正在更新数据库注释和重命名（idat 执行中）...
[+] 数据库更新完成: 重命名 1 个, 注释 1 个
[*] [6/7] 正在沉淀分析脚本到脚本库...
[+] 已保存沉淀脚本: scripts/analyze_auth.py
[*] [7/7] 正在格式化输出...

## 分析摘要
main_0 函数通过 strcmp 比较用户输入与硬编码值来验证身份。

## 详细结果
- user_name: "admin"
- password: "password123"
- 验证逻辑: 先比较 user_name，通过后再比较 password，都正确则返回 1

## 操作记录
- 重命名: main_0 → verify_credentials
- 函数注释: 0x00401000 "验证用户名和密码，正确返回1"

## 置信度说明
- 确定: strcmp 调用位置、比较的字符串值（来自 IDA 数据库精确数据）
- 推测: 函数语义命名（中等置信度，基于调用模式和字符串内容）
────────────────────────────────────
```

---

## 7. 安全与约束

### 7.1 文件安全

- 只操作用户指定的 IDA 数据库文件，不修改其他文件
- 不删除 IDA 数据库文件
- 写文件前检查目录存在性（`mkdir -p`）

### 7.2 操作安全

- 数据库修改操作（重命名、注释）执行前在输出中列出预览
- 批量修改支持 `--dry-run`（通过环境变量 `IDA_DRY_RUN=1`）
- 不执行可能损坏数据库的操作（如强制保存已锁定的数据库）
- 如果数据库已被锁定，立即告知用户并停止执行

### 7.3 AI 行为约束

- AI 不得自行决定修改二进制文件
- AI 不得跳过审计步骤直接报告结果
- 当 AI 置信度不足时，应明确告知用户而非编造结论
- 分析结果必须区分"事实"（来自 IDA 数据库的精确信息）和"推测"（AI 基于上下文的推理）
- 重试不超过 3 次，累计耗时不超过 15 分钟
- 失败后不静默忽略，必须说明失败原因

---

## 8. 实现优先级与分阶段交付

### Phase 1：基础设施 + 最小可用命令

**目标**：能处理查询型需求

**交付顺序**（严格按序）：

1. 创建 `disassembler/ida_tool/` 目录和 `_base.py` 公共基础模块
2. 实现 `query.py` 的核心查询类型：
   - `entry_points`：智能识别文件类型的入口点
   - `functions`：按模式匹配函数
   - `decompile`：反编译函数
   - `func_info`：函数详细信息
   - `xrefs_to`、`xrefs_from`：交叉引用
   - `strings`：字符串搜索
3. 创建 `scripts/` 目录和 `registry.json` 初始空注册表
4. 创建命令文件 `.opencode/commands/ida-pro-analysis.md`（含进度输出规范）
5. 用典型场景中的"查询型"案例进行端到端验证

### Phase 2：更新能力 + 分析型需求

**目标**：能处理分析型需求

1. 实现 `update.py`：
   - `rename`：重命名
   - `set_func_comment`：函数注释
   - `set_line_comment`：行内注释
   - `batch`：批量操作
2. 补充查询模式：`imports`、`exports`、`segments`、`disassemble`
3. 完善命令 prompt（增加分析型需求的编排策略 + 脚本沉淀指令）
4. 用典型场景中的"分析型"案例进行端到端验证，沉淀首批脚本

### Phase 3：增强体验

**目标**：提升可靠性和易用性

1. 根据实际使用反馈优化命令 prompt
2. 完善沉淀脚本库（从实际使用中积累更多脚本）
3. 添加执行超时保护
4. 增加生成脚本的质量校验（语法检查 + 关键 API 调用检查）
5. 优化输出格式（表格、调用链可视化等）

---

## 9. 验收标准

### 9.1 功能验收

- 能正确处理 1.3 中列出的所有典型使用场景
- AI 能根据文件类型（exe/dll/so）智能识别入口类型
- 分析结果准确，注释和重命名能正确写入 IDA 数据库
- 查询型需求只需单次 idat 调用即可完成
- 分析型需求能自动编排多轮查询
- AI 生成的新脚本能正确沉淀到 `scripts/` 目录并在 `registry.json` 中注册
- 后续相同类型的需求能直接调用沉淀脚本

### 9.2 质量验收

- 命令执行有完整日志，日志使用中文，包含上下文信息
- 代码遵循 AGENTS.md 编码规范
- `query.py`、`update.py` 通过 shell 测试框架验证
- 新生成的脚本能通过语法检查
- 所有路径正确处理空格（引号包裹）
- 执行过程中用户能看到进度信息，不会出现超过 30 秒的无输出间隔

### 9.3 架构验收

- 命令为单文件，prompt 精简无冗余
- 工具脚本在 `ida_tool/` 目录下独立维护，不复用现有脚本
- `_base.py` 提供公共基础设施，查询/更新脚本只关注业务逻辑
- 沉淀脚本通过 `registry.json` 管理发现与调用
- 中间文件管理轻量，不做过度设计

---

## 10. 参考资料

| 资料 | 位置/链接 |
|------|----------|
| opencode 自定义命令文档 | https://opencode.ai/docs/zh-cn/commands/ |
| IDAPython 示例索引 | `/Users/aserlili/Documents/Codes/ida-sdk/src/plugins/idapython/examples/index.md` |
| IDAPython 示例源码 | `/Users/aserlili/Documents/Codes/ida-sdk/src/plugins/idapython/examples/` |
| IDAPython 参考文档 | https://python.docs.hex-rays.com/ |
| 无头自动化指南 | `rules/headless-automation-guide.md` |
| 脚本分类参考 | `rules/script-classification.md` |
| 项目编码规范 | `AGENTS.md` |
| v2 审计报告 | `docs/需求/审计报告-IDA-Pro-AI智能分析命令-v2.md` |
| v1 原始需求 | `docs/需求/需求-与AI结合自动分析-v1.md` |
| 工具脚本使用说明 | `disassembler/ida_tool/README.md`（实现时创建） |
| 脚本注册表 | `disassembler/ida_tool/scripts/registry.json`（实现时创建） |
