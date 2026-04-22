# 需求：TencentPediyKeygenMe2 复盘进化 — 智能决策与验证体系

## §1 背景与目标

### 1.1 来源

复盘 TencentPediyKeygenMe2.exe 的完整分析过程（6+小时、40+次 idat 调用、18+手写脚本、5+次错误结果、最终未解决），识别出 9 个改进方案。

### 1.2 痛点与数据

| # | 痛点 | 浪费时间 | 根因 |
|---|------|---------|------|
| 1 | 作弊式验证 — 用自己 buggy 代码验证自己 | ~120min | 缺验证标准规则 |
| 2 | Python 求解器太慢 — 应直接用 C（60倍差距） | ~90min | 缺技术选型决策树 |
| 3 | 静态分析死磕 CryptoPP 模板 | ~60min | 缺静态/动态切换指导 |
| 4 | C/C++ 编译器找不到（实际存在 4 份 cl.exe） | ~30min | 缺环境检测 |
| 5 | Patch 排除法太晚 | ~30min | 缺排除法经验 |
| 6 | GUI 验证靠人工 | ~30min | 缺自动化脚本 |
| 7 | 上下文丢失 — 压缩后 ida-pro-analysis 知识全丢 | ~30min | 架构限制 |
| 8 | 进程卡住 | ~20min | 架构限制 |
| 9 | ECDLP 求解从零探索 | 关联 #2 | 缺经验沉淀 |

### 1.3 目标

1. **消除作弊式验证** — 首次生成的结果就是正确的
2. **技术选型智能化** — 自动选择最优技术栈（C/Python/Unicorn/Hook）
3. **环境自动感知** — 不再出现"编译器找不到"的问题
4. **知识不丢失** — 上下文压缩后仍能遵守 ida-pro-analysis 的规则
5. 最终目标：进化后能正确解决 TencentPediyKeygenMe2 的 License Code

### 1.4 评估维度

| 维度 | 改进前 | 改进后（预期） |
|------|--------|--------------|
| 准确度 | 5+次错误结果 | 首次即正确 |
| 速度（ECDLP类） | 98分钟/轮 | ~19秒/轮（C） |
| 速度（环境检测） | ~30分钟人工排查 | 自动检测秒级完成 |
| 上下文占用 | 不变 | 环境检测一次后缓存结果 |
| 知识持久性 | 压缩后丢失 | 始终可用 |

---

## §2 技术方案

### 2.1 改动总览

| ID | 方案 | 改动文件 | 类型 |
|----|------|---------|------|
| A | 结果验证标准 | `ida-pro-analysis.md` + `crypto-validation-patterns.md` | 修改 |
| B | 技术选型决策树 | 新建 `ida-pro-analysis-knowledge-base/technology-selection.md` | 新增 |
| C | 环境自动检测 | 新建 `scripts/detect_env.py` + 修改 `ida-pro-analysis.md` | 新增+修改 |
| D | 排除法验证策略 | 修改 `crypto-validation-patterns.md` | 修改 |
| E | 模拟执行优先策略 | 修改 `crypto-validation-patterns.md` | 修改 |
| F | 环境搭建指南 | 新建 `ida-pro-analysis-docs/environment-setup.md` | 新增 |
| G | GUI 自动化验证 | 新建 `scripts/gui_verify.py` | 新增 |
| I | ECDLP 求解经验 | 新建 `ida-pro-analysis-knowledge-base/ecdlp-solving.md` | 新增 |
| H | 上下文持久化 | 修改 `ida-pro-analysis.md` + 新建 `ida-pro-analysis-docs/context-persistence.md` | 修改+新增 |

> **注意**: `detect_env.py` 和 `gui_verify.py` 是纯 Python 脚本（不走 `idat`），不注册到 `registry.json`。

### 2.2 方案 A: 结果验证标准（统一 A + D + E 的验证策略）

**改动位置**: `ida-pro-analysis.md` + `crypto-validation-patterns.md`

> 方案 A（验证标准）、D（排除法）、E（模拟执行优先）均修改 `crypto-validation-patterns.md`，
> 统一在此处定义验证优先级链，避免三处规则冲突。

**主 prompt 增加的规则**（~5行）:

```
### 结果验证（强制）

生成的分析结果（如 license、key、password）必须经过验证才能报告给用户。

验证优先级（从高到低，优先使用靠前的手段）：
1. Unicorn 模拟原函数 — 直接运行二进制中的验证函数，传入结果，读取返回值
2. ctypes 加载调用 — 将二进制加载到进程，直接调用验证函数
3. Hook 读取中间值 — 在关键点设置 Hook，运行程序读取中间计算结果
4. Patch 排除法（二分） — 逐段绕过检查点，定位 pipeline 中的失败位置
5. 用户人工确认 — 最后手段

**绝对禁止**：用自己的重实现代码验证自己的重实现结果（作弊式验证）。
```

**知识库增加**（crypto-validation-patterns.md 新增"验证策略"统一章节，~80行）:

统一包含以下内容（D/E 不再单独新增章节，合并到此）：
- Unicorn 模拟函数：如何设置内存、传入参数、读取返回值
- ctypes 直接调用：如何加载原二进制的函数
- Hook 读取中间值：如何在关键点注入读取
- Patch 排除法（方案 D）：如何二分定位 pipeline 中的失败点
- 模拟执行 vs 手动重实现的选择条件（方案 E）：
  - Unicorn 无法模拟（特殊硬件指令、自修改代码）→ 手动重实现
  - 需要大量测试不同输入 → 手动重实现
  - 需要理解算法内部细节以进行修改 → 手动重实现
  - 其他情况 → 优先模拟执行

### 2.3 方案 B: 技术选型决策树

**改动位置**: 新建 `ida-pro-analysis-knowledge-base/technology-selection.md`（~100行）

**触发条件**: 任何涉及算法实现、性能敏感计算、大量数据处理的分析任务。

**决策树核心**:

| 场景 | 首选技术 | 原因 | 备选 |
|------|---------|------|------|
| 计算密集型（暴力搜索、ECDLP、大数运算，预估 >10秒） | C/C++ (cl.exe/gcc) | 10-100x 性能 | gmpy2 加速的 Python |
| 算法验证（确认加密是否标准实现） | Unicorn 模拟原函数 | 无需重实现 | Hook 读取 |
| 算法逆向（理解自定义变体） | 静态分析 + Hook | 需理解细节 | — |
| 少量计算（构造输入、格式转换） | Python | 够用 | — |
| 性能不确定时 | Python 原型 → 转C | 渐进策略 | — |
| 需要调试运行时行为 | IDA 调试器 / Frida | 动态分析 | — |

**C/C++ 编译流程**（Windows）:

```bash
# 通过 vcvarsall.bat 设置环境后编译
cmd /c """<vcvarsall_path>\" x86 && cl /O2 /Fe:<output> <source.c>"
```

**主 prompt 引用**（+3行）:

```
| `technology-selection.md` | 需要实现算法、编写求解器、性能敏感计算 |
```

### 2.4 方案 C: 环境自动检测

**改动位置**:
- 新建 `scripts/detect_env.py`（~120行 Python 脚本，跨平台）
- 修改 `ida-pro-analysis.md`（环境检测在阶段 A 之前执行）

> `detect_env.py` 是纯 Python 脚本，不走 `idat`，不注册到 `registry.json`。

**检测脚本功能**（跨平台 Python）:

| 检测项 | Windows | Linux | macOS | 必需性 |
|--------|---------|-------|-------|--------|
| C/C++ 编译器 | cl.exe (vcvarsall.bat) | gcc/g++ | clang/gcc | **必需** — 缺失则中断要求安装 |
| capstone | pip 安装 | 同左 | 同左 | 推荐 — 缺失则自动安装 |
| unicorn | pip 安装 | 同左 | 同左 | 推荐 — 缺失则自动安装 |
| frida | pip 安装 | 同左 | 同左 | 可选 — 缺失则警告 |
| gmpy2 | pip 安装 | 同左 | 同左 | 推荐 — 缺失则自动安装 |
| Python 架构 | platform.architecture() | 同左 | 同左 | 信息性 |
| IDA Pro | config.json | 同左 | 同左 | **必需** — 已有检测 |

**安装策略**:
- Python 包（capstone/unicorn/frida/gmpy2）: 自动 `pip install`，超时 60 秒，失败则通知用户手动安装
- frida 如因网络/编译失败，降级为警告（不影响核心流程）
- C/C++ 编译器: 通知用户手动安装（Windows: VS Build Tools; Linux: `apt install build-essential`; macOS: Xcode Command Line Tools）
- 检测结果缓存到 `~/bw-ida-pro-analysis/env_cache.json`（有效期 24 小时，避免重复检测）

**主 prompt 变更**:

在"分析执行框架"的"阶段 A"之前增加"阶段 0: 环境检测"（~8行）。

**触发条件**:
- 首次使用 `/ida-pro-analysis` 命令时自动执行
- 缓存过期（>24h）时重新执行
- 用户可通过 `--skip-env-check` 参数跳过

**调用方式**:

```bash
python3 "$SCRIPTS_DIR/scripts/detect_env.py" --output "$TASK_DIR/env.json"
```

**输出格式**:

```json
{
  "success": true,
  "data": {
    "compiler": {"available": true, "type": "msvc", "path": "...", "vcvarsall": "..."},
    "python_arch": "64bit",
    "packages": {
      "capstone": {"available": true, "version": "5.0.7"},
      "unicorn": {"available": true, "version": "2.1.4"},
      "frida": {"available": true, "version": "17.9.1"},
      "gmpy2": {"available": true, "version": "2.3.0"}
    },
    "ida_pro": {"available": true, "path": "..."}
  },
  "errors": []
}
```

### 2.5 方案 D: 排除法验证策略

> 已合并到方案 A（§2.2）的统一验证策略中。此方案不再单独新增章节，
> 其内容（二分排除法、Pipeline 定位）统一写入 `crypto-validation-patterns.md` 的"验证策略"章节。

### 2.6 方案 E: 模拟执行优先策略

> 已合并到方案 A（§2.2）的统一验证策略中。此方案不再单独新增章节，
> 其内容（Unicorn/ctypes/Hook 优先级、手动重实现条件）统一写入 `crypto-validation-patterns.md` 的"验证策略"章节。

### 2.7 方案 F: 环境搭建指南

**改动位置**: 新建 `ida-pro-analysis-docs/environment-setup.md`（~80行）

**内容**:
- 必需工具清单 + 安装命令（Windows/Linux/macOS 各自的命令）
- Python 包：`pip install capstone unicorn frida gmpy2`
- Windows C/C++：VS Build Tools 安装指引
- Linux C/C++：`sudo apt install build-essential` / `sudo yum groupinstall "Development Tools"`
- macOS C/C++：`xcode-select --install`
- 验证命令：如何确认安装成功

### 2.8 方案 G: GUI 自动化验证脚本

**改动位置**: 新建 `scripts/gui_verify.py`（~150行）

> `gui_verify.py` 是纯 Python 脚本，不走 `idat`，不注册到 `registry.json`。
> 仅支持 Windows 平台（依赖 Win32 API）。Linux/macOS 需其他方案（如 xdotool）。

**功能**: 自动化操作 Win32 GUI 对话框，输入用户名和 license，点击验证按钮，读取结果。

**参数**:
- `IDA_TARGET_EXE`: 目标可执行文件路径
- `IDA_USERNAME`: 用户名
- `IDA_LICENSE`: License 代码
- `IDA_OUTPUT`: 输出 JSON 路径
- `IDA_GUI_TIMEOUT`: 超时秒数（默认 30）

**实现要点**:
- 启动目标进程
- `FindWindowA` 找主窗口
- `GetDlgItem` / `EnumChildWindows` 找编辑控件和按钮
- `SendMessageA(WM_SETTEXT)` 设置编辑框文本（不用 `SetDlgItemTextA`，MFC 控件不生效）
- `PostMessageA(WM_COMMAND)` 点击按钮（不用 `SendMessageA(BM_CLICK)`，会阻塞）
- `EnumWindows` 检测结果对话框（如 MessageBox）
- 返回结果：成功/失败/超时

**注意**: 不同程序的控件 ID 不同，脚本应支持 `--edit1-id`、`--edit2-id`、`--button-id` 参数覆盖默认值。

### 2.9 方案 I: ECDLP 求解经验

**改动位置**: 新建 `ida-pro-analysis-knowledge-base/ecdlp-solving.md`（~60行）

**内容**:
- ECDLP 求解算法选择：Pollard's rho（首选）、Baby-step Giant-step（内存允许时）
- 性能基准：Python ~0.8M步/s/core，C ~50M步/s/core
- **强制规则**：64-bit 以上曲线的 ECDLP → 必须用 C/C++
- C 实现 Pollard's rho 的模板（使用 128-bit 整数乘法）
- Python 原型 → C 加速的渐进策略
- gmpy2 加速的 Python 实现（当 C 不可用时的备选）

### 2.10 方案 H: 上下文持久化

**改动位置**:
- 修改 `ida-pro-analysis.md`（增加关键规则摘要）
- 新建 `ida-pro-analysis-docs/context-persistence.md`（技术方案文档）

**问题分析**:

OpenCode 的 `/ida-pro-analysis` 命令仅在用户显式调用时注入完整 prompt。多次上下文压缩后：
- 用户不再使用 `/ida-pro-analysis` 前缀 → AI 失去所有规则/知识
- 即使使用前缀，长时间对话中规则可能被遗忘

**解决方案**: 在 `ida-pro-analysis.md` 的输出格式部分增加"关键规则提醒"：

每次输出分析结果时，在末尾附加一段简短的"规则摘要"（~5行），确保即使上下文被压缩，关键规则仍存在于最近的对话中。

摘要内容包括：
1. 验证标准（禁止作弊式验证）
2. 环境状态（C/C++ 可用、工具可用）
3. 技术选型提醒（计算密集型用 C）

**长期方案**（记录在 context-persistence.md 中）:
- 评估 OpenCode hook 机制：在每轮对话开始时自动注入 ida-pro-analysis.md 的关键规则
- 评估自定义 agent：始终保持 ida-pro-analysis 上下文
- **可行性风险**：如果 OpenCode 不支持 hook 机制，则方案 H 只能做到"每次输出附加摘要"，不能完全解决上下文丢失问题。context-persistence.md 中应记录此限制和替代方案。

---

## §3 实现规范

### 3.1 改动范围表

| 文件 | 方案 | 改动类型 | 行数变化 |
|------|------|---------|---------|
| `ida-pro-analysis.md` | A, C, H | 修改 | +20行（291→~311行） |
| `crypto-validation-patterns.md` | A+D+E（合并） | 修改 | +80行（统一验证策略章节） |
| `ida-pro-analysis-knowledge-base/technology-selection.md` | B | 新增 | ~100行 |
| `scripts/detect_env.py` | C | 新增 | ~120行 |
| `ida-pro-analysis-docs/environment-setup.md` | F | 新增 | ~80行 |
| `scripts/gui_verify.py` | G | 新增 | ~150行 |
| `ida-pro-analysis-knowledge-base/ecdlp-solving.md` | I | 新增 | ~60行 |
| `ida-pro-analysis-docs/context-persistence.md` | H | 新增 | ~60行 |

### 3.2 执行顺序（按依赖）

```
C（环境检测脚本）→ B（技术选型知识库，依赖C的检测结果描述）
                  → F（环境搭建指南，与C互补）
                  → A+D+E（验证标准+排除法+模拟执行，合并修改crypto文档）
                  → G（GUI脚本，依赖环境检测）
                  → I（ECDLP经验）
                  → H（上下文持久化，最后）
```

### 3.3 编码规则

- `detect_env.py` 和 `gui_verify.py` 不依赖 IDA 运行时（纯 Python），不需要 IDAPython 编码规范，也不注册到 `registry.json`
- 它们通过 `python3` 直接调用，不走 `idat`
- 如需作为沉淀脚本调用（通过 idat），则需遵循 `_base.py` 骨架 — 但这两个脚本明确不走此路径

---

## §4 验收标准

### 4.1 功能验收

- [ ] **A+D+E**: ida-pro-analysis.md 包含统一验证标准规则（禁止作弊式验证 + 5级验证优先级）
- [ ] **A+D+E**: crypto-validation-patterns.md 包含统一"验证策略"章节（Unicorn/ctypes/Hook/排除法/模拟条件）
- [ ] **B**: ida-pro-analysis-knowledge-base/technology-selection.md 包含完整的决策树 + C 编译流程
- [ ] **C**: scripts/detect_env.py 跨平台运行，输出 JSON 格式环境信息，必需工具缺失时返回错误
- [ ] **C**: ida-pro-analysis.md 包含阶段 0 环境检测步骤
- [ ] **F**: ida-pro-analysis-docs/environment-setup.md 包含 Windows/Linux/macOS 的安装命令
- [ ] **G**: scripts/gui_verify.py 可操作 Win32 GUI（设置文本 + 点击按钮 + 读取结果）
- [ ] **I**: ida-pro-analysis-knowledge-base/ecdlp-solving.md 包含性能基准 + C 实现模板 + 强制规则
- [ ] **H**: ida-pro-analysis.md 包含关键规则摘要（每次输出时附加）

### 4.2 回归验收

- [ ] ida-pro-analysis.md 行数 < 450 行（当前 291，新增 ~20行 = ~311）
- [ ] 现有知识库文件（packer-handling.md、dynamic-analysis.md 等）无改动，功能不受影响
- [ ] detect_env.py 在 Windows 上运行正确
- [ ] gui_verify.py 语法检查通过
- [ ] registry.json 无改动（detect_env.py 和 gui_verify.py 不注册）

### 4.3 架构验收

- [ ] 新文件都在 `.opencode/commands/` 下
- [ ] 新知识库文件在 `ida-pro-analysis-knowledge-base/` 下
- [ ] 新文档在 `ida-pro-analysis-docs/` 下
- [ ] detect_env.py 不依赖 IDA 运行时
- [ ] gui_verify.py 不依赖 IDA 运行时
- [ ] 引用使用相对路径

---

## §5 与现有需求文档的关系

| 现有需求 | 关系 |
|---------|------|
| 需求-动态分析能力与脱壳流程增强 | 方案 D（排除法）和 E（模拟执行）扩展了该需求的验证策略 |
| 需求-进化流程渐进式披露与Prompt瘦身 | 本次新增 ~20行主 prompt，仍 < 450 行阈值 |
| 需求-IDA调试器动态分析能力 | 方案 G（GUI 脚本）补充了 GUI 交互自动化 |
