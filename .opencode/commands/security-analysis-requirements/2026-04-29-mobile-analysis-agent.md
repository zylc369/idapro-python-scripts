# Mobile Analysis Agent 基础设施搭建

> 日期: 2026-04-29
> 来源: 架构讨论 — 用户需要分析 Android + iOS 移动端应用，当前仅支持 PC 二进制逆向
> 状态: 待实施

---

## §1 背景与目标

### 问题

当前 BinaryAnalysis Agent 完全围绕 IDA Pro 设计，无法处理移动端特有的分析需求：

1. **APK 分析**：需要 apktool 解包 → jadx 反编译 Java/Kotlin 层 → IDA Pro 分析 .so native 层，当前 Agent 不编排这些工具
2. **IPA 分析**：需要 class-dump 提取 ObjC 头 → IDA Pro 分析 .dylib，当前无相关能力
3. **移动端 Frida**：需要设备端 frida-server + 主机端 frida 连接，与 PC 端 Frida 用法差异大
4. **多 Agent 架构缺失**：Plugin 无差别注入环境信息，config.json 无移动端工具配置，detect_env.py 不检测移动端工具

### 目标

1. **新增 mobile-analysis Agent**（primary agent），可分析 APK/IPA，编排移动端工具链
2. **Plugin 按 Agent 注入**不同环境信息（binary-analysis 注入 IDA/编译器，mobile-analysis 注入移动端工具 + IDA）
3. **config.json 精简**：删除 `scripts_dir`（由 Plugin 从 agent 名动态推导），新增 `tools` 字典存放外部工具路径
4. **detect_env.py 扩展**：检测移动端工具（apktool、jadx、adb、class-dump 等）

### 非目标（P1+）

- 移动端 Frida 集成（需设备端 frida-server 配置，P1）
- 移动端工具封装脚本（apk_unpack.py 等，按需沉淀，不在基础设施中）
- Web Analysis Agent（P3）
- Vulnerability Research Agent（P4）

### 约束

- binary-analysis/ 目录不动，mobile-analysis 通过路径引用其 IDA 脚本
- binary-analysis Agent 的行为不受影响（回归验证）
- Agent prompt < 450 行

---

## §2 技术方案

### 2.1 目标架构

```
.opencode/
├── agents/
│   ├── binary-analysis.md        # 已有（不动）
│   └── mobile-analysis.md        # 新增：移动应用分析 Agent
│
├── plugins/
│   └── security-analysis.ts      # 改造：按 Agent 类型注入环境信息
│
├── binary-analysis/              # 已有（不动）
│   ├── query.py                  # mobile-analysis 通过 $IDA_TOOLS_DIR 引用
│   ├── ...
│   └── knowledge-base/
│       └── frida-hook-templates.md  # mobile-analysis 也引用
│
└── mobile-analysis/              # 新增：移动端工具与知识库
    ├── README.md
    └── knowledge-base/
        ├── android-tools.md      # Android 工具安装 + CLI 参考
        ├── ios-tools.md          # iOS 工具安装 + CLI 参考
        ├── mobile-methodology.md # 移动端分析方法论（APK/IPA 结构 + 分析流程）
        ├── mobile-frida.md       # 移动端 Frida（设备连接 + 平台 Hook 差异）
        └── mobile-patterns.md    # 常见安全模式（证书固定、root 检测等）
```

### 2.2 config.json 结构变更

**变更前**：
```json
{
  "ida_path": "/Applications/IDA Professional 9.1.app/Contents/MacOS",
  "scripts_dir": "/Users/.../.opencode/commands/ida-pro-analysis-scripts"
}
```

**变更后**：
```json
{
  "ida_path": "/Applications/IDA Professional 9.1.app/Contents/MacOS",
  "tools": {
    "apktool": "/opt/homebrew/bin/apktool",
    "jadx": "/opt/homebrew/bin/jadx",
    "adb": "/opt/homebrew/bin/adb",
    "class-dump": "/usr/local/bin/class-dump",
    "otool": "/usr/bin/otool",
    "ldid": "/usr/local/bin/ldid"
  }
}
```

- 删除 `scripts_dir`：Plugin 从 agent 名动态推导
- 新增 `tools`：外部工具路径字典，键为工具名（使用实际工具名含连字符，如 `class-dump`），值为绝对路径
- `tools` 为用户手动配置项。工具的可用性和版本由 detect_env.py 自动检测并写入 env_cache.json 的 `mobile_tools` 字段，Plugin 从 env_cache.json 读取

### 2.3 Plugin 改造方案

**核心机制**：`sessionAgentMap` 已跟踪 `sessionID → agent`，在 `system.transform` 中查表分支注入。

**环境信息注入差异**：

| 注入项 | binary-analysis | mobile-analysis |
|--------|----------------|-----------------|
| IDA Pro 路径 | 注入 | 注入 |
| $SCRIPTS_DIR | `.opencode/binary-analysis/` | `.opencode/mobile-analysis/` |
| $IDA_TOOLS_DIR | 不注入（等于 $SCRIPTS_DIR） | 注入 `.opencode/binary-analysis/` |
| 编译器 | 注入 | 不注入 |
| Python packages | 注入 | 注入（frida/unicorn 等） |
| 移动端工具 | 不注入 | 注入（apktool/jadx/adb/class-dump 等） |
| BA_PYTHON | 注入 | 注入 |

**脚本目录推导逻辑**：
```ts
const AGENT_SCRIPT_DIRS: Record<string, string> = {
  "binary-analysis": join(directory, ".opencode", "binary-analysis"),
  "mobile-analysis": join(directory, ".opencode", "mobile-analysis"),
};

function getScriptDir(agentName: string | undefined): string {
  return AGENT_SCRIPT_DIRS[agentName || "binary-analysis"]
    || AGENT_SCRIPT_DIRS["binary-analysis"];
}
```

**compactin 注入差异**：
- binary-analysis：保留分析状态（目标二进制、IDA 数据库、已完成分析）
- mobile-analysis：保留分析状态（目标 APK/IPA、已解包状态、分析阶段）
- **COMPACT_REMINDER 必须按 Agent 动态化**：当前硬编码了 `.opencode/agents/binary-analysis.md` 路径（Plugin 第 35 行）。改为根据 agentName 生成对应路径：binary-analysis → `.opencode/agents/binary-analysis.md`，mobile-analysis → `.opencode/agents/mobile-analysis.md`
- **COMPACTION_CONTEXT_PROMPT 必须按 Agent 差异化**：当前内容面向二进制分析（"目标二进制文件路径"、"已执行的 idat 查询"）。mobile-analysis 需要不同内容（"目标 APK/IPA 路径"、"已执行的 apktool/jadx/IDA 操作"）

### 2.4 detect_env.py 扩展

新增移动端工具检测：

```python
MOBILE_TOOLS = {
    "apktool": {"cmd": ["apktool", "--version"], "platforms": ["all"]},
    "jadx": {"cmd": ["jadx", "--version"], "platforms": ["all"]},
    "adb": {"cmd": ["adb", "version"], "platforms": ["all"]},
    "class-dump": {"cmd": ["class-dump", "--help"], "platforms": ["Darwin"]},
    "otool": {"cmd": ["otool", "--help"], "platforms": ["Darwin"]},
    "ldid": {"cmd": ["ldid", "-h"], "platforms": ["Darwin"]},
}
```

检测结果写入 env_cache.json 的 `mobile_tools` 字段，Plugin 按需读取。

### 2.5 mobile-analysis Agent 设计

**角色**：移动应用逆向分析编排器。输入 APK/IPA + 分析需求，自动编排工具链完成分析。

**核心能力**：
1. 自动识别文件类型（APK/IPA/其他）
2. APK 工作流：apktool 解包 → jadx 反编译 → 识别 native libs → IDA Pro 分析 .so
3. IPA 工作流：unzip 解包 → class-dump 头文件提取 → 识别 frameworks → IDA Pro 分析 .dylib
4. 通过 `$IDA_TOOLS_DIR` 引用 binary-analysis 的 IDA 脚本（query.py、update.py 等）

**不包含**（P1+）：
- Frida 移动端动态分析（需设备端配置）
- Objection 集成
- 自动化脱壳

**prompt 结构**（预估 ~380 行）：

| 章节 | 行数 | 内容 |
|------|------|------|
| 元信息 + 角色 | ~15 | description、mode、permission |
| 运行环境 + 变量 | ~50 | $SCRIPTS_DIR、$IDA_TOOLS_DIR、$TASK_DIR、$BA_PYTHON 初始化 |
| 阶段 0：环境检测 | ~20 | 调用 detect_env.py |
| 阶段 A：初始分析 | ~40 | 文件类型检测 + APK/IPA 工作流骨架 |
| 阶段 B：分析规划 | ~25 | 场景驱动 + 知识库按需加载 |
| 阶段 C：执行监控 | ~40 | 执行纪律 + 循环控制 |
| 逆向核心原则 | ~15 | 复用 binary-analysis 的核心原则 |
| 工具清单 | ~60 | 移动端工具 + IDA Pro 工具引用 |
| 知识库索引 | ~30 | 按需加载的知识库文件列表 |
| 输出格式 + 其他 | ~45 | 输出模板、后续交互、安全规则 |

### 2.6 改动文件清单

| 文件 | 操作 | 说明 |
|------|------|------|
| `agents/mobile-analysis.md` | **新增** | 移动端分析 Agent prompt |
| `mobile-analysis/README.md` | **新增** | 移动端工具目录说明 |
| `mobile-analysis/knowledge-base/android-tools.md` | **新增** | Android 工具指南 |
| `mobile-analysis/knowledge-base/ios-tools.md` | **新增** | iOS 工具指南 |
| `mobile-analysis/knowledge-base/mobile-methodology.md` | **新增** | 移动端分析方法论 |
| `mobile-analysis/knowledge-base/mobile-frida.md` | **新增** | 移动端 Frida 指南 |
| `mobile-analysis/knowledge-base/mobile-patterns.md` | **新增** | 移动端安全模式 |
| `plugins/security-analysis.ts` | **修改** | 按 Agent 注入环境信息 + 动态 COMPACT_REMINDER + 删除 scripts_dir |
| `binary-analysis/scripts/detect_env.py` | **修改** | 新增移动端工具检测 |
| `agents/binary-analysis.md` | **修改** | 变量初始化 fallback：删除 config.json scripts_dir 依赖，改为项目结构推导 |
| `binary-analysis/environment-setup.md` | **修改** | config.json 结构说明同步更新（删除 scripts_dir、新增 tools） |
| `binary-analysis/context-persistence.md` | **修改** | Plugin 架构说明同步更新（按 Agent 注入） |
| `binary-analysis/knowledge-base/gui-automation.md` | **修改** | $SCRIPTS_DIR 来源描述更新（不再从 config.json scripts_dir 获取，改为 Plugin 注入） |
| `commands/gui-interact-pc.md` | **修改** | $SCRIPTS_DIR fallback：删除 config.json scripts_dir 依赖，改为项目结构推导 |
| `commands/security-analysis-docs/setup-guide.md` | **修改** | config.json 模板删除 scripts_dir，验证清单更新 |
| `~/bw-security-analysis/config.json` | **修改** | 删除 scripts_dir，新增 tools |

---

## §3 实现规范

### 编码规则

- Agent prompt 遵循已有的渐进式披露原则（核心规则 < 450 行，详细内容放知识库）
- 知识库文件必须自包含（不依赖主 prompt 上下文即可理解）
- Plugin 改造保持向后兼容（binary-analysis 的行为不受影响）
- 所有路径使用相对路径，禁止硬编码绝对路径

### 改动范围表

| 改动类型 | 文件数 | 预估总行数 | 风险等级 |
|---------|--------|-----------|---------|
| 新增 Agent prompt | 1 | ~380 | 中（AI 行为变更） |
| 新增知识库 | 5 | ~600 | 低（文档） |
| 新增 README | 1 | ~60 | 低（文档） |
| 修改 Plugin | 1 | ~150 行改动 | 高（影响所有 Agent） |
| 修改 detect_env.py | 1 | ~80 行改动 | 中（影响环境检测） |
| 修改 binary-analysis.md | 1 | ~20 行改动 | 高（Agent 行为回归） |
| 修改 environment-setup.md | 1 | ~30 行改动 | 低（文档） |
| 修改 context-persistence.md | 1 | ~20 行改动 | 低（文档） |
| 修改 gui-interact-pc.md | 1 | ~10 行改动 | 低（命令文档） |
| 修改 gui-automation.md | 1 | ~5 行改动 | 低（知识库） |
| 修改 setup-guide.md | 1 | ~15 行改动 | 低（安装指南） |
| 修改 config.json | 1 | ~10 行改动 | 低（配置） |

### §3.1 实施步骤拆分

```
步骤 1. 创建 mobile-analysis 目录结构
  - 文件: mobile-analysis/README.md
  - 预估行数: ~60
  - 验证点: 目录存在、README.md 包含目录结构说明
  - 依赖: 无

步骤 2. 创建 Android 工具知识库
  - 文件: mobile-analysis/knowledge-base/android-tools.md
  - 预估行数: ~120
  - 验证点: 文件存在，包含 apktool/jadx/adb 的安装 + CLI 参考 + 常用命令示例，自包含可独立理解
  - 依赖: 无

步骤 3. 创建 iOS 工具知识库
  - 文件: mobile-analysis/knowledge-base/ios-tools.md
  - 预估行数: ~120
  - 验证点: 文件存在，包含 class-dump/otool/ldid/insert_dylib 的安装 + CLI 参考 + 常用命令示例，自包含可独立理解
  - 依赖: 无

步骤 4. 创建移动端分析方法论知识库
  - 文件: mobile-analysis/knowledge-base/mobile-methodology.md
  - 预估行数: ~120
  - 验证点: 文件存在，包含 APK/IPA 结构说明 + 分析流程模板 + 场景驱动规划，自包含可独立理解
  - 依赖: 步骤 2、步骤 3（引用工具名）

步骤 5. 创建移动端 Frida 知识库
  - 文件: mobile-analysis/knowledge-base/mobile-frida.md
  - 预估行数: ~120
  - 验证点: 文件存在，包含 Android/iOS 设备端 frida-server 部署 + 主机端连接 + Java/ObjC bridge Hook 模板，自包含可独立理解
  - 依赖: 无

步骤 6. 创建移动端安全模式知识库
  - 文件: mobile-analysis/knowledge-base/mobile-patterns.md
  - 预估行数: ~120
  - 验证点: 文件存在，包含证书固定绕过、root/越狱检测、混淆识别等常见模式 + 对应策略，自包含可独立理解
  - 依赖: 无

步骤 7. 创建 mobile-analysis Agent prompt
  - 文件: agents/mobile-analysis.md
  - 预估行数: ~380
  - 验证点: 
    1. 行数 < 450
    2. 包含核心章节：角色、变量初始化、阶段 0/A/B/C、工具清单、知识库索引、输出格式
    3. 引用 $IDA_TOOLS_DIR 路径正确（指向 binary-analysis/）
    4. 知识库索引完整（列出所有步骤 2-6 创建的知识库文件 + 触发条件）
    5. 与 binary-analysis.md 的风格和结构保持一致
  - 依赖: 步骤 1-6（引用知识库文件名）

步骤 8. 改造 Plugin — 按 Agent 注入环境信息
  - 文件: plugins/security-analysis.ts
  - 预估行数: ~150 行改动
  - 改动内容:
    1. ConfigData 接口：删除 scripts_dir，新增 tools?: Record<string, string>
    2. EnvData 接口：新增 mobile_tools?: Record<string, { available: boolean; version: string | null }>
    3. 新增 AGENT_SCRIPT_DIRS 常量，从 agent 名推导脚本目录
    4. COMPACT_REMINDER 从硬编码字符串改为动态生成函数（根据 agentName 生成对应 agent prompt 路径）
    5. COMPACTION_CONTEXT_PROMPT 按 agent 类型准备不同版本（二进制分析 vs 移动分析）
    6. system.transform：从 input 提取 sessionID（可选字段，undefined 时 fallback 到 binary-analysis 注入逻辑）→ 查 sessionAgentMap 获取 agentName → 分支注入不同环境信息
    7. compacting：根据 agent 类型使用不同的 COMPACT_REMINDER 和 COMPACTION_CONTEXT_PROMPT
    8. 删除所有 scripts_dir 相关逻辑（fallback 改为 AGENT_SCRIPT_DIRS）
  - 验证点:
    1. `node --check` 编译通过
    2. binary-analysis Agent 注入的环境信息与改造前一致（回归）
    3. mobile-analysis Agent 注入的环境信息包含 $SCRIPTS_DIR（mobile-analysis/）+ $IDA_TOOLS_DIR（binary-analysis/）+ 移动端工具路径
    4. COMPACT_REMINDER 在 binary-analysis session 中指向 binary-analysis.md，在 mobile-analysis session 中指向 mobile-analysis.md
  - 依赖: 步骤 7（需要 agent 名 "mobile-analysis" 与 prompt 文件名一致）

步骤 9. 扩展 detect_env.py — 移动端工具检测
  - 文件: binary-analysis/scripts/detect_env.py
  - 预估行数: ~80 行改动
  - 改动内容:
    1. 新增 MOBILE_TOOLS 字典（apktool/jadx/adb/class-dump/otool/ldid）
    2. 新增 _detect_tool(cmd) 通用函数（执行命令，捕获版本号或标记不可用）
    3. run_detection() 中新增移动端工具检测，结果写入 data.mobile_tools
    4. 移动端工具缺失不标记 success=false（可选依赖，非必需）
  - 验证点:
    1. python -c "compile(...)" 语法检查通过
    2. 运行 detect_env.py，输出 JSON 包含 mobile_tools 字段
    3. 已安装的工具显示 available: true + version
    4. 未安装的工具显示 available: false，不阻止 success=true
  - 依赖: 无

步骤 10. 更新 binary-analysis.md 变量初始化
  - 文件: agents/binary-analysis.md
  - 预估行数: ~20 行改动
  - 改动内容:
    1. bash fallback：将 `c.get('scripts_dir', os.path.join('$(pwd)', '.opencode', 'binary-analysis'))` 改为不依赖 config.json 的推导（直接用 `os.path.join('$(pwd)', '.opencode', 'binary-analysis')`）
    2. PowerShell fallback：同理更新
  - 验证点:
    1. 不再引用 config.json 的 scripts_dir
    2. fallback 正确推导到 .opencode/binary-analysis/
    3. Plugin 注入的 $SCRIPTS_DIR 优先级高于 fallback（正常路径不受影响）
  - 依赖: 步骤 8（Plugin 已改为动态推导 scripts_dir）

步骤 11. 更新文档 — environment-setup.md + context-persistence.md + gui-automation.md + gui-interact-pc.md + setup-guide.md
  - 文件: binary-analysis/environment-setup.md, binary-analysis/context-persistence.md, binary-analysis/knowledge-base/gui-automation.md, commands/gui-interact-pc.md, commands/security-analysis-docs/setup-guide.md
  - 预估行数: ~80 行改动
  - 改动内容:
    1. environment-setup.md: config.json 结构说明更新（删除 scripts_dir，新增 tools 字段说明）
    2. context-persistence.md: Plugin 架构说明更新（system.transform 按 Agent 分支注入）
    3. gui-automation.md: $SCRIPTS_DIR 来源描述从 "config.json scripts_dir 字段" 改为 "Plugin 环境信息注入"
    4. gui-interact-pc.md: $SCRIPTS_DIR fallback 从 `config.json scripts_dir` 改为项目结构推导（与步骤 10 同理）
    5. setup-guide.md: config.json 模板删除 scripts_dir，新增 tools 说明，验证清单删除 scripts_dir 检查项，新增 mobile-analysis Agent 说明
  - 验证点: 文档内容与实际代码行为一致，无过时引用
  - 依赖: 步骤 8（Plugin 改造完成）

步骤 12. 更新 config.json
  - 文件: ~/bw-security-analysis/config.json
  - 预估行数: ~10 行改动
  - 改动内容: 删除 scripts_dir，新增 tools 字典（初始为空 {}，由用户按需填写或由 detect_env 提示）
  - 验证点: JSON 格式正确，binary-analysis 和 mobile-analysis Agent 均能正常读取
  - 依赖: 步骤 8（Plugin 不再依赖 scripts_dir）

步骤 13. 回归验证
  - 文件: 无新文件
  - 预估行数: 0
  - 验证点:
    1. binary-analysis Agent 的环境信息注入与改造前完全一致
    2. mobile-analysis Agent 能被 OpenCode 识别为 primary agent（Tab 切换可见）
    3. mobile-analysis Agent 的 prompt 加载正确（环境信息包含 $SCRIPTS_DIR + $IDA_TOOLS_DIR）
    4. detect_env.py 输出包含 mobile_tools 字段，不影响原有功能
    5. binary-analysis.md 变量初始化不依赖 config.json 的 scripts_dir
    6. 压缩恢复在两个 Agent 中均正确（COMPACT_REMINDER 指向对应 prompt 文件）
  - 依赖: 步骤 1-12 全部完成
```

---

## §4 验收标准

### 功能验收

| # | 验收项 | 通过条件 |
|---|--------|---------|
| F1 | mobile-analysis Agent 可用 | OpenCode Tab 切换可见，Agent 加载无报错 |
| F2 | APK 初始分析 | 提供 APK 文件，Agent 能编排 apktool 解包 + jadx 反编译 + 识别 native libs |
| F3 | IPA 初始分析 | 提供 IPA 文件，Agent 能编排解包 + class-dump + 识别 frameworks |
| F4 | IDA Pro 联动 | 识别到 .so/.dylib 时，Agent 能通过 $IDA_TOOLS_DIR 调用 query.py |
| F5 | 知识库按需加载 | Agent 在不同场景下加载对应知识库（如检测到加壳 → packer-handling.md） |
| F6 | 环境检测 | detect_env.py 检测移动端工具，结果写入 env_cache.json |

### 回归验收

| # | 验收项 | 通过条件 |
|---|--------|---------|
| R1 | binary-analysis 环境注入不变 | Plugin 注入的 IDA Pro + compiler + packages 信息与改造前一致 |
| R2 | binary-analysis 工作流正常 | 典型分析场景（查询 + 反编译 + 更新）端到端通过 |
| R3 | 压缩恢复正常 | binary-analysis 和 mobile-analysis 压缩后 TASK_DIR 精确恢复，COMPACT_REMINDER 指向正确的 agent prompt |
| R4 | config.json 无 scripts_dir | Plugin 不依赖 scripts_dir，所有路径动态推导 |
| R5 | binary-analysis.md fallback 正确 | 变量初始化不依赖 config.json scripts_dir，fallback 正确推导到 .opencode/binary-analysis/ |

### 架构验收

| # | 验收项 | 通过条件 |
|---|--------|---------|
| A1 | mobile-analysis.md < 450 行 | wc -l 验证 |
| A2 | 知识库文件自包含 | 每个知识库文件不依赖主 prompt 即可理解 |
| A3 | 依赖方向正确 | mobile-analysis/ 不被 binary-analysis/ 引用（单向） |
| A4 | 无循环依赖 | Plugin → config.json → env_cache.json，无反向依赖 |

---

## §5 与现有需求文档的关系

| 需求文档 | 关系 |
|---------|------|
| 2026-04-29-directory-and-plugin-rename.md | 本需求在重命名基础上进行（数据目录已是 bw-security-analysis） |
| 2026-04-28-task-dir-persistence.md | mobile-analysis 复用 create_task_dir.py（通过 $IDA_TOOLS_DIR 路径引用） |
| 2026-04-22-plugin-and-architecture-improvements.md | 本需求的 Plugin 改造是该需求的延伸（从无差别注入到按 Agent 注入） |
| 2026-04-22-environment-dependency-hardening.md | detect_env.py 扩展遵循该需求建立的环境检测框架 |
| 2026-04-24-gui-visual-automation.md | GUI 自动化是 PC 特有功能，仅 binary-analysis 使用，不影响 mobile-analysis |
