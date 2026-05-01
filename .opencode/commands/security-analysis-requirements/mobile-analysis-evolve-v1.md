# 需求: mobile-analysis 进化 v1 — Frida 17.x 适配 + 经验沉淀 + 脚本移植

## §1 背景与目标

**来源**: 新京报 v5.6.5 APK 分析 session 的复盘 + 用户提出的 5 个进化点（`docs/进化/进化-mobile-analysis-v1.md`）

**痛点（附数据）**:
1. frida-server 安装使用了带 "frida" 特征的文件名（`frida_srv_793`），未复用 frida-scripts 的随机名逻辑
2. 错误地将 frida 从 17.x 降级到 16.7.19，浪费 2 轮对话 + 引发 client/server 版本不匹配
3. 不了解 frida 17.x 的 API 变化（`Module` 静态方法已移除、`Java` bridge 在 Python SDK 中不自动注入）
4. 脱壳脚本全部手写，无沉淀，重复造轮子（3 个一次性脚本）
5. frida-scripts 的 7 篇 Hook 经验未沉淀到知识库

**目标**: 将 frida-scripts 的成熟逻辑适配为 AI 可调用的架构，创建完整的 frida 17.x 知识体系，让 mobile-analysis agent 从"每次从零开始"进化为"基于沉淀经验执行"。

**预期收益**:
- 上下文: frida 相关操作从 5-6 次 bash 调用 → 1 次（frida-server 管理）
- 轮次: 脱壳从 3 轮 → 0 轮调试
- 准确度: 消除 API 版本误判、Hook 最佳实践违规
- 速度: 省约 10 分钟脚本编写时间

## §2 技术方案

### 2.1 方案 F: 版本统一（已完成）

- venv Python frida 已升级到 17.9.3
- frida-server 已通过 frida-scripts 升级到 17.9.3
- 验证: `frida.__version__ == '17.9.3'`, 设备进程名 `8qumey45`（无 frida 特征）

### 2.2 方案 A: frida-server 管理脚本

**改动文件**:
- 新增 `.opencode/mobile-analysis/scripts/manage_frida.py`
- 更新 `.opencode/mobile-analysis/scripts/registry.json`
- 更新 `.opencode/agents/mobile-analysis.md`（调用方式说明）

**设计**:
从 frida-scripts 提取核心逻辑（`start-frida.py` + `library/`），创建一个可被 AI Agent 通过 bash 调用的 CLI 脚本。

**功能**:
1. `--action install` — 下载 + 安装 frida-server 到 Android 设备（随机名 + 随机目录）
2. `--action start` — 启动 frida-server + 端口转发，输出 JSON（host_port, device_port, pid）
3. `--action stop` — 停止 frida-server + 清理端口转发
4. `--action status` — 检查 frida-server 状态

**数据格式**: 使用 frida-scripts 相同的 `~/bw-frida/frida-server/install_record.json` 保持兼容。

**依赖**: frida-scripts 的 `library/` 目录。直接 import frida-scripts 的模块（`sys.path` 插入），不重复实现。

### 2.3 方案 B: Frida 17.x API + Bridge 知识库

**改动文件**:
- 新增 `.opencode/mobile-analysis/knowledge-base/frida-17x-api.md`（GumJS 核心 API 变化：Module/Memory/Process/NativeFunction 等）
- 新增 `.opencode/mobile-analysis/knowledge-base/frida-17x-bridge.md`（Java/ObjC/Swift bridge 编译与使用方案，与 api.md 无重叠）
- 更新 `.opencode/agents/mobile-analysis.md`（知识库索引）

**关键 API 变化（已通过源码 + 实测验证）**:

| API | frida 16.x | frida 17.x |
|-----|-----------|-----------|
| `Module.findExportByName(null, 'memcpy')` | ✅ 静态方法 | ❌ Module 变为构造函数 |
| `Process.getModuleByName('libc.so').getExportByName('memcpy')` | ✅ | ✅ 正确用法 |
| `NativeFunction(addr, 'pointer', ['pointer', 'pointer', 'uint'])` | ✅ | ✅ `uint`/`size_t` 均可用 |
| `Memory.alloc/readU8/readByteArray` | ✅ | ✅ 无变化 |
| `Interceptor.attach/detach` | ✅ | ✅ 无变化 |
| `Process.enumerateModules()` | ✅ | ✅ 无变化 |

**Bridge 变化（frida 17.0.0+ 最重要的变化，已实测验证）**:

Frida 17.0.0 起，Java/ObjC/Swift bridge **不再内置到 GumJS runtime**。

| 环境 | Java 可用? | 原因 |
|------|-----------|------|
| `frida` CLI (REPL) + `frida-trace` | ✅ | 内置了全部三个 bridge |
| Python SDK `session.create_script(source)` | ❌ | bridge 不内置，`typeof Java === "undefined"` |
| Python SDK `frida.Compiler().build(ts)` | ✅ | 编译时打包 bridge 到 bundle 中 |

**Python SDK 使用 Java bridge 的方案（已实测通过）**:

```python
import frida

# 1. 编译 TypeScript（显式 import bridge）
compiler = frida.Compiler()
bundle = compiler.build("script.ts", project_root="/tmp/project")

# 2. 用编译产物创建脚本
script = session.create_script(bundle)
script.load()
```

TypeScript 脚本中显式 import:
```typescript
import Java from "frida-java-bridge";
```

前置条件: 项目目录需 `npm install frida-java-bridge`。Bundle 约 752KB。

**结论**: 所有涉及 Java/ObjC Hook 的 Python 脚本，必须走 `frida.Compiler` 编译流程，不能再直接传纯 JS 字符串给 `session.create_script()`。

### 2.4 方案 C: Hook 经验移植

**改动文件**:
- 新增 `.opencode/mobile-analysis/knowledge-base/frida-hook-principles.md`（合并 01-核心原则 + 03-Java-Bridge陷阱）
- 新增 `.opencode/mobile-analysis/knowledge-base/frida-hook-templates.md`（合并 02-Hook架构与模板 + 04-Native-Hook要点）
- 更新 `.opencode/agents/mobile-analysis.md`（知识库索引）

**设计**: 将 frida-scripts 的 7 篇经验文档精简合并为 2 个知识库文件（减少文件数，降低按需加载的复杂度），同时适配 17.x 的 API 变化。

**17.x 适配重点**:
- Java Hook 模板必须标注"Python SDK 需通过 `frida.Compiler` 编译"
- 所有 `Module.findExportByName` 替换为 `Process.getModuleByName().getExportByName()`
- Native Hook（Interceptor）无需 bridge，纯 JS 字符串仍可使用

### 2.5 方案 D: 加固识别与脱壳知识库 + DEX dump 脚本

**改动文件**:
- 新增 `.opencode/mobile-analysis/knowledge-base/android-unpacking.md`
- 新增 `.opencode/mobile-analysis/scripts/dex_dump.py`
- 更新 `.opencode/mobile-analysis/scripts/registry.json`
- 更新 `.opencode/agents/mobile-analysis.md`（知识库索引 + 脚本调用方式）

**知识库内容**:
- 常见加固识别特征表（梆梆/360/腾讯/爱加密等）
- 脱壳方法论（Frida 内存 dump 的 3 种策略：maps 扫描 / 全量扫描 / ClassLoader 枚举）
- 验证步骤

**脚本设计**: 
- dex_dump.py 使用 `frida.Compiler` 编译含 `import Java from "frida-java-bridge"` 的 TypeScript 脚本
- 内嵌 TypeScript 模板（DEX dump 逻辑），编译后注入目标进程
- 接受参数: `--pid <pid> --output <dir> --host <host:port>`

### 2.6 方案 E: DEX dump 的 Frida JS 沉淀脚本

**改动文件**:
- 新增 `.opencode/mobile-analysis/scripts/dex_dump.js`

**设计**: 独立的 JS 脚本，可被 frida CLI 直接加载（`frida -H ... -l dex_dump.js`）。仅用于 frida CLI 场景，Python SDK 场景使用 dex_dump.py 的内嵌 TypeScript 模板。

## §3 实现规范

### 3.1 实施步骤拆分

```
步骤 1. 创建 frida-17x-api.md 知识库
  - 文件: .opencode/mobile-analysis/knowledge-base/frida-17x-api.md
  - 预估行数: ~120 行
  - 验证点: 文件自包含 + API 变化表完整 + 代码示例正确（不使用已废弃 API）
  - 依赖: 无

步骤 2. 创建 frida-17x-bridge.md 知识库
  - 文件: .opencode/mobile-analysis/knowledge-base/frida-17x-bridge.md
  - 预估行数: ~150 行
  - 验证点: 文件自包含 + 包含 Python SDK 编译方案完整示例 + frida CLI 方案 + npm 前置条件 + 错误排查
  - 依赖: 无

步骤 3. 创建 frida-hook-principles.md 知识库
  - 文件: .opencode/mobile-analysis/knowledge-base/frida-hook-principles.md
  - 预估行数: ~200 行（合并 01-核心原则 + 03-Java-Bridge陷阱，适配 17.x）
  - 验证点: 包含 4 条铁律 + Java Bridge 陷阱 + 17.x bridge 编译机制说明 + 检查清单
  - 依赖: 步骤 2（引用 bridge 编译方案）

步骤 4. 创建 frida-hook-templates.md 知识库
  - 文件: .opencode/mobile-analysis/knowledge-base/frida-hook-templates.md
  - 预估行数: ~180 行（合并 02-Hook架构与模板 + 04-Native-Hook要点，适配 17.x）
  - 验证点: 包含标准 Hook 模板 + 拦截器链模式 + Native Hook 模板 + 17.x 适配
  - 依赖: 步骤 1（API 变化引用）+ 步骤 2（bridge 编译引用）

步骤 5. 创建 android-unpacking.md 知识库
  - 文件: .opencode/mobile-analysis/knowledge-base/android-unpacking.md
  - 预估行数: ~120 行
  - 验证点: 包含加固识别表 + 3 种 dump 策略 + 验证步骤
  - 依赖: 步骤 2（bridge 编译引用，DEX dump 需要 Java.perform）

步骤 6. 创建 manage_frida.py 脚本
  - 文件: .opencode/mobile-analysis/scripts/manage_frida.py
  - 预估行数: ~180 行
  - 验证点: `python manage_frida.py --help` 输出正确 + `python manage_frida.py --action status` 可运行
  - 依赖: 无（直接 import frida-scripts 的 library）

步骤 7. 创建 dex_dump.py 脚本（使用 frida.Compiler 编译 TypeScript）
  - 文件: .opencode/mobile-analysis/scripts/dex_dump.py
  - 预估行数: ~150 行（含内嵌 TypeScript 模板 + Compiler 编译逻辑 + DEX 保存逻辑）
  - 验证点: `python dex_dump.py --help` 输出正确
  - 依赖: 步骤 2（bridge 编译方案）
  - 备注:
    - 脚本内嵌 TypeScript 模板（含 `import Java from "frida-java-bridge"`），编译为 bundle 后注入
    - 编译需要临时项目目录：脚本在 `/tmp/frida-dex-dump/` 下自动创建 `package.json` + `npm install frida-java-bridge`
    - 首次运行自动安装 npm 依赖（约 2 秒），后续运行复用 node_modules
    - 接受参数: `--pid <pid> --output <dir> --host <host:port>`

步骤 8. 创建 dex_dump.js 沉淀脚本（frida CLI 用）
  - 文件: .opencode/mobile-analysis/scripts/dex_dump.js
  - 预估行数: ~60 行
  - 验证点: JS 语法检查通过（`node --check`）+ 无已废弃 API（不使用 Module.findExportByName）
  - 依赖: 步骤 1（使用 17.x API 写法）
  - 备注: 仅用于 `frida -H ... -l dex_dump.js` 场景。frida CLI/REPL 内置 Java bridge，无需显式 import，脚本直接使用 `Java.perform(...)` 即可

步骤 9. 更新 registry.json
  - 文件: .opencode/mobile-analysis/scripts/registry.json
  - 预估行数: ~30 行
  - 验证点: JSON 格式正确 + 包含 manage_frida.py 和 dex_dump.py 和 dex_dump.js 的注册信息
  - 依赖: 步骤 6, 7, 8

步骤 10. 更新 mobile-frida.md — 替换安装步骤为脚本调用 + 17.x bridge 说明
  - 文件: .opencode/mobile-analysis/knowledge-base/mobile-frida.md
  - 预估行数: ~40 行改动（替换手动安装步骤为 `python manage_frida.py` 调用 + Java Hook 模板加注 17.x bridge 说明）
  - 验证点: 安装步骤引用脚本 + Java Hook 模板区域添加 17.x 注意事项（"Python SDK 需走 Compiler 编译；frida CLI 可直接用"）+ ObjC Hook 模板区域添加同类说明
  - 依赖: 步骤 6（manage_frida.py）+ 步骤 2（bridge 编译方案）
  - 备注: Hook 模板代码本身不改（仍是标准 JS 语法），只在模板上方加注释说明编译要求

步骤 11. 更新 mobile-analysis agent prompt — 添加知识库索引和脚本调用说明
  - 文件: .opencode/agents/mobile-analysis.md
  - 预估行数: ~20 行（新增索引条目 + bridge 编译核心规则）
  - 验证点: prompt 行数 < 450 行 + 新知识库索引完整 + 包含 "Python SDK Java Hook 必须走 Compiler" 规则
  - 依赖: 步骤 1-5（知识库文件名确定）+ 步骤 6-8（脚本文件名确定）
```

### §3.2 编码规则

1. 知识库文件使用 `$SCRIPTS_DIR` 或 `$OPENCODE_ROOT` 变量引用路径，禁止硬编码绝对路径
2. Python 脚本通过 `sys.path.insert` 导入 frida-scripts 的 library 模块，不重复实现
3. JS 脚本使用 frida 17.x 的正确 API（`Process.getModuleByName` + `module.getExportByName`），禁止使用 `Module.findExportByName`
4. 知识库文件必须自包含（不依赖主 prompt 上下文即可理解）
5. 所有 Python 脚本用 `$BA_PYTHON`（venv）执行，不用系统 Python
6. **涉及 Java/ObjC Bridge 的 Python SDK 脚本必须使用 `frida.Compiler` 编译 TypeScript，禁止直接 `session.create_script(js_string)`**
7. **纯 Native Hook（Interceptor）无需 bridge，仍可用纯 JS 字符串**
8. dex_dump.py 的 TypeScript 模板内嵌在 Python 字符串中，编译时写入临时目录

### §3.3 架构影响

```
.opencode/
├── agents/mobile-analysis.md          ← 步骤 11 更新（+20 行索引）
└── mobile-analysis/
    ├── knowledge-base/
    │   ├── mobile-frida.md             ← 步骤 10 更新（替换安装步骤 + bridge 说明）
    │   ├── frida-17x-api.md            ← 步骤 1 新增（~120 行）
    │   ├── frida-17x-bridge.md         ← 步骤 2 新增（~150 行）
    │   ├── frida-hook-principles.md    ← 步骤 3 新增（~200 行）
    │   ├── frida-hook-templates.md     ← 步骤 4 新增（~180 行）
    │   └── android-unpacking.md        ← 步骤 5 新增（~120 行）
    └── scripts/
        ├── registry.json               ← 步骤 9 更新
        ├── manage_frida.py             ← 步骤 6 新增（~180 行）
        ├── dex_dump.py                 ← 步骤 7 新增（~150 行）
        └── dex_dump.js                 ← 步骤 8 新增（~60 行）
```

## §4 验收标准

### 功能验收
- [ ] `manage_frida.py --action start -s <device>` 能成功启动 frida-server 并输出 JSON
- [ ] `manage_frida.py --action status` 能检查 frida-server 运行状态
- [ ] `dex_dump.py --pid <pid> --output <dir>` 能 dump DEX 文件（通过 frida.Compiler 编译 TypeScript + Java bridge）
- [ ] `dex_dump.js` 可被 frida CLI 加载（`frida -H ... -l dex_dump.js`）
- [ ] frida-17x-api.md 覆盖所有已发现的 API 变化
- [ ] frida-17x-bridge.md 包含 Python SDK 编译方案的完整可复现代码示例
- [ ] frida-hook-principles.md 包含 4 条铁律 + Java Bridge 陷阱 + 17.x bridge 编译说明
- [ ] frida-hook-templates.md 的 Hook 模板全部使用 17.x API
- [ ] android-unpacking.md 包含至少 4 种加固的识别特征

### 回归验收
- [ ] mobile-analysis agent prompt 行数 < 450 行
- [ ] 现有知识库文件（android-tools.md, ios-tools.md, mobile-methodology.md, mobile-patterns.md）无破坏性变更
- [ ] frida-scripts 的 start-frida.py 功能不受影响
- [ ] 纯 Native Hook（无需 Java bridge）的 Python 脚本仍可用纯 JS 字符串

### 架构验收
- [ ] 新文件位于 `.opencode/mobile-analysis/` 下正确位置
- [ ] 无循环依赖
- [ ] Python 脚本通过 import frida-scripts library 复用逻辑，不重复实现
- [ ] JS 脚本使用 17.x API（不使用已废弃的 `Module.findExportByName`）
- [ ] 知识库文件自包含（不依赖主 prompt 上下文即可理解）

## §5 与现有需求文档的关系

无前置依赖。本需求为 mobile-analysis 的首次进化需求。
