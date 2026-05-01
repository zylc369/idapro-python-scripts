# AliCrackme2 复盘改进：Frida 排查 SOP + Android UI 自动化 + jadx-smali 分层原则

## §1 背景与目标

### 来源
分析 APK `AliCrackme2_1_难度86.apk`（Cobb的记忆）时的复盘。

### 痛点
1. **Frida 超时排查无 SOP**：frida-server 异常状态导致所有方案超时。重启 server 后只测了纯 Native 脚本（成功），没有重新尝试 CLI + Java bridge，误判"Java bridge 不可用"。浪费 ~8 轮。
2. **Android UI 自动化知识缺失**：keycode 映射错误（2 次）、`input text` 追加换行导致 NumberFormatException（1 次）。浪费 ~3 轮。
3. **jadx-smali 分层验证原则缺失**：jadx 显示 `j = jIntValue` 但 smali 中 `v10 = 124750 + jIntValue`。早期基于 jadx 推导的公式有误，没有及时在 smali 层验证。

### 预期收益
| 维度 | 改进前 | 改进后 |
|------|--------|--------|
| 上下文 | Frida 超时排查消耗 ~8 轮 | 排查 SOP 指引下 2 轮内定位并解决 |
| 轮次 | keycode/换行浪费 3 轮 | 有参考表直接正确 |
| 准确度 | jadx 映射错误导致公式推导全错 | 分层验证避免误判 |

## §2 技术方案

### 改动 1：补充 Frida 超时排查 SOP
- **文件**: `$OPENCODE_ROOT/mobile-analysis/knowledge-base/frida-17x-bridge.md`
- **位置**: 在现有"错误排查"表格后新增章节"超时排查 SOP"
- **内容**: 
  - 症状识别（`Failed to load script: timeout`、`create_script` TransportError）
  - 分步排查流程（重启 server → 测纯 Native → 测 CLI + Java bridge → 测 Python SDK）
  - 关键提醒：**重启 server 后必须重新尝试所有方案**，不能只试一个就放弃

### 改动 2：新增 Android UI 自动化知识库
- **文件**: `$OPENCODE_ROOT/mobile-analysis/knowledge-base/android-ui-automation.md`（新建）
- **内容**:
  - Android 数字键 keycode 映射表（KEYCODE_0=7 到 KEYCODE_9=16）
  - `adb shell input text` 的换行陷阱（用 keyevent 替代）
  - `uiautomator dump` + 坐标点击的标准操作流程
  - ScrollView 中控件可能不可见的处理方法

### 改动 3：补充 jadx-smali 分层分析原则
- **文件**: `$OPENCODE_ROOT/mobile-analysis/knowledge-base/mobile-methodology.md`
- **位置**: 在"路径 2: Smali 级精读"章节后新增分析原则
- **内容**:
  - jadx 用于快速理解结构和变量命名
  - smali 是 ground truth，关键公式（比较、返回值、跳转条件）必须在 smali 层验证
  - jadx 变量映射在高度混淆代码中不可靠的案例说明

## §3 实施规范

### §3.1 实施步骤拆分

**步骤 1. 补充 Frida 超时排查 SOP**
- 文件: `$OPENCODE_ROOT/mobile-analysis/knowledge-base/frida-17x-bridge.md`
- 预估行数: ~40 行（在"错误排查"章节后新增）
- 验证点: 人工读一遍确认自包含性 + 引用路径正确
- 依赖: 无

**步骤 2. 新建 Android UI 自动化知识库**
- 文件: `$OPENCODE_ROOT/mobile-analysis/knowledge-base/android-ui-automation.md`（新建）
- 预估行数: ~80 行
- 验证点: 人工读一遍确认自包含性（知识库文件必须不依赖主 prompt 上下文即可理解）
- 依赖: 无

**步骤 3. 补充 jadx-smali 分层分析原则**
- 文件: `$OPENCODE_ROOT/mobile-analysis/knowledge-base/mobile-methodology.md`
- 预估行数: ~30 行（在路径 2 后新增章节）
- 验证点: 人工读一遍确认与现有内容无冲突
- 依赖: 无

## §4 验收标准

### 功能验收
- [x] frida-17x-bridge.md 包含超时排查 SOP，覆盖"重启 server 后必须重试所有方案"
- [x] android-ui-automation.md 包含完整 keycode 映射表 + input text 换行陷阱 + uiautomator 流程
- [x] mobile-methodology.md 包含 jadx-smali 分层分析原则

### 回归验收
- [x] frida-17x-bridge.md 原有内容未被破坏
- [x] mobile-methodology.md 原有的决策树和路径映射表未被破坏

### 架构验收
- [x] 所有新文件在 `$OPENCODE_ROOT/mobile-analysis/knowledge-base/` 下（移动端特有知识）
- [x] 无循环依赖，无跨层引用违规

## §5 与现有需求文档的关系

- 独立需求，不依赖其他未完成的需求文档
- 与 `mobile-analysis-evolve-v1.md`（mobile-analysis agent 初版）互补
