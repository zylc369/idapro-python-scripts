# 进化-GUI自动化操作

> 来源：用户与 AI 的深度讨论（2026-04-23），讨论记录见本轮对话上下文。
> 关联文档：`docs/进化/进化-解决GUI验证卡住问题.md`、`docs/进化/进化-分析TencentPediyKeygenMe2的问题和疑问记录.md`
> 本文档为 Phase 0-1 产出，待用户 REVIEW 后进入 Phase 2。

---

## Phase 0: 复盘分析

### 0.1 痛点统计

| # | 痛点 | 出现次数 | 后果 |
|---|------|---------|------|
| 1 | GUI 操作卡住（超时等待） | ≥3 次（TencentPediyKeygenMe2 分析过程） | 浪费 5+ 分钟/次，用户被迫中断 |
| 2 | Agent 因 GUI 卡住而走极端（"100% 静态分析"） | ≥2 次 | 方向偏移，错过最优路径 |
| 3 | GUI 操作需要用户手动介入 | ≥1 次（patch 二进制后请用户点击 Verify） | 自动化链断裂，需人工接力 |
| 4 | 验证结果不准确（作弊式验证） | ≥5 次（同一 binary 连续给错误 license） | 用户信任度下降 |
| 5 | `gui_verify.py` 对非标准控件无效 | 多次 | MFC/Qt/Electron 等框架完全不支持 |

### 0.2 根因分析

**当前 `gui_verify.py` 的 5 个根本缺陷**：

| # | 缺陷 | 代码位置 | 影响 |
|---|------|---------|------|
| 1 | 控件 ID 硬编码（1000/1001/1002） | L97-99 | 不同程序控件 ID 不同，直接失败 |
| 2 | 线性流水线 + 单一 timeout | L97-129 | 任何一步失败都静默等待到超时才返回 |
| 3 | 只能用 Win32 消息机制操作控件 | L232-243 | MFC/Qt/Electron/Delphi 部分控件不响应 `WM_SETTEXT` |
| 4 | 结果检测依赖 MessageBox 关键词匹配 | L101-102 | 静默失败（无弹窗）的程序无法判断结果 |
| 5 | 不截图不留痕 | 全文件 | 失败后无法诊断"哪一步出了问题" |

**更深层的原因**：当前方案试图用**控件级 API**（`GetDlgItem` + `SendMessage`）操作 GUI，这条路的通用性天花板很低——每种 GUI 框架的控件实现不同，不可能逐一适配。

### 0.3 用户提出的核心洞察

> "LLM 解决看和坐标的问题，GUI 自动化执行框架解决操作的问题，操作包括：点击、调用输入法输入，即完全模拟人的操作。"

这条路径的正确性已被验证：Anthropic Computer Use、OpenAI Operator 等产品已在走同样的架构——**截图 → 多模态理解 → 坐标级键鼠操作 → 再截图**。

### 0.4 关键约束

用户明确给出以下约束：

| # | 约束 | 说明 |
|---|------|------|
| 1 | 视觉理解能力 | 已有 zai-mcp-server MCP（GLM-4.6V），全局安装在 OpenCode 中，timeout 已设为 120s |
| 2 | 截图/录屏范围 | 全屏截图、全屏录屏（最大可能捕获完整窗口） |
| 3 | 文件存储 | 图片、视频存储到 `~/bw-ida-pro-analysis/view/temp_files/`（MCP 需要本地文件路径） |
| 4 | 文件大小 | 在 AI 能识别的前提下尽量小（减少 MCP 处理时间和超时风险） |
| 5 | 可移植 | 能在不同电脑上运行 |
| 6 | 跨平台 | Windows 先做，后续支持 macOS/Linux |
| 7 | 双入口 | 用户能主动触发命令，Binary-Analysis agent 也能调用 |

---

## Phase 1: 候选方案评估

### 方案 A（推荐做）：视觉驱动 GUI 自动化

**核心思路**：用多模态 LLM（zai-mcp-server）识别截图中的控件位置和文字，用坐标级键鼠操作（pyautogui + pyperclip）模拟人的操作，用截图对比判断操作结果。

```
┌──────────┐     ┌──────────────┐     ┌──────────┐
│ 截图(Eye) │ ──→ │ MCP视觉(Brain)│ ──→ │ 键鼠(Hand)│
│ 全屏截图   │     │ 识别控件坐标   │     │ click/type│
└──────────┘     └──────────────┘     └──────────┘
       ↑                                    │
       └────── 再截图，对比前后变化 ←─────────┘
```

**架构设计**：

```
新增文件:
.opencode/commands/gui-interact.md      ← OpenCode 命令（薄壳，引用知识库）
.opencode/binary-analysis/
  scripts/
    gui_capture.py                       ← 截图/录屏（输出文件 + 元数据 JSON）
    gui_act.py                           ← 键鼠操作（click/type/hotkey）
    gui_launch.py                        ← 进程/窗口管理（启动、查找、前台、kill）
  knowledge-base/
    gui-automation.md                    ← GUI 自动化操作规范（单点维护）

删除/废弃:
  scripts/gui_verify.py                  ← 被 gui_capture + gui_act + gui_launch 替代
```

**关键设计决策**：

#### 决策 1：gui-interact 命令是薄壳

```markdown
# gui-interact.md 的全部内容（约 5 行）:
---
description: GUI 自动化交互 — 截图、视觉识别、键鼠操作
---
使用 Read 工具读取 $SCRIPTS_DIR/knowledge-base/gui-automation.md，按照其中的规范执行用户的 GUI 操作请求。
```

- 命令只是一个入口，所有逻辑写在 `knowledge-base/gui-automation.md`
- Binary-Analysis agent 需要操作 GUI 时，也读取同一个知识库文件
- **单点维护**：改知识库 = 命令和 agent 都更新

#### 决策 2：截图对比判断操作结果（而非读回验证）

```
操作前截图 (before)
    ↓ 执行操作
    ↓ 等待 settle (0.5~1s)
操作后截图 (after)
```

**MCP 调用方式**：使用 `zai-mcp-server_ui_diff_check` 工具，将 before 作为 `expected_image_source`、after 作为 `actual_image_source` 传入，prompt 指定"对比这两张截图，识别所有视觉变化（新弹窗、文字变化、控件状态变化等）"。如果 `ui_diff_check` 不可用或超时，退化为用 `zai-mcp-server_analyze_image` 单独分析 after 截图，prompt 中描述 before 的状态（如"操作前窗口中有两个空白输入框和一个 Verify 按钮"），让 MCP 判断当前状态是否发生了变化。

**为什么不用 `WM_GETTEXT` 读回验证**：只对 Win32 标准控件有效，Qt/Electron/WPF 不响应，不通用。截图对比是唯一跨框架通用的验证方式。

**静默失败场景的处理**：
- MCP 说"两张图片看起来一样" → 这本身就是诊断信息
- 策略：换一种操作方式重试一次（剪贴板粘贴 → 逐字输入）
- 仍然没变化 → 坐标可能偏了，重新截图让 MCP 再次定位

#### 决策 3：截图用 JPEG 格式

```
全屏 PNG 1920x1080 ≈ 1~3MB → MCP 处理 ~15s，超时风险高
全屏 JPEG quality=75 ≈ 200~500KB → MCP 处理 ~8s，超时风险低
```

除非需要 OCR（OCR 用 PNG 更清晰），默认用 JPEG。

#### 决策 4：坐标系统 — 统一用 pyautogui，无需映射

截图和操作统一使用 `pyautogui`，**不需要坐标换算**。原因：`pyautogui.screenshot()` 返回的图片像素尺寸和 `pyautogui.click()` 使用的坐标系统是一致的（都是物理像素坐标），pyautogui 内部处理了 DPI 缩放。MCP 返回图片坐标 (460, 320) → 直接 `pyautogui.click(460, 320)` 即可。

`gui_capture.py` 截图时输出的元数据仅用于记录和调试，不参与坐标换算：

```json
{
  "screenshot": "screen.jpg",
  "screen_resolution": [1920, 1080],
  "screenshot_size": [1920, 1080],
  "format": "jpeg",
  "quality": 75
}
```

**注意**：如果未来切换到 `mss` 截图（性能更好），mss 返回的是原始物理像素，需要确认与 pyautogui.click() 的坐标系统是否一致后再决定是否需要映射。

#### 决策 5：录屏不用于判断操作成功

MCP 视频理解基于关键帧提取（不是逐帧分析），无法可靠判断"按钮是否被点击"这种瞬时事件。视频限制 8MB 也严重限制录屏时长。录屏可保留作为调试/回看功能，但不作为操作成功判断的主要手段。

#### 决策 6：进程管理策略

- 启动前检查目标进程是否已运行 → 已运行则 kill 再启动（而非切到后台）
- kill 自己启动的进程不需要管理员权限
- 避免"两个同名窗口同时显示干扰截图识别"

#### 决策 7：先做 Windows，后续扩展

`gui_launch.py` 对外暴露统一接口（`launch / find_window / bring_to_front / kill`），内部按平台分发实现。P0 只实现 Windows 版本，P1/P2 补充 macOS/Linux 实现时只改 gui_launch.py 内部，其他脚本和知识库不受影响。

| 期 | 平台 | 截图 | 操作 | 窗口管理 |
|----|------|------|------|---------|
| P0 | Windows | pyautogui | pyautogui + pyperclip | subprocess + ctypes Win32 |
| P1 | macOS | pyautogui | pyautogui + subprocess("osascript") | subprocess("open") + AppleScript |
| P2 | Linux | pyautogui | pyautogui + xdotool | xdotool + wmctrl |

每期脚本接口相同，内部实现按平台切换。MCP 视觉理解层完全不需要改。

**四维度量评估**：

| 维度 | 改进前（gui_verify.py） | 改进后（视觉驱动） | 提升 |
|------|------------------------|-------------------|------|
| 上下文 | GUI 卡住后多轮对话排查 | 一步到位，截图→识别→操作 | 减少 3-5 轮 |
| 轮次 | GUI 操作经常需要用户介入 | 全自动，零人工介入 | 从 N 次人工 → 0 次 |
| 速度 | 卡住等待 30s timeout × N 步 | 每步 5-10s（截图+MCP+操作） | 显著 |
| 准确度 | 控件 ID 猜错/消息机制不生效 | 视觉定位，不依赖控件 API | 根本性提升 |

```
结论: 推荐做
实现成本: 新增 4 个文件（gui_capture.py ~100行, gui_act.py ~80行, gui_launch.py ~100行, gui-automation.md ~150行），废弃 1 个文件
上下文成本: 主 prompt 仅加 2-3 行引用，详细内容在知识库
风险: 依赖 zai-mcp-server MCP 的可用性和响应速度；依赖 pyautogui/pyperclip 的安装
```

---

### 方案 B（可选做）：保留 gui_verify.py 作为 Win32 快速路径

**思路**：对于确认是标准 Win32 对话框的程序（`discover` 模式检测到 `Edit`/`Button` 类名），保留 `gui_verify.py` 作为快速验证路径（不需要 MCP 调用，速度更快）。

**与 agent prompt 的冲突风险**：当前 `binary-analysis.md` 验证决策树中 `GUI → gui_verify.py`（L248）。如果保留 gui_verify.py，agent 在遇到 GUI 验证时需要选择"视觉驱动"还是"Win32 快速路径"——这增加了 agent 的决策复杂度和 prompt 体积。如果删除 gui_verify.py，agent 只有一条路径，简单可靠。

```
结论: 可选做
原因: 方案 A 完全覆盖 gui_verify.py 的能力。保留的收益是"标准 Win32 场景更快（2s vs 15s）"，但增加了维护成本（两套方案）和 agent 决策复杂度。建议：方案 A 稳定后再评估是否值得保留。如果 MCP 超时频繁，可作为降级策略。
```

---

### 方案 C（可选做）：录制视频用于用户回看

**思路**：在 GUI 自动化操作过程中录制全屏视频，操作结束后用户可以回看视频了解操作过程。

```
结论: 可选做
原因: 对分析准确度无直接提升，但对用户信任度和调试有帮助。实现成本低（gui_capture.py 加一个 --record 参数），但增加了文件管理复杂度。可在方案 A 稳定后作为增强功能添加。
```

---

### 方案 D（不建议做）：用录屏 + MCP 视频分析判断操作成功

**思路**：录制操作过程视频 → 让 MCP 分析视频 → 判断按钮是否被点击、输入是否成功。

```
结论: 不建议做
原因:
1. MCP 视频理解是关键帧提取（3-5 帧），不是逐帧分析，按钮点击（1-2帧/33ms）大概率被跳过
2. 视频限制 8MB，全屏录屏 5-10 秒就超限
3. 无法区分"操作没执行"和"操作执行了但程序静默失败"
4. 截图对比方案更可靠、更快、文件更小
```

---

### 方案 E（不建议做）：WM_GETTEXT 读回验证

**思路**：输入文本后用 `WM_GETTEXT` 读回编辑框内容，验证输入是否成功。

```
结论: 不建议做
原因: 只对 Win32 标准控件有效，Qt/Electron/WPF/Delphi 部分控件不响应。作为跨框架通用方案不成立。
```

---

## MCP 超时问题（已解决）

**问题**：`zai-mcp-server_analyze_image` 调用慢，出现 `Request timed out` 后 OpenCode fallback 到 GLM5.1 模型，导致"当前模型不支持图像输入"错误。

**已采取措施**：
1. `opencode.json` 中 `zai-mcp-server` 的 `timeout` 已改为 `120000`（120 秒）
2. 截图默认使用 JPEG 格式（200-500KB vs PNG 1-3MB），从根源减少 MCP 处理时间

**待观察**：实际使用中 120s 是否足够，JPEG 截图是否影响识别精度。如果仍然超时，考虑进一步降低截图分辨率到 1280x720。

---

## 等待用户确认

以上为 Phase 0-1 的完整分析。请 REVIEW 后告知：

1. 方案 A（视觉驱动 GUI 自动化）是否确认？是否有调整？
2. 方案 B（保留 gui_verify.py 快速路径）是否要做？
3. 方案 C（录制视频回看）是否要做？
4. 其他调整或补充？

确认后进入 Phase 2 生成需求文档。
