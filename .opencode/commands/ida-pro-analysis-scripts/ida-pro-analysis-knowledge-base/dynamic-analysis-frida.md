# 动态分析策略 — Frida 模式

> 本文档是 Frida 专用动态分析知识库。IDA 调试器为首选方案，详见 `dynamic-analysis.md`。
> 仅当 IDA 调试器不可用或失败时，才使用本文档中的 Frida 方案。

## 触发条件

以下场景需要动态分析（Frida），而非纯静态分析：

1. **算法验证**：静态分析推导出算法后，需要用实际输入/输出对比验证
2. **动态脱壳**：静态脱壳失败，需要 dump 解壳后的内存（详见 `packer-handling.md` 阶段 3.5）
3. **运行时数据追踪**：需要追踪特定函数的参数、返回值、内存状态
4. **GUI 程序自动化**：需要向 GUI 控件输入数据并读取结果

---

## Frida 版本适配（Frida 16 → 17）

Frida 17 对 API 做了破坏性变更。下表列出关键差异：

| 操作 | Frida 16 | Frida 17 |
|------|----------|----------|
| 读 1 字节 | `Memory.readU8(ptr(0xaddr))` | `ptr(0xaddr).readU8()` |
| 读 N 字节 | `Memory.readByteArray(ptr, n)` | `ptr.readByteArray(n)` |
| 写字符串 | `Memory.writeUtf8String(ptr, s)` | `ptr.writeUtf8String(s)` |
| 分配字符串 | `Memory.allocUtf8String(s)` | 不变 |
| 获取导出函数 | `Module.getExportByName("dll", "func")` | `Process.getModuleByName("dll").getExportByName("func")` |
| NativeFunction | `new NativeFunction(addr, ret, args)` | 不变 |

**适配策略**：检测 `Frida.version` 字符串，或直接使用 Frida 17 风格（2024+ 的主流版本）。

---

## 加壳程序动态分析模式

### 核心流程

```
spawn(挂起) → attach → create_script → resume → 轮询解壳 → dump/hook
```

### 关键发现

**spawn 后代码仍是加密的！** 必须 resume 后等待解壳完成。

### 检测解壳完成

轮询入口点地址的字节，直到变为合法指令：

```javascript
// 检测 0x401610（举例）是否已解壳
// 0x55 = push ebp，x86 函数常见首字节
var b = ptr(0x401610).readU8();
if (b === 0x55) {
    // 解壳完成
}
```

或使用 `disassembler/frida_unpack.py` 的内置监控机制（自动检测代码段写入并等待稳定）。

---

## GUI 程序处理模式（仅 Windows）

> 以下 Win32 API 自动化模式仅适用于 Windows 平台。Linux/macOS 需使用 X11/Wayland 自动化（不在本文档范围内）。

### 设置编辑框内容

**禁止**直接写内存缓冲区（如 `ptr(0x417180).writeUtf8String(name)`）——因为 GUI 程序通过 `GetDlgItemTextA` 从控件读取，不是从固定地址读取。

**正确做法**：用 `SetDlgItemTextA` 写入控件：

```javascript
var user32 = Process.getModuleByName("user32.dll");
var SetDlgItemTextA = new NativeFunction(
    user32.getExportByName("SetDlgItemTextA"),
    "int", ["pointer", "int", "pointer"]
);
var textPtr = Memory.allocUtf8String("my_input");
SetDlgItemTextA(hwnd, controlId, textPtr);
```

### 触发按钮点击

**禁止** `SendMessageA(btn, BM_CLICK, 0, 0)` ——同步调用，如果按钮处理函数弹出 MessageBox，会阻塞 JS 线程。

**正确做法**：用 `PostMessageA` 发送 `WM_COMMAND`：

```javascript
var PostMessageA = new NativeFunction(
    user32.getExportByName("PostMessageA"),
    "int", ["pointer", "uint", "pointer", "pointer"]
);
var WM_COMMAND = 0x0111;
var btnId = 0x3EB;  // 按钮控件 ID
var btn = GetDlgItem(hwnd, btnId);
PostMessageA(hwnd, WM_COMMAND, ptr(btnId), btn);
```

### 读取结果

按钮点击后，程序可能弹出 MessageBox 显示结果。用 `EnumWindows` 遍历所有窗口，找到 `#32770`（Dialog）类的窗口，读取标题：

```javascript
var EnumWindows = new NativeFunction(
    user32.getExportByName("EnumWindows"),
    "int", ["pointer", "pointer"]
);
var GetWindowTextA = new NativeFunction(
    user32.getExportByName("GetWindowTextA"),
    "int", ["pointer", "pointer", "int"]
);
var GetClassNameA = new NativeFunction(
    user32.getExportByName("GetClassNameA"),
    "int", ["pointer", "pointer", "int"]
);
```

---

## NativeFunction 调用限制

### 加壳/SEH 程序中的崩溃风险

在加壳或使用 SEH（结构化异常处理）的程序中，`NativeFunction` 直接调用函数可能崩溃：
- 原因：Frida JIT 机制与程序自身的 SEH handler 冲突
- 症状：`script has been destroyed` 或进程崩溃

### 替代方案

1. **Hook + 输入模拟**：用 `Interceptor.attach` hook 目标函数，通过 GUI 自动化触发（而非直接调用）
2. **纯 Python 本地验证**：在 Python 中重新实现算法（MD5/RC4/RSA 等），不依赖进程内调用
3. **Unicorn 模拟**：在 Unicorn CPU 模拟器中执行（适合简单函数，不适合复杂壳）

---

## 进程清理模板

每次 Frida 脚本执行必须有严格超时和清理：

```python
import frida, time, os

pid = frida.spawn(target)
session = frida.attach(pid)
script = session.create_script(js_code)
script.load()
frida.resume(pid)

try:
    # 等待结果，带超时
    time.sleep(max_wait)
except Exception:
    pass
finally:
    # 无论成功失败都清理
    try:
        session.detach()
    except Exception:
        pass
    # GUI 程序弹出模态对话框时进程不会自行退出，必须 kill
    if os.name == "nt":
        os.system(f"taskkill /PID {pid} /F >nul 2>&1")
    else:
        os.system(f"kill -9 {pid} 2>/dev/null")
```

**关键原则**：
- 超时后必须 kill 进程（GUI 程序不会自行退出）
- `session.detach()` 必须在 finally 中
- 跨平台 kill 命令：Windows `taskkill`，Unix `kill -9`
