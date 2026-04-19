# 动态分析策略

> AI 编排器在需要动态分析时通过 Read 工具按需加载。

## 触发条件

1. **动态脱壳**：阶段 2.5 定位到 OEP 后，需要 dump 解壳后的内存
2. **算法验证**：静态分析推导出算法后，需要用实际输入/输出对比验证
3. **运行时数据追踪**：需要追踪特定函数的参数、返回值、内存状态
4. **GUI 程序交互**：需要向 GUI 控件输入数据并读取结果

## 方案选择

| 方案 | 优先级 | 适用场景 | 前置条件 |
|------|--------|---------|---------|
| IDA 内置调试器 | **首选** | 本地可执行文件、脱壳、断点追踪、算法验证 | 无（IDA 自带） |
| Frida | 后备 | IDA 调试器失败（强反调试）、需要注入远程进程 | pip install frida |

**优先使用 IDA 内置调试器**。仅当 IDA 调试器不可用或失败时，才切换到 Frida：
- 读取 `$SCRIPTS_DIR/ida-pro-analysis-knowledge-base/dynamic-analysis-frida.md`

---

## IDA 内置调试器

### 核心优势

- 零额外依赖（IDA 自带调试器模块）
- dump 后数据直接在 IDA 内，无需重新加载
- 使用标准 OS 调试 API（Windows: Win32 Debug API, Linux: ptrace），不被反 Frida 检测
- 可在 idat headless 模式下运行（`idat -A -S<script>`）

### 事件驱动调试模型（强制）

IDA 调试器使用**事件驱动模型**，而非轮询。核心模式：

```python
import ida_dbg
import ida_ida
import ida_segment
import ida_bytes

class MyHook(ida_dbg.DBG_Hooks):
    def dbg_run_to(self, pid, tid=0, ea=0):
        ida_dbg.refresh_debugger_memory()
        pc = ida_dbg.get_reg_val("EIP")  # 或 "RIP"（64-bit）
        # ... 处理断点命中 ...
        ida_dbg.request_exit_process()
        ida_dbg.run_requests()

    def dbg_process_exit(self, pid, tid, ea, code):
        # 进程退出回调
        return 0

def _load_debugger():
    if ida_ida.inf_get_filetype() == ida_ida.f_PE:
        ida_dbg.load_debugger("win32", 0)
    elif ida_ida.inf_get_filetype() == ida_ida.f_ELF:
        ida_dbg.load_debugger("linux", 0)
    elif ida_ida.inf_get_filetype() == ida_ida.f_MACHO:
        ida_dbg.load_debugger("mac", 0)

_load_debugger()
hook = MyHook()
hook.hook()
ida_dbg.run_to(target_addr)

while ida_dbg.get_process_state() != 0:
    ida_dbg.wait_for_next_event(1, 0)

hook.unhook()
```

**关键点**：
- **必须调用 `ida_dbg.load_debugger()`**：根据文件类型加载对应调试器插件（win32/linux/mac）
- **使用 `DBG_Hooks` 回调**：不在外部轮询，在回调中处理事件
- **使用 `ida_dbg.run_to(addr)`**：运行到指定地址（设置临时断点并启动）
- **headless 事件循环**：`ida_dbg.wait_for_next_event(1, 0)` 驱动事件，直到 `get_process_state() == 0`
- **在回调中用 `request_*` + `run_requests()`**：如 `request_exit_process()` + `run_requests()`

### 核心 IDAPython 调试 API

| API | 用途 |
|-----|------|
| `ida_dbg.load_debugger(plugin, opts)` | 加载调试器插件（"win32"/"linux"/"mac"） |
| `ida_dbg.run_to(ea)` | 运行到指定地址（启动进程 + 临时断点） |
| `ida_dbg.add_bpt(ea)` | 添加断点 |
| `ida_dbg.del_bpt(ea)` | 删除断点 |
| `ida_dbg.get_reg_val(name)` | 读寄存器（EIP/RIP/EAX/RAX 等） |
| `ida_dbg.set_reg_val(name, val)` | 写寄存器 |
| `ida_dbg.is_debugger_on()` | 调试器是否激活 |
| `ida_dbg.get_process_state()` | 进程状态（0 = 未运行） |
| `ida_dbg.refresh_debugger_memory()` | 刷新内存视图（断点命中后必须调用） |
| `ida_dbg.wait_for_next_event(wf, timeout)` | headless 事件循环驱动 |
| `ida_dbg.DBG_Hooks` | 事件回调基类 |
| `ida_dbg.request_continue_process()` | 请求继续运行（需配 `run_requests()`） |
| `ida_dbg.request_step_into()` | 请求单步进入（需配 `run_requests()`） |
| `ida_dbg.request_step_over()` | 请求单步跳过（需配 `run_requests()`） |
| `ida_dbg.request_exit_process()` | 请求终止进程（需配 `run_requests()`） |
| `ida_dbg.run_requests()` | 执行已排队的请求 |

配合 `ida_bytes.get_bytes(ea, size)` 在断点命中时读取任意内存。

### 脱壳场景：debug_dump.py

项目内置 IDA 调试器脱壳脚本：`$SCRIPTS_DIR/scripts/debug_dump.py`

**使用方式**：
```bash
IDA_OEP_ADDR=0x401000 IDA_OUTPUT="$TASK_DIR/unpacked.exe" \
  "$IDAT" -A -S"$SCRIPTS_DIR/scripts/debug_dump.py" \
  -L"$TASK_DIR/debug_dump.log" "<目标文件>.i64"
```

**脚本功能**：
1. 根据文件类型自动加载调试器插件（`ida_dbg.load_debugger()`）
2. 读取 `IDA_OEP_ADDR` 环境变量获取 OEP 地址
3. 注册 `DBG_Hooks` 回调，在 `dbg_run_to` 中处理断点命中
4. `run_to(OEP)` 启动调试并运行到 OEP
5. 断点命中后 dump 所有段内存
6. 从 dump 数据重建 PE 文件（修正段表、入口点；**不含 IAT 重建**，仅用于 IDA 加载）
7. 写入 `IDA_OUTPUT` 指定路径
8. 终止调试进程并退出

**环境变量**：

| 变量 | 必填 | 说明 |
|------|------|------|
| `IDA_OEP_ADDR` | 是 | OEP 地址（十六进制，如 `0x401000`） |
| `IDA_OUTPUT` | 是 | 输出文件路径 |
| `IDA_DEBUG_TIMEOUT` | 否 | 等待断点超时（秒），默认 60 |

**注意**：输出的 PE 文件仅用于 IDA 加载分析，不含 IAT 重建。如需完整可执行文件，需额外使用 Import Reconstructor 工具。

### 断点追踪场景

在已加载的 IDA 数据库中（非脱壳），通过 IDAPython 脚本设断点追踪：

1. **追踪函数参数**：在目标函数入口设断点，命中后读取参数寄存器（ECX/RCX、EDX/RDX 等）
2. **追踪返回值**：在函数出口设断点（`ret` 指令处），读取 EAX/RAX
3. **追踪内存写入**：在关键地址设硬件断点（`ida_dbg.add_bpt(ea, 0, ida_dbg.BPT_WRITE)`）

通用追踪脚本模板（事件驱动）：
```python
import ida_dbg
import ida_bytes
import ida_ida

def _load_debugger():
    if ida_ida.inf_get_filetype() == ida_ida.f_PE:
        ida_dbg.load_debugger("win32", 0)
    elif ida_ida.inf_get_filetype() == ida_ida.f_ELF:
        ida_dbg.load_debugger("linux", 0)
    elif ida_ida.inf_get_filetype() == ida_ida.f_MACHO:
        ida_dbg.load_debugger("mac", 0)

class TraceHook(ida_dbg.DBG_Hooks):
    def __init__(self):
        ida_dbg.DBG_Hooks.__init__(self)

    def dbg_bpt(self, tid, ea):
        ida_dbg.refresh_debugger_memory()
        reg_val = ida_dbg.get_reg_val("EAX")
        mem_data = ida_bytes.get_bytes(addr, size)
        # ... 处理数据 ...
        ida_dbg.request_continue_process()
        ida_dbg.run_requests()
        return 0

    def dbg_process_exit(self, pid, tid, ea, code):
        return 0

_load_debugger()
ida_dbg.add_bpt(target_addr)

hook = TraceHook()
hook.hook()
ida_dbg.run_to(target_addr)

while ida_dbg.get_process_state() != 0:
    ida_dbg.wait_for_next_event(1, 0)

hook.unhook()
```

### GUI 程序交互（仅 Windows）

IDA 调试器启动程序后，GUI 窗口正常显示。分析者可：
1. 手动在 GUI 中输入数据（程序在断点处暂停时无法交互，需要 resume 后操作）
2. 通过 IDAPython 脚本调用 Win32 API 自动化：
   - `SetDlgItemTextA` 设置编辑框内容
   - `PostMessageA(WM_COMMAND)` 触发按钮点击
3. 设断点在目标函数，让程序运行到断点后读取状态

### 限制

- **反调试检测**：部分壳使用 `IsDebuggerPresent`、`NtQueryInformationProcess` 等检测调试器。遇到时切换到 Frida
- **仅限本地**：IDA 调试器只能调试本机进程
- **平台绑定**：Windows 调试器只能调试 Windows 程序，Linux 只能调试 Linux 程序
- **headless 事件循环**：必须用 `ida_dbg.wait_for_next_event()` 驱动，不能省略
