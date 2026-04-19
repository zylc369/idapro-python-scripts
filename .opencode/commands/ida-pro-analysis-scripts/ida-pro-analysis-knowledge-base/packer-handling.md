# 加壳/混淆二进制处理策略

> AI 编排器在检测到加壳时通过 Read 工具按需加载。

## 触发条件

`packer_detect` 返回 `packer_detected: true`，或 `segments` 返回 `packer_warning.detected: true`。

以下流程**仅在检测到加壳时激活**，非加壳场景不走此分支。

## 阶段 1：壳检测

首次分析新二进制时，在 `entry_points` 查询后立即调用 `packer_detect`。

## 阶段 2：已知壳自动脱壳

检测到已知壳名（`packer_name` 不为 null 且不为 "unknown"）时：

1. 检查系统是否安装对应脱壳工具（`which upx` 等）
2. **已安装** → 执行脱壳（输出到 `$TASK_DIR`，不覆盖原文件），如 `upx -d "<原始文件>" -o "$TASK_DIR/<文件名>_unpacked"`
3. **已安装但脱壳失败** → 进入阶段 2.5
4. **未安装** → 告知用户安装命令（如 `brew install upx`），然后进入阶段 2.5

脱壳成功后 → 用 `file` 命令验证输出文件类型 → 跳到"脱壳后后续流程"。

## 阶段 2.5：关键点绕过（适用于任何壳）

**核心思路**：壳的本质是"运行时还原代码"。不需要理解壳如何还原，只需要找到还原完成的那一刻，dump 内存即可。

### 策略 2.5.1：定位 OEP（原始入口点）

解壳 stub 结束时必然跳转到 OEP。通过分析 stub 尾部找到跳转指令，计算 OEP 地址。

从 `entry_points` 获取 `architecture` 字段，根据架构选择对应的 OEP 模式表：

#### x86 (32-bit)

| 模式 | 字节序列 | 说明 |
|------|---------|------|
| `popad; jmp OEP` | `61 E9 xx xx xx xx` | 经典 UPX 模式。`popad` 恢复寄存器，`jmp` 跳转到 OEP |
| `popad; push OEP; ret` | `61 68 xx xx xx xx C3` | 变体：push 目标地址后 ret |

**OEP 计算方法**：以 `jmp rel32`（E9 指令）为例：
- OEP = jmp_下一条指令地址 + rel32（有符号 32 位偏移）
- 即 OEP = (jmp_地址 + 5) + int32(偏移字节)

#### x86_64 (64-bit)

| 模式 | 字节序列 | 说明 |
|------|---------|------|
| `pop rXX; ... ; jmp rXX` | `5E`/`5F` + ... + `FF E6`/`FF E7` | 恢复寄存器后间接跳转 |
| `lea rax, [rip+off]; jmp rax` | `48 8D 05 xx xx xx xx FF E0` | RIP-relative 跳转 |

**OEP 计算方法**：同 x86 的 `jmp rel32`（E9 指令），RIP-relative 的 `lea` 计算类似。

#### ARM64 (AArch64)

| 模式 | 指令 | 说明 |
|------|------|------|
| 恢复寄存器 + `ret` | `ldp x29, x30, [sp], #N; ret` | 从栈恢复 FP/LR 后返回，LR 即 OEP |
| 恢复寄存器 + `br` | `ldr x0, [sp, #off]; br x0` | 从栈加载 OEP 到寄存器后间接跳转 |
| `adr` + `br` | `adr x0, #off; br x0` | 短距离 PC-relative 跳转（±1MB） |
| `adrp` + `add` + `br` | `adrp x0, #page; add x0, x0, #off; br x0` | 长距离 PC-relative 跳转（±4GB），比 `adr` 更常见 |

#### 通用定位技巧

1. **从 entry_points 获取 stub 起始地址和 architecture 字段**，根据架构选择对应的 OEP 模式表
2. 用 `read_data`（bytes 模式，`IDA_READ_SIZE` 设为 256~512）读取 stub 尾部（最后 256-512 字节）
3. **搜索特征字节序列**（上表中的模式）
4. **验证 OEP 合理性**：OEP 应在可执行段内（通常在代码段的起始区域），不应在壳的解压数据段内。如果所有候选 OEP 均不合理，视为"找不到 OEP"，进入阶段 3

### 策略 2.5.2：搜索目标特征字符串

目标程序的功能性字符串（如 crackme 的"Failed"、"Enter your name"、错误提示）在解壳后必然出现在内存中。

**步骤**：
1. 从用户描述中提取目标程序的特征信息（UI 文本、错误消息、API 调用）
2. 用 `read_data`（bytes 模式，较大 `IDA_READ_SIZE`）在目标代码段搜索这些字符串
3. 找到后通过交叉引用或上下文定位关键逻辑

**注意**：此策略在加壳版本上可能搜不到（字符串被压缩），但在动态 dump 后的二进制上有效。

### 策略 2.5.3：动态 dump

定位 OEP 后，使用动态方法 dump 解壳后的内存（详见阶段 3.5a/3.5b）：

1. **首选 IDA 调试器 dump**（阶段 3.5a）
2. **IDA 调试器失败**（反调试 / 无法启动 / 超时）→ 尝试 Frida（阶段 3.5b）
3. **Frida 也失败**（未安装 / 非 PE 格式 / 反 Frida）→ 回退到阶段 3（静态分析）

## 阶段 3：静态分析脱壳（后备方案：动态方法失败时）

当阶段 2.5 的关键点绕过和阶段 3.5a/3.5b 的动态 dump 均失败时（反调试壳、嵌入式固件、无法运行），回退到静态分析。

仅在以下场景使用此阶段：
- 二进制无法运行（嵌入式固件、缺失依赖）
- 壳有强反调试（检测 Frida / 调试器后拒绝解壳）
- 用户明确要求分析壳的实现算法

⚠ 此阶段耗时较长，容易消耗大量 context。仅在确实无法绕过时使用。

### 步骤 3.1：分析解壳 stub

`decompile` 入口点函数（即解壳 stub），从反编译结果中识别：
- **解压/解密循环**：循环体 + 循环次数/终止条件
- **数据源地址**：被加壳数据存放的起始地址和长度
- **数据目标地址**：解壳后数据写入的起始地址
- **OEP（原始入口点）**：存储位置和恢复方式
- **变换算法**：XOR、ADD/SUB、位运算组合、LZMA、aPLib 等

如果反编译失败或结果不可读，回退到 `disassemble`。

### 步骤 3.2：提取数据布局

`segments` 获取段布局确定加壳数据段，`read_data`（bytes 模式）采样加壳数据区验证对算法的理解。

### 步骤 3.3：生成脱壳机

基于步骤 3.1-3.2 的分析结果，生成独立 Python 脱壳机脚本（不依赖 IDAPython，可在任意环境运行）：

```python
#!/usr/bin/env python3
"""脱壳机: <二进制文件名> — <壳类型或"自定义壳">

基于静态分析结果自动生成。
入口点: 0xXXXX（解壳 stub）
原始入口点: 0xXXXX（OEP）
解壳算法: <一句话描述>
"""

import struct
import sys

INPUT_FILE = sys.argv[1] if len(sys.argv) > 1 else "<原始文件名>"
OUTPUT_FILE = sys.argv[2] if len(sys.argv) > 2 else INPUT_FILE + ".unpacked"

def unpack(input_path, output_path):
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    # === 解壳算法（根据静态分析结果填写） ===
    # 示例: XOR 解密
    # for i in range(start_offset, end_offset):
    #     data[i] ^= key

    with open(output_path, "wb") as f:
        f.write(data)
    print(f"[+] 脱壳完成: {output_path}")

if __name__ == "__main__":
    unpack(INPUT_FILE, OUTPUT_FILE)
```

脱壳机脚本写入 `$TASK_DIR/unpacker.py`。

### 步骤 3.4：执行与验证

执行 `python3 "$TASK_DIR/unpacker.py" "<原始二进制文件>" "$TASK_DIR/<文件名>_unpacked"`，然后 `file` 和 `ls -la` 验证输出。

验证标准：
- 输出文件存在且非空
- `file` 命令显示合法可执行文件格式
- 文件大小应与原始加壳文件不同（通常更大）

**如果脱壳失败**（输出文件损坏或格式不对）：
- 分析失败原因（算法理解错误？偏移计算错误？）
- 尝试修正脱壳机脚本后重试（最多 2 次）
- 2 次仍失败 → 切换到动态 dump（阶段 3.5a/3.5b）

## 脱壳策略决策树

```
检测到加壳
  ├── 已知壳（UPX/ASPack 等）→ 阶段 2：自动脱壳工具
  │     ├── 成功 → 脱壳后后续流程
  │     └── 失败 → 阶段 2.5
  ├── 未知壳 → 阶段 2.5：关键点绕过
  │     ├── 找到 OEP → 动态 dump
  │     │     ├── 阶段 3.5a: IDA 调试器 dump（首选）
  │     │     │     ├── 成功 → 脱壳后后续流程
  │     │     │     └── 失败（反调试/无法启动）→ 阶段 3.5b
  │     │     ├── 阶段 3.5b: Frida dump（后备）
  │     │     │     ├── 成功 → 脱壳后后续流程
  │     │     │     └── 失败 → 阶段 3
  │     └── 找不到 OEP → 阶段 3：静态分析脱壳
  └── 阶段 3 失败 2 次 → 告知用户限制
```

**规则**：
1. 优先使用关键点绕过（阶段 2.5）而非静态逆向解壳算法（阶段 3）
2. 阶段 3 仅在以下场景使用：动态方法失败（反调试、无法运行）、二进制不能运行（嵌入式固件）、用户明确要求分析壳的实现
3. 禁止在阶段 3 上花费超过 30 分钟（即使重试次数未达上限）
4. 禁止在同一个失败方向上重试超过 2 次

## 阶段 3.5a：IDA 调试器 dump（首选）

**前置条件**：无额外依赖（IDA 自带）

使用 IDA 内置调试器运行到 OEP 并 dump 内存。详见 `dynamic-analysis.md` 中"脱壳场景：debug_dump.py"。

**优势**：零额外依赖；dump 后数据在 IDA 内；不被反 Frida 检测

**使用 debug_dump.py**：
```bash
IDA_OEP_ADDR=<OEP地址> IDA_OUTPUT="$TASK_DIR/<文件名>_unpacked" \
  "$IDAT" -A -S"$SCRIPTS_DIR/scripts/debug_dump.py" \
  -L"$TASK_DIR/debug_dump.log" "<目标文件>.i64"
```

**验证输出**：
- 输出文件存在且非空
- `file` 命令显示合法可执行文件格式

**注意**：输出的 PE 不含 IAT 重建，仅用于 IDA 加载分析。

## 阶段 3.5b：Frida 进程 dump（后备）

**前置条件**：`pip install frida frida-tools`

IDA 调试器失败时使用 Frida。详见 `dynamic-analysis-frida.md`。

项目内置 Frida PE 脱壳脚本：`disassembler/frida_unpack.py`
```bash
python disassembler/frida_unpack.py <目标二进制> -o "$TASK_DIR/<文件名>_unpacked" -w 30
```

## 常见解壳模式参考

| 模式 | 识别特征 | 脱壳方法 |
|------|---------|---------|
| 单/多字节 XOR | `data[i] ^= key` 或滚动 key | 找到 key 和范围，逆异或 |
| ADD/SUB | `data[i] += N` 或 `-= N` | 反向操作 |
| ROL/ROR | 位旋转 | 反向旋转 |
| LZMA/zlib | 调用 `decompress` 或内嵌解压 | Python `lzma`/`zlib` 库 |
| aPLib | 小体积压缩库 | `aplib` Python 库或手动实现 |
| 分块解密 | 按固定块大小处理，每块不同 key | 找到块大小和 key 生成逻辑 |
| 导入表重建 | `LoadLibrary`/`GetProcAddress` 调用序列 | 解析解壳后的 IAT 区域 |

## 脱壳后后续流程

脱壳成功后（无论阶段 2/2.5/3/3.5a/3.5b），将解壳产物加载到 IDA 自动分析：

1. 用 idat 加载解壳产物：
   ```bash
   "$IDAT" -A -S"$SCRIPTS_DIR/query.py" -L"$TASK_DIR/load.log" "$TASK_DIR/<脱壳产物文件名>"
   ```
2. 加载成功后，用 `query.py` 的全部分析能力（`decompile`/`strings`/`xrefs`/`functions` 等）分析解壳后的二进制
3. 后续分析流程与非加壳二进制相同
4. 脱壳机/dump 脚本保留在 `$TASK_DIR/`，用户可复用

## 禁止操作（加壳版本上）

| 操作 | 状态 | 原因 |
|------|------|------|
| `functions` | 禁止 | 加壳后函数识别不完整 |
| `func_info` | 禁止 | 同上 |
| `strings` | 禁止 | 加壳后字符串被加密/压缩 |
| `xrefs_to` / `xrefs_from` | 禁止 | 交叉引用基于函数识别，不可靠 |
| `update.py`（任何操作） | 禁止 | 修改加壳版本无意义 |
| `decompile`（解壳 stub） | **允许** | 分析解壳算法所必需 |
| `disassemble`（解壳 stub） | **允许** | 反编译不可读时的回退 |
| `read_data`（加壳数据区） | **允许** | 验证对算法的理解 |
| `segments` | **允许** | 确定数据布局 |
