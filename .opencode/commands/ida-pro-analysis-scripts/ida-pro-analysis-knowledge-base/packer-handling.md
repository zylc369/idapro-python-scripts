# 加壳/混淆二进制处理策略

> 本文档由 `ida-pro-analysis-evolve` 从主 prompt 提取。AI 编排器在检测到加壳时通过 Read 工具按需加载。

## 触发条件

`packer_detect` 返回 `packer_detected: true`，或 `segments` 返回 `packer_warning.detected: true`。

以下流程**仅在检测到加壳时激活**，非加壳场景不走此分支。

## 阶段 1：壳检测

首次分析新二进制时，在 `entry_points` 查询后立即调用 `packer_detect`。

## 阶段 2：已知壳自动脱壳

检测到已知壳名（`packer_name` 不为 null 且不为 "unknown"）时：

1. 检查系统是否安装对应脱壳工具（`which upx` 等）
2. **已安装** → 执行脱壳（输出到 `$TASK_DIR`，不覆盖原文件），如 `upx -d "<原始文件>" -o "$TASK_DIR/<文件名>_unpacked"`
3. **未安装** → 告知用户安装命令（如 `brew install upx`），然后进入阶段 3

脱壳成功后 → 用 `file` 命令验证输出文件类型 → 跳到"脱壳后后续流程"。

## 阶段 3：静态分析脱壳（自定义壳 / 无脱壳工具）

当没有可用的自动脱壳工具时，通过静态分析理解解壳算法并生成脱壳机。

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
- 2 次仍失败 → 切换到阶段 3.5（动态脱壳）

## 脱壳策略决策树

静态脱壳 vs 动态脱壳的选择：

```
检测到加壳
  ├── 已知壳（UPX/ASPack 等）→ 阶段 2：自动脱壳工具
  ├── 未知壳 → 阶段 3：先尝试静态脱壳
  │     ├── 成功 → 脱壳后后续流程
  │     └── 失败 2 次 → 阶段 3.5：动态脱壳（Frida dump）
  └── 动态脱壳也失败 → 告知用户限制
```

**规则**：
1. 优先尝试静态脱壳（适合简单变换：XOR/ADD/ROL）
2. 静态脱壳失败 **2 次**后 → 立即切换动态脱壳
3. 禁止在静态脱壳上花费超过 30 分钟
4. 禁止在同一个失败方向上重试超过 2 次

## 阶段 3.5：动态脱壳（Frida 进程 dump）

当静态脱壳失败时，使用 Frida 启动目标进程，等待代码解壳后 dump 内存。

### 使用 frida_unpack.py

项目内置通用 Frida PE 脱壳脚本：`disassembler/frida_unpack.py`

```bash
python disassembler/frida_unpack.py <目标二进制> -o "$TASK_DIR/<文件名>_unpacked" -w 30
```

脚本会自动：spawn 进程 → resume → 监控代码段写入 → 检测写入稳定后 dump → 重建 PE 文件。

### 前置条件

- 需要 frida：`pip install frida frida-tools`
- 如果 frida 未安装，脚本会提示安装命令并退出。此时回退到静态脱壳并告知用户限制
- 支持 32-bit 和 64-bit PE（自动检测 PE32/PE32+ 格式）
- 当前仅支持 EXE（DLL 需宿主进程，不在自动处理范围内）

### 验证输出

- `file "$TASK_DIR/<文件名>_unpacked"` 检查是否为合法可执行文件
- 输出文件应比原始文件不同（通常更大或段内容变化）
- 如果输出 `.bin` 文件（PE 重建不完整），可以尝试直接用 idat 加载 `.bin` 文件

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

脱壳成功后（无论阶段 2/3/3.5），将解壳产物加载到 IDA 自动分析：

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
