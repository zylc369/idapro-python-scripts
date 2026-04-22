# 技术选型决策树

> AI 编排器在需要实现算法、编写求解器、性能敏感计算时按需加载。

## 触发条件

- 需要实现加密/解密算法
- 需要编写暴力搜索或数学求解器
- 涉及大量数据处理或性能敏感计算
- 不确定使用 Python 还是 C/C++ 时

---

## 决策树

### 第一步：判断计算规模

| 估算单次计算耗时 | 预估迭代次数 | 总耗时估算 | 推荐 |
|-----------------|------------|-----------|------|
| < 0.01s | < 1000 | < 10s | Python |
| 0.01s - 1s | > 10000 | > 100s | **C/C++** |
| > 1s | 任意 | 任意 | **C/C++** |
| 不确定 | 未知 | 未知 | Python 原型 → 性能测试 → 必要时转 C |

### 第二步：选择技术

| 场景 | 首选技术 | 原因 | 备选 |
|------|---------|------|------|
| 计算密集型（暴力搜索、ECDLP、大数运算） | C/C++ | 10-100x 性能 | gmpy2 加速的 Python |
| 算法验证（确认加密是否标准实现） | Unicorn 模拟原函数 | 无需重实现 | Hook 读取 |
| 算法逆向（理解自定义变体） | 静态分析 + Hook | 需理解细节 | — |
| 少量计算（构造输入、格式转换） | Python | 够用 | — |
| 性能不确定时 | Python 原型 → 转 C | 渐进策略 | — |
| 需要调试运行时行为 | IDA 调试器 / Frida | 动态分析 | — |
| 大整数运算（密码学） | Python + gmpy2 | 开发快 | C + GMP |

### 第三步：验证选择

选择后回答以下问题：
1. 预估总耗时是否在 10 分钟以内？（是 → 继续；否 → 考虑升级技术栈）
2. 是否可以用 Unicorn 模拟替代手动重实现？（是 → 优先模拟）
3. Python 是否有现成库可用？（是 → 先用库验证，不要手写）

---

## C/C++ 编译流程

### Windows (MSVC)

使用 `detect_env.py` 检测到的 `vcvarsall.bat` 路径：

```bash
# 32 位目标（常见于逆向目标）
cmd /c "call "<vcvarsall_path>" x86 >nul 2>&1 && cl /O2 /Fe:<output.exe> <source.c>"

# 64 位目标
cmd /c "call "<vcvarsall_path>" x64 >nul 2>&1 && cl /O2 /Fe:<output.exe> <source.c>"
```

### Linux

```bash
gcc -O2 -o <output> <source.c> -lgmp   # 需要 GMP 时
gcc -O2 -o <output> <source.c>          # 不需要 GMP
```

### macOS

```bash
clang -O2 -o <output> <source.c>
```

---

## 渐进策略：Python 原型 → C 加速

当性能需求不明确时，推荐以下流程：

1. **Python 原型**：用 Python + gmpy2 快速实现，验证算法正确性
2. **性能测试**：用小规模数据测试，估算实际耗时
3. **判断**：如果 Python 够用（< 10 分钟），就不再优化
4. **转 C**：如果 Python 不够用，将核心循环转为 C，通过 subprocess 调用

### Python 调用 C 的模式

```python
import subprocess
result = subprocess.run(
    ["./solver", str(param1), str(param2)],
    capture_output=True, text=True, timeout=3600
)
output = result.stdout.strip()
```

### C 模板

```c
#include <stdio.h>
#include <stdlib.h>
// 按需添加: #include <gmp.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <param1> <param2>\n", argv[0]);
        return 1;
    }
    // 核心计算逻辑
    // 结果输出到 stdout，方便 Python 捕获
    printf("%llu\n", result);
    return 0;
}
```

---

## 常见误区

| 误区 | 正确做法 |
|------|---------|
| 用 Python 暴力搜索 64-bit 空间 | 必须用 C，Python 需要数百年 |
| 手动重实现标准算法 | 先用 Unicorn 模拟验证，再决定是否需要重实现 |
| 不做性能估算就开始编码 | 先用小规模数据测试，估算总耗时 |
| 纠结于语言选择不做实事 | Python 原型先行，验证正确后再优化 |

---

## 性能基准参考

| 操作 | Python | C/C++ | 加速比 |
|------|--------|-------|--------|
| ECDLP Pollard's rho (64-bit) | ~0.8M 步/s/core | ~50M 步/s/core | ~60x |
| 大数模幂 (1024-bit) | ~1000 次/s (gmpy2) | ~50000 次/s (GMP) | ~50x |
| AES 加密 | ~10 MB/s (pycryptodome) | ~1 GB/s (OpenSSL) | ~100x |
| 简单整数运算 | ~50M 次/s | ~2G 次/s | ~40x |
