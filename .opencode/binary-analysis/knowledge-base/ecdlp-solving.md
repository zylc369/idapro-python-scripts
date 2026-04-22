# ECDLP 求解经验

> AI 编排器在遇到椭圆曲线离散对数问题 (ECDLP) 时按需加载。

## 触发条件

- 反编译代码中出现椭圆曲线点加/点乘运算
- 曲线阶 n 为已知素数
- 需要由公钥点反推私钥（或由部分信息反推标量）

---

## 算法选择

| 曲线位数 | 算法 | 预估耗时 | 内存 |
|---------|------|---------|------|
| ≤ 32 bit | 暴力枚举 | < 1s (C) | 极低 |
| 33-64 bit | Pollard's rho | 分钟-小时级 (C) | 极低 |
| 33-64 bit | Baby-step Giant-step | 分钟级 (C) | O(√n) |
| > 64 bit | Pollard's rho | 天-年级 | 极低 |
| > 128 bit | **不可行** | 理论上不可能 | — |

**首选**: Pollard's rho（低内存、可并行、实现简单）

---

## 强制规则

> **64-bit 以上曲线的 ECDLP → 必须用 C/C++ 实现**

Python Pollard's rho ~0.8M 步/s/core，C ~50M 步/s/core，差距 60x。
64-bit 曲线需要 ~2^32 步，Python 需要 ~90 分钟，C 需要 ~1.5 分钟。

### `__umul128` vs `uint128_t` (MSVC)

MSVC 不支持 `__int128`，替代方案：

| 方案 | 实现 | 性能 |
|------|------|------|
| `__umul128` + `_umul128` | intrinsics，需要 `<intrin.h>` | **最优** — 编译器直接生成 `mul` 指令 |
| `unsigned __int128` | GCC/Clang 原生支持 | **等价** — 同样生成单条 `mul` 指令 |
| 手写 64x64→128 拆分 | 用 32-bit 半字乘法模拟 | 慢 ~2-4x |

**MSVC 下推荐**：`#include <intrin.h>` 使用 `__umul128(a, b, &hi)`，性能与 GCC `__int128` 等价。

---

## 性能基准

| 实现 | 速度 | 适用场景 |
|------|------|---------|
| Python (纯) | ~0.1M 步/s/core | 仅用于 32-bit 以下曲线 |
| Python + gmpy2 | ~0.8M 步/s/core | 48-bit 以下曲线的原型验证 |
| C + 128-bit 整数 | ~50M 步/s/core | 64-bit 曲线的生产求解 |
| C + GMP | ~40M 步/s/core | 任意位数（但 GMP 开销略大） |

---

## Pollard's rho 算法模板

### Python 原型（用于验证正确性）

```python
def pollard_rho(G, n, target_x, curve_add, curve_mul):
    """Pollard's rho 求解 ECDLP: 找 k 使得 (k*G).x mod n == target_x"""
    from random import randint

    def step(P, a, b):
        partition = P[0] % 3
        if partition == 0:
            return curve_add(P, G), (a + 1) % n, b
        elif partition == 1:
            return curve_double(P), (2 * a) % n, (2 * b) % n
        else:
            return curve_add(P, target_point), a, (b + 1) % n

    tortoise = (curve_mul(randint(1, n-1), G), 0, 0)
    hare = step(*step(*tortoise))

    while tortoise[0] != hare[0]:
        tortoise = step(*tortoise)
        hare = step(*step(*hare))

    # 恢复 k
    # ...
```

### C 模板（生产用）

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// 128-bit 整数运算（用于 64-bit 素数域）
typedef unsigned __int128 uint128_t;

typedef struct {
    uint64_t x;
    uint64_t y;
} Point;

typedef struct {
    uint64_t x;
    uint64_t y;
    uint64_t a_coeff;
    uint64_t p;
} Curve;

// 模加
static inline uint64_t mod_add(uint64_t a, uint64_t b, uint64_t p) {
    uint128_t s = (uint128_t)a + b;
    return s >= p ? (uint64_t)(s - p) : (uint64_t)s;
}

// 模乘
static inline uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t p) {
    return (uint128_t)a * b % p;
}

// 模逆（费马小定理）
static inline uint64_t mod_inv(uint64_t a, uint64_t p) {
    // a^(p-2) mod p — 用快速幂
    uint64_t result = 1, base = a, exp = p - 2;
    while (exp > 0) {
        if (exp & 1) result = mod_mul(result, base, p);
        base = mod_mul(base, base, p);
        exp >>= 1;
    }
    return result;
}

// 点加（省略细节，按具体曲线实现）
Point point_add(Point P, Point Q, Curve *c);
Point point_double(Point P, Curve *c);
Point point_mul(uint64_t k, Point P, Curve *c);

int main(int argc, char *argv[]) {
    // 初始化曲线参数
    // 运行 Pollard's rho
    // 输出结果到 stdout
    return 0;
}
```

---

## 渐进策略

1. **Python 原型**（~30 分钟）
   - 用 gmpy2 实现曲线运算
   - 用小曲线（已知答案）验证正确性
   - 用目标曲线测试几步，确认算法无误

2. **性能估算**（~5 分钟）
   - Python 跑 1000 步计时
   - 估算总步数 = √n
   - 如果 Python 需要超过 30 分钟 → 转 C

3. **C 实现**（~60 分钟）
   - 复制 Python 的曲线参数
   - 用 128-bit 整数或 GMP 实现模运算
   - 编译优化：`/O2` (MSVC) 或 `-O2` (gcc/clang)
   - 通过 subprocess 从 Python 调用

4. **验证**（~10 分钟）
   - C 输出与 Python 原型（小规模）一致
   - 用 Unicorn 模拟原二进制的验证函数确认结果

---

## 常见陷阱

| 陷阱 | 说明 |
|------|------|
| 忘记 mod n vs mod p | 曲线坐标 mod p，标量运算 mod n，混淆会导致完全错误的结果 |
| 点在曲线上检查 | 每次点运算后检查结果是否在曲线上，帮助发现计算错误 |
| 无穷远点处理 | 点加时两个相同点需要用 point_double 而非 point_add |
| 字节序 | 二进制中的大整数可能是大端序，需要转换 |
| 素性检查 | 曲线参数 n 必须是素数，否则 Pollard's rho 不适用 |
