# 常见密码学验证模式

> 本文档由 `ida-pro-analysis-evolve` 生成。AI 编排器在检测到密码学算法特征时通过 Read 工具按需加载。

## 触发条件

反编译/反汇编代码中出现以下特征时加载本文档：
- MD5 初始化常量：`0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`
- RSA 指数：`65537`（`0x10001`）
- 256 字节 S-box 初始化 + i/j 双指针交换（RC4）
- Base64 字母表：`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
- Hex 查找表：`0123456789ABCDEF`

---

## MD5 + 比较

### 识别特征

- 4 个初始化常量：`0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`
- 64 个轮常量（T table）
- 4 轮变换，每轮 16 步

### 常见变体

| 变体 | 说明 | 逆向注意 |
|------|------|---------|
| 比较全部 16 字节 | `memcmp(md5, expected, 16)` | 需要完整的 MD5 碰撞 |
| 比较前 8 字节 | `memcmp(md5, expected, 8)` | 只需要匹配前半部分 |
| 比较后 8 字节 | 比较偏移 8 处 | 注意 MD5 context 中 digest 的位置 |
| 转为 hex 字符串再比较 | 每字节 → 2 hex 字符，共 32 字符 | 需要 hex 编码后再比对 |
| 分开使用前后半 | 前 8 字节用于一个检查，后 8 字节用于另一个 | 分别分析两个检查的逻辑 |

### MD5 Context 结构

标准 MD5 context 内存布局：

```
offset 0:   state[4]     — 4 个 uint32（16 字节）
offset 16:  count[2]     — 2 个 uint32（8 字节，位计数）
offset 24:  buffer[64]   — 64 字节输入缓冲区
offset 88:  digest[16]   — MD5_Final 后的 16 字节摘要
```

**关键**：`MD5_Final` 将最终的 16 字节摘要写入 context 结构的某个偏移。不同实现的偏移可能不同，但最常见的布局是 digest 在 offset 88 处。分析时需要确认具体实现的偏移。

### 逆向策略

1. 确认 MD5 的输入（哪个字符串/数据被哈希）
2. 确认 MD5 的输出用在哪里（全部 16 字节？前 8？后 8？转 hex？）
3. 确认比较目标（硬编码值？动态计算值？）

---

## RSA 签名验证

### 识别特征

- 常量 `65537`（`0x10001`）— 最常见的公钥指数
- 大数运算（多字整数乘法、模幂）
- `modpow` 函数：`base^exp mod n`
- 十进制/十六进制大数字符串（模数 n）

### 常见变体

| 变体 | 公式 | 逆向策略 |
|------|------|---------|
| 公钥验证（最常见） | `sig^e mod n == expected` | 找到 n → 分解 n → 计算 d → 伪造 sig = `expected^d mod n` |
| 私钥签名 | `msg^d mod n` | 找到 n、d（通常硬编码或可从 p、q 推导） |
| 数字字符串签名 | `BigInt(digits)^e mod n` | digits 是十进制字符串形式的大整数 |

### 逆向步骤

1. 找到模数 n（通常是十六进制字符串或大端字节序列）
2. 分解 n → 得到 p、q（用 `factordb.com` 或 Python `sympy.factorint`）
3. 计算 `d = pow(e, -1, (p-1)*(q-1))`
4. 计算签名 `sig = pow(target, d, n)`
5. 验证：`pow(sig, e, n) == target`

### 注意事项

- 消息必须 `< n`，否则无法签名
- 大数在内存中可能以字符串形式存储（十进制或十六进制）
- 模幂函数可能使用 Montgomery 约化等优化算法

---

## RC4

### 识别特征

- **KSA（Key Scheduling Algorithm）**：256 字节 S-box 初始化 + 两指针交换
- **PRGA（Pseudo-Random Generation Algorithm）**：i/j 双指针递增 + 交换 + XOR

### 伪代码

```python
# KSA
S = list(range(256))
j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) % 256
    S[i], S[j] = S[j], S[i]

# PRGA（生成密钥流并 XOR）
i = j = 0
for byte in data:
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    k = S[(S[i] + S[j]) % 256]
    output.append(byte ^ k)
```

### 关键特性

- **对称**：加密 = 解密（同一密钥，同一算法）
- **密钥长度可变**：1-256 字节
- **无独立 IV**：每次用同一密钥加密同一明文，密文相同

### 逆向策略

1. 找到 RC4 密钥（通常是硬编码的字节数组）
2. 找到被加密/解密的数据（通常是 serial 的一部分）
3. 用相同密钥重新加密/解密即可

---

## Base64 编解码

### 识别特征

- 字母表字符串：`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
- 4 字符 → 3 字节映射
- `=` 填充字符（0x3D）

### 编解码查找表函数

通常对输入字符做范围判断：

```c
if (c >= 'A' && c <= 'Z') return c - 'A';       // 0-25
if (c >= 'a' && c <= 'z') return c - 'a' + 26;  // 26-51
if (c >= '0' && c <= '9') return c - '0' + 52;  // 52-61
if (c == '+') return 62;
if (c == '/') return 63;
```

### 逆向注意

- Base64 常用于编码 Serial（将二进制数据转为可输入的 ASCII 字符串）
- 解码后得到的二进制数据通常包含加密密文 + 数字签名等
- 检查解码后的数据长度是否是 3 的倍数（近似）

---

## Hex 编解码

### 识别特征

- 查找表字符串：`0123456789ABCDEF`（或小写 `0123456789abcdef`）
- 每个字节拆为高 4 位和低 4 位（nibble），分别查表

### 编码过程

```c
output[0] = hex_table[(byte >> 4) & 0xF];  // 高 nibble
output[1] = hex_table[byte & 0xF];          // 低 nibble
```

### 常见用途

- 将二进制数据（如 MD5 hash）转为可比较的 hex 字符串
- 将 hex 字符串转为大整数（用于 RSA 比较）

---

## 组合模式

### 最常见组合

```
Base64Decode(Serial)
  → 前 N 字节：RC4 解密 → 与 MD5(Name) 的某部分比较
  → 后续字节：十进制数字字符串 → BigInt(digits)^e mod n == BigIntFromHex(MD5(Name)的另一部分)
```

### 识别策略

1. **从字符串反推**：在二进制中找到 Base64 字母表 → 找到引用它的函数 → 确认为 Base64 解码
2. **从常量反推**：找到 MD5 init 常量 → 找到引用它们的函数 → 确认 MD5
3. **从大数运算反推**：找到 `65537` → 找到 modpow → 确认 RSA
4. **从 S-box 反推**：找到 256 字节初始化循环 → 确认 RC4
5. **从 hex 表反推**：找到 `0123456789ABCDEF` → 找到引用 → 确认 hex 编解码

### 数据流追踪

确认各算法之间的数据流向：
- Serial 经过什么编码/解码？
- 中间结果（如 MD5 hash）被如何分割使用？
- 最终比较的是什么？

**关键**：逐字节追踪比较操作，确认比较的两个操作数分别来自哪里。不要假设——从反编译代码中确认每个操作数的来源。
