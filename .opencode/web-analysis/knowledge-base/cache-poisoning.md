# Web Cache Poisoning 专题

> 本文档为 web-analysis Agent 的 Web Cache Poisoning 深度参考。
> 内容沉淀自 CyberGame 2026 `future.js` 题目的完整分析（详见 `docs/解题报告/Web/futurejs-writeup.md`）。
> 不依赖主 prompt 上下文即可理解。

---

## 1. 缓存投毒原理

### 1.1 什么是 Web 缓存？

反向代理（nginx/Cloudflare/Akamai）在用户和源服务器之间缓存响应：

```
用户请求 → 反向代理 → 检查缓存 → 命中(HIT): 返回缓存副本
                                    → 未命中(MISS): 转发到源服务器 → 缓存响应 → 返回给用户
```

### 1.2 缓存投毒的核心问题

**缓存把"只能影响自己的攻击"变成了"能影响其他用户的攻击"。**

```
无缓存:
  攻击者发恶意请求 → 只有攻击者收到恶意响应 → Self-XSS（无意义）

有缓存:
  攻击者发恶意请求 → 缓存存储恶意响应
  其他用户请求同一 URL → 命中缓存 → 收到恶意响应 → 被 XSS！
```

### 1.3 缓存投毒的必要条件

1. **存在缓存机制**：反向代理/CDN 配置了缓存
2. **攻击者能控制响应内容**：通过请求头/参数注入
3. **控制的内容在缓存键之外**（unkeyed）或缓存键可控
4. **缓存响应能命中其他用户**：缓存键匹配
5. **响应被浏览器解析为 HTML**：Content-Type 正确

---

## 2. 缓存键分析

### 2.1 缓存键的组成

缓存键决定了"两个请求是否命中同一缓存条目"：

```
缓存键 = HTTP Method + URL路径 + 查询参数 + Host + Vary头指定的请求头
```

**典型 nginx 缓存键**：
```
proxy_cache_key $scheme$host$request_uri;
# = http + proxy:4000 + /_next/page
```

### 2.2 主键 vs 二级键

| 键类型 | 来源 | 匹配规则 |
|--------|------|---------|
| 主键 | `proxy_cache_key` 指令 | 精确匹配（Method + Host + URL） |
| 二级键 | `Vary` 响应头 | 指定的请求头值必须匹配 |

**Vary 头示例**：
```
Vary: rsc, next-router-state-tree, next-router-prefetch, Accept-Encoding
```
意味着缓存会为 `rsc` + `next-router-state-tree` + `next-router-prefetch` + `Accept-Encoding` 的每个不同组合存储不同的缓存条目。

### 2.3 缓存键分析清单

分析缓存投毒时，逐一回答：

- [ ] 哪些路径被缓存？（看 proxy 配置）
- [ ] 缓存主键包含什么？（Host? Scheme? Query String?）
- [ ] 响应的 Vary 头包含什么？
- [ ] 攻击者能控制哪些请求头？
- [ ] 控制的头在缓存键中吗？
- [ ] 目标用户（Bot/其他用户）的请求头值是什么？
- [ ] 攻击者的缓存键和目标用户的缓存键能匹配吗？

---

## 3. Vary 头绕过

### 3.1 Vary 头的作用

Vary 头告诉缓存："这个响应会根据哪些请求头的值而变化"。

```
Vary: Accept-Encoding
→ 缓存为每种 AE 值存不同副本
→ Accept-Encoding: gzip 和 Accept-Encoding: gzip, deflate 是不同的缓存条目
```

### 3.2 常见绕过方式

| 方式 | 原理 | 条件 |
|------|------|------|
| **空值 vs 缺失** | 框架检查 `!== undefined` vs `=== '1'`，空值通过宽松检查但 Vary 匹配时等同于缺失 | 两个模块对同一头有不同判断 |
| **值标准化差异** | 代理和源服务器对同一头的值解析/标准化方式不同 | 如 AE 排序、空格处理 |
| **未列在 Vary 中的头** | 响应内容受某头影响，但 Vary 未列出该头 | 应用漏洞/配置遗漏 |

### 3.3 空值绕过的经典 case（futurejs）

**问题**：Next.js 框架内部两个文件对 `RSC` 请求头的判断不一致：

```javascript
// base-server.js（请求调度器）— 严格检查
isRSCRequest = req.headers['rsc'] === '1'  // 空字符串 → false

// app-render.js（渲染引擎）— 宽松检查
isRSCRequest = headers['rsc'] !== undefined  // 空字符串 → true
```

**结果**：发送 `RSC: ""`（空字符串）时：
- base-server.js 认为不是 RSC 请求（`"" !== "1"`）
- app-render.js 按 RSC 模式渲染（`"" !== undefined`）
- Vary 头的 `rsc` 字段值为空字符串
- Bot 不发 RSC 头 → Vary 的 `rsc` 字段也为空字符串
- **缓存键匹配**！

---

## 4. 组合利用

### 4.1 缓存投毒 + XSS

最常见的组合利用模式：

```
1. 找到反射点（用户输入出现在响应中）
2. 找到绕过转义的方式（框架渲染差异 / 编码绕过）
3. 确保响应 Content-Type 为 text/html
4. 找到缓存机制（反向代理缓存）
5. 构造缓存键匹配（Host/Vary 头值对齐）
6. 发送投毒请求 → 缓存存储 XSS 响应
7. 其他用户访问 → 命中缓存 → 执行 XSS
```

### 4.2 缓存中缓存（数据渗出）

当目标环境无外网（Docker 隔离）时，XSS 无法外传数据。解法：

```
1. XSS 读取敏感数据（如 document.cookie）
2. XSS 将数据作为请求头发送到同一域名的另一个缓存路径
   fetch('/_next/exfil', {headers: {'x-nonce': 'STOLEN:' + document.cookie}})
3. 数据被写入缓存
4. 攻击者从外部访问该缓存路径 → 读取数据
```

**原理**：缓存只关心"请求/响应"，不关心"数据流向"。攻击者让目标的服务器帮自己"暂存"数据。

---

## 5. 防御措施

### 5.1 缓存配置

| 防御 | 说明 |
|------|------|
| 只缓存静态资源 | 避免缓存动态内容（HTML/API 响应） |
| 缓存键包含所有影响响应的头 | Vary 头必须完整列出所有相关头 |
| 禁用带请求头的缓存 | 不缓存非标准请求头的响应 |

### 5.2 应用层防御

| 防御 | 说明 |
|------|------|
| 输入验证/转义 | 所有用户输入在输出前转义 |
| Content-Type 严格 | 动态响应的 CT 固定，不依赖请求头 |
| CSP 头 | 即使被注入 HTML，CSP 也限制脚本执行 |
| Cookie HttpOnly + Secure | 减轻 XSS 的影响 |

### 5.3 框架层面

| 防御 | 说明 |
|------|------|
| 统一请求头检查逻辑 | 消除同一框架内不同模块的判断差异 |
| Vary 头自动管理 | 框架自动设置正确的 Vary 头 |
| 缓存控制头 | `Cache-Control: private` / `no-store` 防止缓存 |
