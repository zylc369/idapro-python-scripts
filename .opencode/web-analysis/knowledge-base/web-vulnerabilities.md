# Web 漏洞模式速查

> 本文档为 web-analysis Agent 的漏洞模式参考。每个漏洞类型包含：识别方法、利用思路、关键检查点。
> 不依赖主 prompt 上下文即可理解。

---

## 1. 注入类

### 1.1 XSS（跨站脚本攻击）

**本质**：用户输入被浏览器当作代码执行。

**类型**：
| 类型 | 注入位置 | 触发方式 |
|------|---------|---------|
| 反射型 | URL 参数 → 响应 HTML | 用户点击恶意链接 |
| 存储型 | 用户输入存入数据库 → 其他用户页面 | 任何人访问被注入的页面 |
| DOM 型 | JS 从 URL/输入读取 → 写入 DOM | 用户点击恶意链接 |

**识别方法**：
1. 找反射点：用户输入是否出现在响应 HTML 中？
2. 检查转义：`<` → `&lt;`？`"` → `&quot;`？
3. 检查上下文：在 HTML 标签内？属性内？JS 字符串内？URL 内？
4. 检查 CSP：响应头 `Content-Security-Policy` 是否阻止 inline script？
5. 检查 nonce/hash：`<script nonce="xxx">` 是否必须？

**利用思路**：
- HTML 标签内：`<script>alert(1)</script>`
- 属性内：`" onmouseover="alert(1)" `
- JS 字符串内：`';alert(1);//`
- URL 内：`javascript:alert(1)`
- 绕过 CSP：找允许的 script src 域 / JSONP 端点 / base 标签劫持

**关键检查点**：
- nonce 机制是否可预测/绕过？
- 输入是否经过多个处理层？每一层可能引入不同的转义行为
- 响应的 Content-Type 是否正确？（`text/html` 浏览器才解析）

### 1.2 SQL 注入

**本质**：用户输入被拼入 SQL 查询。

**识别方法**：
1. 输入点在查询参数/POST 表单
2. 输入特殊字符（`'` / `"` / `;`）观察错误/行为变化
3. 布尔盲注：`' AND 1=1--` vs `' AND 1=2--` 看响应差异
4. 时间盲注：`' AND SLEEP(5)--` 看响应延迟

**利用思路**：
- UNION 注入：`' UNION SELECT password FROM users--`
- 堆叠注入：`'; DROP TABLE users--`
- 盲注：逐字符提取数据
- ORM 注入：利用 ORM 的 raw query / 排序参数

### 1.3 SSRF（服务端请求伪造）

**本质**：让服务器发起请求到攻击者指定的地址。

**识别方法**：
1. 功能点：URL 预览、图片加载、Webhook、文件导入
2. 参数值是 URL 或主机名
3. 测试：`http://127.0.0.1` / `http://localhost` / `http://内网IP`

**利用思路**：
- 访问内网服务（元数据 API / 管理面板）
- 读取本地文件（`file:///etc/passwd`）
- 绕过：IP 进制转换 / DNS Rebinding / URL 解析差异

### 1.4 CRLF 注入 / HTTP 头注入

**本质**：用户输入包含 `\r\n`，注入额外的 HTTP 头或响应体。

**识别方法**：
1. 用户输入出现在响应头中（重定向 URL / Set-Cookie / 自定义头）
2. 测试 `%0d%0a`（`\r\n`）是否能注入新头

**利用思路**：
- 注入 `Set-Cookie` 头
- 注入额外的响应头（CSP / CORS）
- HTTP 请求走私（配合反向代理差异）

---

## 2. 认证/会话类

### 2.1 Cookie 安全

**关键属性检查**：
| 属性 | 作用 | 缺失风险 |
|------|------|---------|
| `HttpOnly` | JS 无法读取 | XSS 可窃取 Cookie |
| `Secure` | 仅 HTTPS 传输 | 中间人可截获 |
| `SameSite` | 跨站请求限制 | CSRF 攻击 |
| `Path` | Cookie 作用路径 | 路径越宽越危险 |
| `Domain` | Cookie 作用域名 | 域名越宽越危险 |

**利用思路**：
- `httpOnly: false` → XSS 可读 Cookie（`document.cookie`）
- `SameSite=None` → 跨站请求带 Cookie（CSRF + 缓存投毒）
- `Path=/` → 所有路径都能访问

### 2.2 JWT（JSON Web Token）

**识别方法**：
1. 认证 Token 格式为 `xxx.yyy.zzz`（Base64 编码的三段）
2. 解码第一段看 `alg` 字段

**常见漏洞**：
| 漏洞 | 检测方法 |
|------|---------|
| `alg: none` | 修改 alg 为 none，删除签名，看是否通过 |
| 弱密钥 | 用 jwt-tool / hashcat 暴力破解密钥 |
| RS256→HS256 混淆 | 用公钥作为 HMAC 密钥签名 |
| kid 注入 | kid 参数注入路径遍历 |

### 2.3 CORS（跨域资源共享）

**识别方法**：
1. 发送 `Origin: https://evil.com` 头
2. 检查响应中 `Access-Control-Allow-Origin` 是否反射
3. 检查 `Access-Control-Allow-Credentials: true`

**利用思路**：
- `ACAO: *` + `ACAC: true` → 任意域读取数据（浏览器实际阻止这种组合）
- `ACAO: https://evil.com` + `ACAC: true` → evil.com 可读取用户数据
- `null` Origin → iframe sandbox 可触发

---

## 3. 缓存类

> 详细分析见 `$AGENT_DIR/knowledge-base/cache-poisoning.md`。

### 3.1 Web Cache Poisoning（缓存投毒）

**核心问题**：攻击者的输入被缓存，其他用户收到被投毒的响应。

**关键检查**：
1. 是否有缓存？（X-Cache 头 / 响应时间差异）
2. 缓存键包含什么？（URL / Host / Vary 头）
3. 攻击者能控制键外的内容吗？（未键入的输入被缓存）

### 3.2 Web Cache Deception（缓存欺骗）

**核心问题**：缓存把包含敏感数据的响应当作静态资源缓存。

**关键检查**：
1. 路径混淆：`/api/user-data/xxx.css` → 缓存认为是 CSS，服务器返回用户数据
2. 缓存规则：只看路径后缀？还是看 Content-Type？

---

## 4. 文件类

### 4.1 LFI/RFI（本地/远程文件包含）

**识别方法**：
1. 参数包含文件路径（`?page=about` / `?file=download`）
2. 测试路径遍历：`../../etc/passwd`

**利用思路**：
- 读取敏感文件（配置/日志/源码）
- 日志注入：在 User-Agent 中注入 PHP 代码，然后包含日志文件
- PHP 协议：`php://filter/convert.base64-encode/resource=index.php`

### 4.2 文件上传

**识别方法**：
1. 文件上传功能点
2. 检查：文件类型限制？文件名处理？存储路径？

**利用思路**：
- 双扩展名：`shell.php.jpg`
- MIME 类型欺骗：修改 Content-Type
- 路径遍历：`../../../var/www/html/shell.php`
- 竞争条件：上传→快速访问→利用

---

## 5. 逻辑类

### 5.1 IDOR（不安全的直接对象引用）

**识别方法**：
1. URL/API 中有 ID 参数（`/api/user/123`）
2. 修改 ID 看能否访问其他用户的数据

**利用思路**：
- 枚举 ID（数字/UUID）
- 批量请求
- 批量 ID 修改

### 5.2 条件竞争

**识别方法**：
1. 功能涉及：余额检查→扣款 / 库存检查→下单 / 优惠券使用
2. 多次并发请求同一操作

**利用思路**：
- 用 Burp Intruder / Python 并发请求
- 时间窗口内的双重使用
- TOCTOU（检查时间/使用时间不一致）

---

## 6. 反向代理/基础设施类

### 6.1 HTTP 请求走私

**本质**：前端代理和后端服务器对请求边界的解析不一致。

**类型**：
| 类型 | 方式 |
|------|------|
| CL.CL | 两个 Content-Length |
| CL.TE | Content-Length + Transfer-Encoding |
| TE.CL | Transfer-Encoding + Content-Length |
| TE.TE | 两个 Transfer-Encoding（混淆） |

**检测方法**：发送精心构造的请求，观察响应延迟/内容差异。

### 6.2 Host 头攻击

**识别方法**：
1. 修改 Host 头看服务器如何使用
2. 检查：密码重置链接 / 缓存键 / 虚拟主机路由

**利用思路**：
- 密码重置链接中毒
- 缓存投毒（Host 是缓存键的一部分）
- SSRF（Host 被用于反向代理上游请求）
