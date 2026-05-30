# 移动端 MITM 方案选型指南

> 移动应用流量拦截的方案选择和常见陷阱。适用于：需要拦截/篡改移动应用的 HTTPS 通信。
> 触发条件：分析移动应用的网络通信，需要执行 MITM（中间人攻击）。

---

## 1. 三种 MITM 方案对比

| 方案 | 原理 | 适用场景 | 复杂度 |
|------|------|---------|--------|
| **A: DNS 重定向 + 代理** | 修改 DNS 将目标域名指向代理 IP，代理解密重加密 | 无 SSL pinning 的应用 | 低 |
| **B: SSL bypass + 流量拦截** | Frida Hook 绕过 SSL pinning，同时 Hook read/write 拦截明文 | 有 SSL pinning 的应用 | 高 |
| **C: 系统CA注入** | 将代理 CA 证书安装到系统信任存储，绕过应用层验证 | Root 设备 + 非用户证书感知的应用 | 中 |

---

## 2. 方案选择决策树

```
目标应用是否有 SSL Pinning？
├── 否 → 方案 A（DNS 重定向 + 代理）
│        配置简单，Burp/Charles 即可
│
├── 是 → 应用类型？
│        ├── Flutter 应用 → 方案 B（SSL bypass + 流量拦截）
│        │   Flutter 不走 Java TLS，必须 Hook native 层
│        │   详见 $AGENT_DIR/knowledge-base/flutter-ssl-bypass.md
│        │
│        ├── 标准 Java/Kotlin → 方案 C 或 B
│        │   先尝试方案 C（安装系统 CA）
│        │   如果应用检查用户证书 → 方案 B
│        │
│        └── Unity/其他 Hybrid → 方案 B
│            通常不走 Java TLS，需要 Hook native
│
└── 不确定 → 先尝试方案 A，观察是否报证书错误
             报错 → 有 SSL pinning → 切换到对应方案
```

---

## 3. 核心教训：SSL bypass 与流量重定向的冲突

### 3.1 问题描述

同时使用 **DNS 重定向（iptables）** 和 **SSL bypass（Frida Hook）** 时，两者会冲突：

1. DNS 重定向将流量导向代理 → 应用实际连接的是代理而非真实服务器
2. SSL bypass Hook 的 `TrustBuiltinRoots` / `native peer` 不会被触发
3. 因为 Flutter 的 SSL 握手在 native 层完成，连接对象变了（代理 vs 真实服务器），导致 SSL 上下文不同

### 3.2 正确方案

**如果需要 SSL bypass + 流量拦截，不要使用 DNS 重定向。** 正确做法：

1. **SSL bypass**：Frida Hook 绕过证书验证（应用正常连接真实服务器）
2. **流量拦截**：Hook `read()`/`write()` 系统调用，在明文层拦截
3. **响应篡改**：在 `read()` Hook 中检测到目标内容后，用 `popen("curl ...")` 获取原始响应并替换

```javascript
// 方案 B 的核心思路（伪代码）
Interceptor.attach(read_addr, {
    onEnter: function(args) {
        this.fd = args[0];
        this.buf = args[1];
    },
    onLeave: function(retval) {
        var data = this.buf.readUtf8String(retval.toInt32());
        if (data && data.indexOf("TLS Application Data") !== -1) {
            // TLS 解密后的明文数据
            // 在这里篡改响应
        }
    }
});
```

### 3.3 方案 A（纯代理）适用时

如果应用**没有 SSL pinning**，直接用 DNS 重定向 + 代理（Burp/Charles）更简单：

```bash
# iptables 重定向（Android）
adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination PROXY_IP:PROXY_PORT

# 或使用 adb forward + Burp
adb forward tcp:8080 tcp:8080
# 在应用中配置 HTTP 代理（如果应用支持）
```

---

## 4. 常见失败模式

| 现象 | 原因 | 解决 |
|------|------|------|
| 代理捕获不到流量 | 应用使用固定 IP，不走 DNS | 用 iptables 按目标 IP 重定向 |
| SSL bypass 后仍握手失败 | CA 证书过期或代理证书链不完整 | 更新代理 CA 证书，检查完整链 |
| Hook read() 只看到加密数据 | SSL bypass 未生效或 Hook 时机不对 | 确认 TrustBuiltinRoots 已被成功调用 |
| 篡改后应用崩溃 | 篡改的数据长度变化导致 Content-Length 不匹配 | 篡改后同步更新 Content-Length 头 |
| Frida 崩溃 | Java bridge 不稳定（Flutter 应用） | 用 native popen/fgets 替代 Java bridge，详见 `$SHARED_DIR/knowledge-base/frida-native-shell-tricks.md` |

---

## 5. 与其他知识库的关系

- Flutter SSL bypass 详见 `$AGENT_DIR/knowledge-base/flutter-ssl-bypass.md`
- Frida native shell 技巧详见 `$SHARED_DIR/knowledge-base/frida-native-shell-tricks.md`
- Frida 反检测和设备操作详见 `$AGENT_DIR/knowledge-base/mobile-frida.md`
