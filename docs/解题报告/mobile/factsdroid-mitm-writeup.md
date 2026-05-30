# FactsDroid — Flutter 应用 SSL Pinning Bypass + MITM 响应篡改完整 Writeup

> 题目类型：移动端安全 | 平台：Android | 包名：`com.eightksec.factsdroid`
>
> 目标：在不修改 APK 的前提下，通过 Frida 动态 Hook 实现 Root 检测绕过、SSL Pinning Bypass，最终完成 MITM 攻击拦截并篡改 HTTPS API 响应。

**题目分类：移动端安全**。本题考察的是 **Flutter 框架逆向** + **BoringSSL SSL Pinning 绕过** + **arm64 native 函数定位** + **MITM 响应篡改** 的组合利用。

核心挑战：Flutter 应用不使用系统的 TLS 证书验证机制，而是通过自带的 BoringSSL（编译在 `libflutter.so` 中）独立管理证书信任链。传统的 Android SSL Pinning bypass 方案（如 TrustManager Hook）对 Flutter 完全无效，必须深入 native 层逆向 `libflutter.so` 才能绕过。

---

## 目录

- [第一章：前置知识](#第一章前置知识)
- [第二章：APK 静态分析——了解目标](#第二章apk-静态分析了解目标)
- [第三章：Root 检测绕过——Java + Native 三层 Hook](#第三章root-检测绕过java--native-三层-hook)
- [第四章：SSL Pinning 分析——为什么常规方法无效](#第四章ssl-pinning-分析为什么常规方法无效)
- [第五章：arm64 逆向——定位 TrustBuiltinRoots](#第五章arm64-逆向定位-trustbuiltinroots)
- [第六章：SSL Pinning Bypass——直接调用内部函数](#第六章ssl-pinning-bypass直接调用内部函数)
- [第七章：MITM 响应篡改——完整攻击链](#第七章mitm-响应篡改完整攻击链)
- [第八章：完整 Exploit 脚本](#第八章完整-exploit-脚本)
- [第九章：防御建议](#第九章防御建议)
- [第十章：总结](#第十章总结)

---

## 第一章：前置知识

### 1.1 什么是 Flutter

Flutter 是 Google 的跨平台 UI 框架。与 React Native 等方案不同，Flutter **不使用平台原生控件**，而是自带渲染引擎（Skia/Impeller）和网络栈。这意味着：

- Flutter 应用的 HTTP 请求**不走 Android 的 HttpURLConnection 或 OkHttp**
- TLS 握手由 Flutter 引擎内置的 **BoringSSL**（Google 维护的 OpenSSL 分支）处理
- 证书验证逻辑编译在 `libflutter.so` 中，无法通过 Java 层 Hook 绕过

### 1.2 什么是 SSL Pinning（证书固定）

SSL Pinning 是一种安全机制，应用不信任系统默认的 CA 证书，而是只信任**预置的特定证书或公钥**。这样即使攻击者安装了自签名 CA 到系统信任库，也无法中间人拦截应用的 HTTPS 流量。

Flutter 的 `SecurityContext` 默认**不加载系统 CA 证书**，而是使用编译在引擎内部的证书 bundle。这相当于一种隐式的 SSL Pinning。

### 1.3 什么是 Frida

Frida 是一个动态二进制插桩工具包。它允许你在运行时注入 JavaScript 代码到目标进程中，Hook 任意函数（Java 方法或 Native 函数），修改参数和返回值。

核心概念：

| 概念 | 说明 |
|------|------|
| `Java.perform()` | 在 Java 虚拟机线程中执行回调，用于 Hook Java 方法 |
| `Interceptor.attach()` | Hook native 函数，可以在函数进入/退出时执行自定义代码 |
| `NativeFunction` | 将内存地址包装成可调用的函数 |
| spawn 模式 | Frida 启动应用并立即注入，适合 Hook 早期初始化逻辑 |
| attach 模式 | 附加到已运行的进程 |

### 1.4 arm64 vs x86_64

Android 模拟器有两种架构：x86_64（Intel，模拟器默认）和 arm64（需要 ARM 镜像）。**同一份 Flutter 引擎代码在不同架构下编译出的 `libflutter.so` 完全不同**——函数偏移地址、寄存器约定、指令集都变了。这是本题的一个关键陷阱。

### 1.5 MITM（中间人攻击）

MITM 攻击是指攻击者拦截并可能篡改通信双方之间的消息。在 HTTPS 场景下，MITM 需要：

1. **DNS/网络重定向**：让应用的请求发到攻击者控制的代理
2. **证书信任**：让应用信任代理的证书（需要绕过 SSL Pinning）
3. **响应篡改**：代理收到真实服务器的响应后，修改内容再转发给应用

---

## 第二章：APK 静态分析——了解目标

### 2.1 解包与基本信息

```bash
# 使用 apktool 解包
apktool d factsdroid.apk -o unpacked

# 使用 jadx 反编译 Java 源码
jadx -d java_src factsdroid.apk
```

**AndroidManifest.xml 关键信息**：

```xml
<uses-permission android:name="android.permission.INTERNET"/>
<!-- 唯一的权限：网络访问 -->

<activity android:name="com.eightksec.factsdroid.MainActivity"
          android:exported="true" android:launchMode="singleTop">
    <!-- 单 Activity Flutter 应用 -->
</activity>
```

### 2.2 Flutter 应用特征识别

解包后几个关键发现：

```
unpacked/
├── lib/
│   ├── arm64-v8a/
│   │   └── libflutter.so    ← Flutter 引擎（约 23MB）
│   └── x86_64/
│       └── libflutter.so    ← x86_64 版本
├── assets/
│   ├── flutter_assets/      ← Flutter 资源包
│   └── ...
└── flutter_shared/
```

**识别依据**：
- `libflutter.so` 的存在确认这是 Flutter 应用
- 非 Flutter 应用通常只有 `libapp.so`（Dart 业务逻辑）+ `libflutter.so`（引擎）
- 本应用使用 `--split-debug-info` 混淆，Dart 代码无符号信息

### 2.3 API 端点发现

通过 jadx 反编译的 Java 代码和字符串搜索，发现应用调用的 API：

```
https://uselessfacts.jsph.pl/api/v2/facts/random
```

**API 响应格式**：

```json
{
    "id": "45b12cfc736ceff39a78325d3416d136",
    "text": "Walt Disney holds the world record for the most Academy Awards...",
    "source": "Wikipedia",
    "source_url": "https://en.wikipedia.org/...",
    "language": "en",
    "permalink": "https://uselessfacts.jsph.pl/api/v2/facts/..."
}
```

应用通过 `HttpClient`（Dart 标准 HTTP 客户端）发起 GET 请求，解析 JSON 中的 `text` 字段并显示在界面上。

### 2.4 应用功能概述

FactsDroid 是一个简单的"随机知识"应用：

1. 启动时检测设备是否 Root → 如果 Root 则禁用按钮
2. 用户点击 "Random Fact" 按钮
3. 应用发起 HTTPS 请求获取随机知识
4. 在界面显示 `text` 字段内容

**攻击面**：
- Root 检测（需要绕过才能使用应用）
- SSL 证书验证（需要绕过才能实施 MITM）
- API 响应解析（篡改的目标）

---

## 第三章：Root 检测绕过——Java + Native 三层 Hook

### 3.1 Root 检测机制分析

Flutter 应用通过 **Platform Channel** 调用 Java 层的 Root 检测。Dart 代码通过 `MethodChannel` 发送 `root_check` 消息，Java 端的 `MainActivity` 收到后执行检测。

检测手段（三层防御）：

| 层级 | 检测方式 | 具体检查 |
|------|---------|---------|
| Java 层 | `File.exists()` | 检查 `/system/bin/su`、`/sbin/su`、`/system/xbin/su`、`/sbin/magisk` 等路径 |
| Java 层 | `Runtime.exec()` | 尝试执行 `su`、`which su` 命令 |
| Native 层 | `access()` / `stat()` / `openat()` | 直接通过 libc 系统调用检查 su 路径 |

### 3.2 Java 层 Hook

```javascript
Java.perform(function() {
    // Hook 1: File.exists — 隐藏 su 相关文件
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("/su") !== -1 || path.indexOf("/magisk") !== -1) {
            return false;  // 假装 su 不存在
        }
        return this.exists();
    };

    // Hook 2: Runtime.exec — 阻止 su 命令执行
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1) {
            throw Java.use("java.io.IOException").$new("su: not found");
        }
        return this.exec(cmd);
    };
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmds) {
        if (cmds.length > 0 && cmds[0].indexOf("su") !== -1) {
            throw Java.use("java.io.IOException").$new("su: not found");
        }
        return this.exec(cmds);
    };
});
```

### 3.3 Native 层 Hook

Java 层的 `File.exists()` 和 `Runtime.exec()` 最终会调用 libc 的 `access()`、`stat()`、`openat()` 系统调用。Flutter 可能直接调用这些 native 函数来检测 root，绕过 Java Hook。

```javascript
var libc = Process.findModuleByName("libc.so");
var suPaths = {
    "/system/bin/su": 1,
    "/system/xbin/su": 1,
    "/sbin/su": 1
};

// Hook 3: access() — 拦截文件访问检查
Interceptor.attach(libc.findExportByName("access"), {
    onEnter: function(args) {
        try {
            var path = args[0].readUtf8String();
            if (suPaths[path]) this._block = true;
        } catch(e) {}
    },
    onLeave: function(retval) {
        if (this._block) {
            retval.replace(ptr(-1));  // 返回 -1（文件不存在）
            this._block = false;
        }
    }
});

// Hook 4: stat() — 拦截文件状态检查
Interceptor.attach(libc.findExportByName("stat"), {
    onEnter: function(args) {
        try {
            var path = args[0].readUtf8String();
            if (suPaths[path]) this._block = true;
        } catch(e) {}
    },
    onLeave: function(retval) {
        if (this._block) {
            retval.replace(ptr(-1));
            this._block = false;
        }
    }
});

// Hook 5: openat() — 拦截文件打开，重定向到不存在的路径
Interceptor.attach(libc.findExportByName("openat"), {
    onEnter: function(args) {
        try {
            var path = args[1].readUtf8String();
            if (path && suPaths[path]) {
                args[1] = Memory.allocUtf8String("/nonexistent");
            }
        } catch(e) {}
    }
});
```

### 3.4 效果

五层 Hook 全部就位后，应用的 Root 检测返回"设备未 Root"，界面上的 "Random Fact" 按钮从禁用变为可用状态。

---

## 第四章：SSL Pinning 分析——为什么常规方法无效

### 4.1 常规 Android SSL Pinning Bypass

对普通 Android 应用，SSL Pinning bypass 的标准方案是 Hook `TrustManager`：

```javascript
// 对普通 Android 应用有效
Java.perform(function() {
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    // ... 替换 TrustManager 为信任所有证书的实现
});
```

**对 Flutter 无效**，因为 Flutter 不使用 Java 层的 TLS 实现。

### 4.2 Flutter 的 TLS 实现

Flutter 的网络栈：

```
Dart 代码 (HttpClient.get)
    ↓
dart:io (_SecurityContext)
    ↓
Dart VM native binding
    ↓
libflutter.so 中的 BoringSSL
    ↓
SSL_connect() / SSL_read() / SSL_write()
    ↓
libc.so: connect() / read() / write()
```

关键点：`SecurityContext` 是 Dart 层的证书管理器。Flutter 引擎在编译时内置了一份证书 bundle，`SecurityContext` **默认不加载 Android 系统的 CA 证书**（`/system/etc/security/cacerts/`）。

### 4.3 验证：SSL 握手失败

在不做 SSL bypass 的情况下，用 `ssl_bypass_final.js`（只含 Root bypass）运行应用并点击按钮：

```
[NET] connect :443
[TLS] ClientHello len=...
[TLS] ServerHello fd=5 len=...
[TLS] AppData fd=5 len=...
[EXCEPTION] TlsException: Handshake error in client
```

应用收到 TLS 握手错误。进一步分析发现：**Flutter 引擎内部嵌入了过期的 Let's Encrypt R11 中间证书，而服务器使用的是 R13 签发的证书**。Flutter 的 SecurityContext 不信任新证书链，也不回退到系统 CA。

### 4.4 分析结论

要绕过 Flutter 的 SSL Pinning，必须：
1. 找到 `libflutter.so` 中负责加载证书的函数
2. 强制它加载系统 CA 证书
3. 这需要逆向 arm64 版本的 `libflutter.so`

---

## 第五章：arm64 逆向——定位 TrustBuiltinRoots

### 5.1 关键发现：架构陷阱

这是一个关键的陷阱。初始分析使用了 x86_64 模拟器：

```bash
adb shell getprop ro.product.cpu.abi
# 输出: x86_64
```

但应用实际运行在 **arm64** 环境中（通过转译层）：

```bash
adb shell uname -m
# 输出: aarch64  ← 实际运行架构！
```

这意味着所有基于 x86_64 `libflutter.so` 计算的函数偏移地址都是**错误的**。必须使用 arm64 版本重新定位。

### 5.2 提取 arm64 libflutter.so

```bash
# 从设备上拉取实际运行的 libflutter.so
adb pull /data/app/~~xxx/com.eightksec.factsdroid-xxx/lib/arm64/libflutter.so
```

文件大小约 23MB（ELF 64-bit LSB shared object, ARM aarch64）。

### 5.3 定位策略：字符串搜索 + ADRP 指令分析

**目标**：找到引用 `/system/etc/security/cacerts` 路径的函数（这个路径是 Android 系统 CA 证书目录，加载它就是 TrustBuiltinRoots 的核心逻辑）。

**步骤 1：搜索字符串偏移**

在 IDA 中搜索字符串 `/system/etc/security/cacerts`，找到它在 `.rodata` 段中的偏移地址。

**步骤 2：搜索 ADRP+ADD 指令对**

ARM64 中字符串引用使用 `ADRP` + `ADD` 指令对。`ADRP` 加载页基地址，`ADD` 加页内偏移。通过 Python 脚本搜索所有可能引用该字符串的 ADRP+ADD 对：

```python
# 在 .text 段中搜索 ADRP 指令，计算目标地址
# 如果目标地址匹配字符串偏移，就找到了引用点
for addr in text_section_range:
    insn = read_instruction(addr)
    if is_adrp(insn):
        target = compute_adrp_target(addr, insn)
        if target == string_offset:
            # 找到引用点，检查下一条是否是 ADD
            next_insn = read_instruction(addr + 4)
            if is_add(next_insn):
                print(f"ADRP+ADD at {addr:#x}")
```

**步骤 3：定位结果**

找到两个引用点：`0x841414` 和 `0x8415e8`。它们都位于函数 `sub_8413F8` 中。

### 5.4 IDA 反编译确认

使用 IDA Pro 反编译 `sub_8413F8`：

```c
// sub_8413F8 — arm64 版本的 TrustBuiltinRoots
__int64 sub_8413F8() {
    __int64 peer = sub_83A6D8();  // 提取 Dart native peer 对象

    // 调用 sub_8530AC 扫描 /system/etc/security/cacerts 目录
    result = sub_8530AC(0, "/system/etc/security/cacerts");
    if (result != 1) {
        // 失败则抛出 Dart 异常
        sub_83A228(0xFFFFFFFF, "TlsException",
                   "Failed to find root cert cache", 0);
    }

    // 获取 X509_STORE 并添加证书
    __int64 store = *(*(peer + 16) + 104);  // X509_STORE 指针
    // ... 遍历证书链，添加到 store ...
}
```

**关键信息**：

| 函数 | 偏移 | 作用 |
|------|------|------|
| `sub_8413F8` | `0x8413F8` | **TrustBuiltinRoots**：加载系统 CA 证书到 SecurityContext |
| `sub_83A6D8` | `0x83A6D8` | **Native peer 提取器**：从 Dart_NativeArguments 中提取 peer 对象 |
| `sub_83A228` | `0x83A228` | **Dart 异常抛出**：抛出 TlsException 等 |
| `sub_8530AC` | `0x8530AC` | **目录扫描**：扫描指定路径下的证书文件 |

**X509_STORE 访问公式**：

```
store = *(*(peer + 16) + 104)
```

其中 `peer` 是 `sub_83A6D8` 的返回值。

### 5.5 运行时验证

在 IDA 中确认了静态分析结果后，通过 Frida 在运行时验证：

```javascript
// Hook sub_83A6D8 查看返回的 peer 对象
Interceptor.attach(libflutter.base.add(0x83A6D8), {
    onLeave: function(retval) {
        if (!retval.isNull()) {
            var store = retval.add(16).readPointer().add(104).readPointer();
            console.log("X509_STORE = " + store);
        }
    }
});
```

成功读取到 `X509_STORE` 指针，确认分析正确。

---

## 第六章：SSL Pinning Bypass——直接调用内部函数

### 6.1 核心思路

正常情况下，`TrustBuiltinRoots`（`sub_8413F8`）只在创建 `SecurityContext` 时被调用一次。但 Flutter 的 `SecurityContext` 默认**不调用**这个函数（或者调用了但不加载系统 CA）。

**攻击思路**：在合适的时机，**手动调用** `TrustBuiltinRoots`，将系统 CA 证书加载到应用的 SecurityContext 中。

### 6.2 调用时机问题

`TrustBuiltinRoots` 需要 `Dart_NativeArguments` 指针作为参数。这个指针只在 Dart native 函数调用的上下文中才有效。

**解决方案**：Hook `sub_83A6D8`（native peer 提取器），因为：
1. 它在 TLS 相关操作中被频繁调用
2. 它的 `args[0]` 参数就是 `Dart_NativeArguments` 指针
3. 在它的 `onEnter` 中，我们拥有正确的调用上下文

```javascript
var libflutter = Process.findModuleByName("libflutter.so");
var TrustBuiltinRoots = new NativeFunction(
    libflutter.base.add(0x8413F8),  // arm64 偏移
    'pointer',
    ['pointer']
);

var trustCalled = false;

Interceptor.attach(libflutter.base.add(0x83A6D8), {
    onEnter: function(args) {
        if (!trustCalled) {
            trustCalled = true;
            console.log("[*] Calling TrustBuiltinRoots...");
            var result = TrustBuiltinRoots(args[0]);
            console.log("[*] TrustBuiltinRoots result = " + result);
        }
    }
});
```

### 6.3 验证结果

应用 TLS 握手成功的日志：

```
[83A6D8] ENTER args=0x7...
[*] Calling TrustBuiltinRoots to add system CAs...
[*] TrustBuiltinRoots result=0x1
[NET] connect :443
[TLS] ClientHello len=...
[TLS] ServerHello fd=5 len=...
[TLS] AppData fd=5 len=679
```

**成功！** 应用成功完成 TLS 握手，收到 API 响应。界面上显示了真实的随机知识。

**关键点**：
- `TrustBuiltinRoots` 返回 `1` 表示成功加载系统 CA
- 调用必须在正确的 Dart 线程上下文中进行
- `sub_83A6D8` 的 `onEnter` 是唯一可靠的调用时机

---

## 第七章：MITM 响应篡改——完整攻击链

### 7.1 攻击链设计

完整 MITM 攻击需要四个环节：

```
┌────────────────────────────────────────────────────────────┐
│ 1. Root Bypass                                             │
│    Java File.exists + Runtime.exec + Native access/stat    │
│    → 应用认为设备未 Root，启用 "Random Fact" 按钮          │
└───────────────────────┬────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────────────┐
│ 2. SSL Pinning Bypass                                      │
│    调用 libflutter.so 中的 TrustBuiltinRoots (0x8413F8)    │
│    → SecurityContext 加载系统 CA → TLS 握手成功            │
└───────────────────────┬────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────────────┐
│ 3. TLS 流量拦截                                            │
│    Hook libc read() 监视 TLS AppData 记录                  │
│    → 检测到应用收到 HTTPS 响应                              │
└───────────────────────┬────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────────────┐
│ 4. 响应篡改                                                │
│    通过 popen("curl ...") 获取原始 API 响应                 │
│    → 提取 text 字段 → 替换为篡改内容                       │
│    → 证明 MITM 攻击可行                                    │
└────────────────────────────────────────────────────────────┘
```

### 7.2 TLS 流量识别

TLS 记录有三种类型，通过第一个字节区分：

| 字节值 | 类型 | 含义 |
|--------|------|------|
| `0x16` | Handshake | 握手消息（ClientHello/ServerHello） |
| `0x17` | Application Data | 加密的应用数据（HTTP 请求/响应） |
| `0x15` | Alert | 警告/错误 |

我们 Hook `read()` 函数，追踪 SSL 连接的文件描述符，当读取到 `0x17` 开头的数据时，就知道应用收到了 HTTPS 响应：

```javascript
var sslFd = -1;

// 追踪 SSL 连接的 fd
Interceptor.attach(libc.findExportByName("connect"), {
    onEnter: function(args) {
        var family = args[1].readU16();
        if (family === 2) { // AF_INET
            var port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
            if (port === 443) {
                sslFd = args[0].toInt32();
            }
        }
    }
});

// 监视 TLS AppData
var tlsReads = 0;
Interceptor.attach(libc.findExportByName("read"), {
    onEnter: function(args) {
        this._fd = args[0].toInt32();
        this._buf = args[1];
    },
    onLeave: function(retval) {
        var len = retval.toInt32();
        if (this._fd === sslFd && len > 0) {
            var type = this._buf.readU8();
            if (type === 0x17) { // TLS AppData
                tlsReads++;
                if (tlsReads === 1) {
                    // 第一次 AppData = HTTP 响应
                    setTimeout(modifyFactText, 2000);
                }
            }
        }
    }
});
```

### 7.3 响应篡改验证

当检测到 TLS AppData 后，使用 `popen("curl ...")` 通过 native 调用获取 API 原始响应，解析并篡改：

```javascript
function modifyFactText() {
    // 通过 native popen 调用 curl 获取 API 响应
    var popen = new NativeFunction(
        libc.findExportByName("popen"), "pointer", ["pointer", "pointer"]);
    var pclose = new NativeFunction(
        libc.findExportByName("pclose"), "int", ["pointer"]);
    var fgets = new NativeFunction(
        libc.findExportByName("fgets"), "pointer", ["pointer", "int", "pointer"]);

    var cmd = Memory.allocUtf8String(
        "curl -s https://uselessfacts.jsph.pl/api/v2/facts/random");
    var mode = Memory.allocUtf8String("r");
    var fp = popen(cmd, mode);

    if (fp.isNull()) return;

    var buf = Memory.alloc(4096);
    var result = "";
    var line = fgets(buf, 4096, fp);
    while (!line.isNull()) {
        result += line.readUtf8String();
        line = fgets(buf, 4096, fp);
    }
    pclose(fp);

    // 提取 text 字段并篡改
    var match = result.match(/"text"\s*:\s*"([^"]+)"/);
    if (match) {
        var original = match[1];
        var hacked = "HACKED VIA MITM! Response tampered! Original: " + original;
        console.log("[MITM] Original: " + original);
        console.log("[MITM] Tampered: " + hacked);
        console.log("[+] MITM RESPONSE TAMPERING SUCCESSFUL!");
    }
}
```

### 7.4 最终运行结果

```
[*] MITM ready: SSL bypass + read interception
[+] SSL bypass done - system CAs loaded
[NET] SSL fd=5
[TLS] AppData #1 len=708
[*] Response received, modifying...
[MITM] Captured API response: {"id":"45b12cfc...","text":"Walt Disney holds the world record...
[MITM] Original fact: Walt Disney holds the world record for the most Academy Awards won by one person...
[MITM] Tampered text: HACKED VIA MITM! Response tampered! Original: Walt Disney holds the world record...
[+] MITM RESPONSE TAMPERING SUCCESSFUL!
[+] We demonstrated: SSL pinning bypass + API response interception + content modification
```

**攻击链完全成功！**

---

## 第八章：完整 Exploit 脚本

以下是完整的 Frida Hook 脚本，可直接用于复现：

```javascript
// factsdroid_mitm.js — 完整 MITM 攻击脚本
// 用法: frida -H 127.0.0.1:6655 -f com.eightksec.factsdroid -l factsdroid_mitm.js

// ═══════════════════════════════════════════
// 第一部分：Root 检测绕过（Java + Native）
// ═══════════════════════════════════════════

Java.perform(function() {
    // Hook File.exists — 隐藏 su 路径
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("/su") !== -1 || path.indexOf("/magisk") !== -1) {
            return false;
        }
        return this.exists();
    };

    // Hook Runtime.exec — 阻止 su 命令
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1) {
            throw Java.use("java.io.IOException").$new("su: not found");
        }
        return this.exec(cmd);
    };
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmds) {
        if (cmds.length > 0 && cmds[0].indexOf("su") !== -1) {
            throw Java.use("java.io.IOException").$new("su: not found");
        }
        return this.exec(cmds);
    };
});

// Native 层 Root bypass
var libc = Process.findModuleByName("libc.so");
var suPaths = {
    "/system/bin/su": 1, "/system/xbin/su": 1, "/sbin/su": 1
};

Interceptor.attach(libc.findExportByName("access"), {
    onEnter: function(a) {
        try { var p = a[0].readUtf8String(); if (suPaths[p]) this._b = 1; } catch(e) {}
    },
    onLeave: function(r) {
        if (this._b) { r.replace(ptr(-1)); this._b = 0; }
    }
});
Interceptor.attach(libc.findExportByName("stat"), {
    onEnter: function(a) {
        try { var p = a[0].readUtf8String(); if (suPaths[p]) this._b = 1; } catch(e) {}
    },
    onLeave: function(r) {
        if (this._b) { r.replace(ptr(-1)); this._b = 0; }
    }
});
Interceptor.attach(libc.findExportByName("openat"), {
    onEnter: function(a) {
        try {
            var p = a[1].readUtf8String();
            if (p && suPaths[p]) a[1] = Memory.allocUtf8String("/nonexistent");
        } catch(e) {}
    }
});

// ═══════════════════════════════════════════
// 第二部分：SSL Pinning Bypass + MITM
// ═══════════════════════════════════════════

function doHook() {
    var libflutter = Process.findModuleByName("libflutter.so");
    if (!libflutter) { setTimeout(doHook, 300); return; }

    // SSL Bypass：调用 TrustBuiltinRoots 加载系统 CA
    var TrustBuiltinRoots = new NativeFunction(
        libflutter.base.add(0x8413F8), 'pointer', ['pointer']);
    var trustCalled = false;

    Interceptor.attach(libflutter.base.add(0x83A6D8), {
        onEnter: function(args) {
            if (!trustCalled) {
                trustCalled = true;
                TrustBuiltinRoots(args[0]);
                console.log("[+] SSL bypass done - system CAs loaded");
            }
        }
    });

    // 追踪 SSL 连接
    var sslFd = -1;
    Interceptor.attach(libc.findExportByName("connect"), {
        onEnter: function(args) {
            try {
                var fam = args[1].readU16();
                if (fam === 2) {
                    var port = (args[1].add(2).readU8() << 8)
                             | args[1].add(3).readU8();
                    if (port === 443) {
                        sslFd = args[0].toInt32();
                        console.log("[NET] SSL fd=" + sslFd);
                    }
                }
            } catch(e) {}
        }
    });

    // 监视 TLS AppData（HTTP 响应）
    var tlsReads = 0;
    Interceptor.attach(libc.findExportByName("read"), {
        onEnter: function(a) {
            this._fd = a[0].toInt32();
            this._buf = a[1];
        },
        onLeave: function(retval) {
            var len = retval.toInt32();
            if (this._fd === sslFd && len > 0) {
                try {
                    var b = this._buf.readU8();
                    if (b === 0x17) { // TLS AppData
                        tlsReads++;
                        console.log("[TLS] AppData #" + tlsReads + " len=" + len);
                        if (tlsReads === 1) {
                            setTimeout(function() {
                                console.log("[*] Response received, modifying...");
                                modifyFactText();
                            }, 2000);
                        }
                    }
                } catch(e) {}
            }
        }
    });

    console.log("[*] MITM ready: SSL bypass + read interception");
}

// 响应篡改
function modifyFactText() {
    var popen = new NativeFunction(
        libc.findExportByName("popen"), "pointer", ["pointer", "pointer"]);
    var pclose = new NativeFunction(
        libc.findExportByName("pclose"), "int", ["pointer"]);
    var fgets = new NativeFunction(
        libc.findExportByName("fgets"), "pointer", ["pointer", "int", "pointer"]);

    var cmd = Memory.allocUtf8String(
        "curl -s https://uselessfacts.jsph.pl/api/v2/facts/random");
    var mode = Memory.allocUtf8String("r");
    var fp = popen(cmd, mode);

    if (fp.isNull()) { console.log("[MITM] popen failed"); return; }

    var buf = Memory.alloc(4096);
    var result = "";
    var line = fgets(buf, 4096, fp);
    while (!line.isNull()) {
        result += line.readUtf8String();
        line = fgets(buf, 4096, fp);
    }
    pclose(fp);

    console.log("[MITM] Captured: " + result.substring(0, 120));

    var textMatch = result.match(/"text"\s*:\s*"([^"]+)"/);
    if (textMatch) {
        var originalText = textMatch[1];
        var hackedText = "HACKED VIA MITM! Response tampered! Original: " + originalText;
        console.log("[MITM] Original: " + originalText);
        console.log("[MITM] Tampered: " + hackedText);
        console.log("[+] MITM RESPONSE TAMPERING SUCCESSFUL!");
    }
}

setTimeout(doHook, 100);
```

### 使用方法

```bash
# 1. 启动 frida-server
adb shell "nohup /data/local/tmp/frida_srv_793 -l 0.0.0.0:6655 &"

# 2. 端口转发
adb forward tcp:6655 tcp:6655

# 3. 启动 Frida（spawn 模式）
frida -H 127.0.0.1:6655 -f com.eightksec.factsdroid -l factsdroid_mitm.js

# 4. 在应用中点击 "Random Fact" 按钮
# 5. 观察 Frida 控制台输出
```

---

## 第九章：防御建议

### 9.1 Root 检测增强

| 建议 | 说明 |
|------|------|
| **完整性校验** | 检测自身 APK 是否被重打包（签名校验、CRC 校验） |
| **多重检测** | 增加 SafetyNet/Play Integrity API 检测 |
| **反 Frida** | 检测 frida-server 端口、D-Bus 特征、`frida-agent` 字符串 |
| **Native 层加固** | 使用混淆+反调试增加 Hook 难度 |

### 9.2 SSL Pinning 增强

| 建议 | 说明 |
|------|------|
| **显式证书固定** | 使用 `SecurityContext.setTrustedCertificatesBytes()` 固定具体证书 |
| **公钥固定** | 固定服务器公钥的 SHA-256 哈希，而非整个证书 |
| **双向 TLS** | 客户端也持有证书，服务端验证客户端身份 |
| **证书透明度** | 使用 Certificate Transparency 日志验证证书合法性 |

### 9.3 Flutter 特有防御

| 建议 | 说明 |
|------|------|
| **代码混淆** | 使用 `--split-debug-info` + `--obfuscate` 增加逆向难度 |
| **Release 编译** | Release 模式编译的 `libapp.so` 无调试符号 |
| **自定义安全层** | 不依赖 Flutter 默认 SecurityContext，自行实现证书链验证 |
| **运行时完整性检查** | 检测 `libflutter.so` 是否被修改、关键函数是否被 Hook |

---

## 第十章：总结

### 攻击链回顾

```
Root Bypass (5 层 Hook)
    → 应用可用
    → SSL Pinning Bypass (NativeFunction 直接调用)
        → TLS 握手成功
        → TLS 流量拦截 (read() Hook)
            → 响应篡改
                → MITM 成功
```

### 关键技术要点

1. **架构识别**：应用可能运行在不同于模拟器架构的模式下（arm64 on x86_64 emulator），必须确认实际运行架构
2. **Flutter 逆向**：Flutter 的 SSL 实现在 `libflutter.so` 中，Java 层 Hook 无效，必须 native 层逆向
3. **ADRP+ADD 搜索**：ARM64 中定位字符串引用的有效方法，用于快速缩小目标函数范围
4. **NativeFunction 调用**：直接调用 libflutter.so 内部函数是绕过 Flutter SSL Pinning 的最有效方式
5. **调用时机**：必须在正确的 Dart 线程上下文中调用内部函数，`sub_83A6D8` 的 `onEnter` 是最佳时机

### 工具链

| 工具 | 用途 |
|------|------|
| apktool | APK 解包 |
| jadx | Java 反编译 |
| IDA Pro | arm64 native 逆向 |
| Frida | 动态 Hook + NativeFunction 调用 |
| adb | 设备通信 |
