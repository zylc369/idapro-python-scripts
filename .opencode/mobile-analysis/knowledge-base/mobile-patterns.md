# 移动端常见安全模式

> 移动应用中常见的安全机制及其分析方法。

## SSL Pinning（证书固定）

### 原理

应用在客户端硬编码服务器证书或公钥的哈希值，即使系统信任了中间人证书，应用也会拒绝连接。

### 检测方法

```bash
# 1. 搜索证书相关代码
jadx -d java_src app.apk
grep -r "CertificatePinner\|sslPin\|TrustManager\|X509TrustManager\|pinning" java_src/

# 2. 搜索配置文件中的 pin
grep -r "pin-set\|pin digest" unpacked/res/
```

### 绕过方法

**方法 1: Frida Hook（推荐）**

```javascript
// OkHttp CertificatePinner Hook
Java.perform(function() {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
        console.log("[*] SSL Pinning bypassed for: " + hostname);
    };
});
```

```javascript
// TrustManager Hook（通用）
Java.perform(function() {
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var TrustManagerImpl = Java.registerClass({
        name: "com.bypass.TrustManager",
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    SSLContext.init.overload("[Ljavax.net.ssl.TrustManager;", "[Ljavax.net.ssl.KeyManager;", "java.security.SecureRandom").implementation = function(tms, kms, sr) {
        this.init([TrustManagerImpl.$new()], kms, sr);
    };
});
```

**方法 2: 修改 APK**

```bash
# 反编译 → 修改 smali 中的证书校验逻辑 → 重打包
apktool d app.apk -o unpacked
# 编辑 smali 中 CertificatePinner.check 相关代码
apktool b unpacked -o modified.apk
```

**iOS SSL Pinning 绕过**

```javascript
// NSURLSession delegate Hook
var delegate = ObjC.classes.NSURLSession;
// 或使用 SSL Kill Switch 2 (越狱越备)
```

---

## Root/越狱检测

### Android Root 检测

| 检测方法 | 分析位置 |
|---------|---------|
| 检查 su 命令 | `Runtime.exec("which su")` |
| 检查 Superuser.apk | `File.exists("/system/app/Superuser.apk")` |
| 检查 Magisk | `File.exists("/sbin/magisk")` |
| SafetyNet attestation | Google Play Services API |
| 检查 SELinux | 读取 /proc/self/attr/current |

### Root 检测绕过

```javascript
Java.perform(function() {
    // Hook File.exists() — 隐藏特定路径
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var blocked = ["/sbin/su", "/system/bin/su", "/system/xbin/su",
                       "/data/local/bin/su", "/system/app/Superuser.apk",
                       "/sbin/magisk"];
        if (blocked.indexOf(path) !== -1) {
            console.log("[*] Root check bypassed: " + path);
            return false;
        }
        return this.exists();
    };
});
```

### iOS 越狱检测

| 检测方法 | 分析位置 |
|---------|---------|
| 检查 Cydia | `FileManager.fileExists(atPath: "/Applications/Cydia.app")` |
| 检查 SSH | 尝试连接 localhost:22 |
| 检查 /bin/bash | `FileManager.fileExists(atPath: "/bin/bash")` |
| 检查 fork | 检测能否 fork 子进程（沙箱限制） |

---

## 代码混淆

### ProGuard / R8（Android）

**识别特征**:
- 类名/方法名为 `a.b.c`、`a.b.d` 等短名
- 反编译后大量无意义命名
- 通常保留了 Application/Activity 等关键类名

**分析策略**:

```
1. jadx --deobf 反编译 → jadx 自动重命名（a→a_b_c）
2. 搜索字符串常量 → 从字符串反推方法用途
3. 搜索 API 调用 → 从系统调用反推逻辑
4. 检查 mapping 文件（如果有的话）→ 还原原始名称
5. 结合 smali 精读 → jadx 不可读的部分
```

###OLLVM / 控制流平坦化

**识别特征**:
- 大量 switch/dispatcher 结构
- while(1) 循环内 switch
- IDA Pro 中 CFG 呈"意大利面条"状

**分析策略**:

```
1. 识别 dispatcher 变量（通常是一个整数）
2. 追踪 dispatcher 的赋值链
3. 还原真实的控制流（忽略混淆的跳转）
4. 使用 IDA Pro 的 HexRays 反编译 + 手动修正
5. 如无法还原 → 使用动态分析（Frida Hook）绕过
```

---

## 反调试

### 常见反调试技术

| 技术 | 平台 | 检测方法 |
|------|------|---------|
| `ptrace(PTRACE_TRACEME)` | Android | 检查 `/proc/self/status` 的 TracerPid |
| `android.os.Debug.isDebuggerConnected()` | Android | Java 层调试检测 |
| `sysctl` 检查 P_TRACED flag | iOS | BSD 层调试检测 |
| 检测断点指令 | 通用 | 代码完整性校验 |
| 时间检测（rdtsc） | 通用 | 检测单步执行 |

### 反调试绕过

```javascript
// Android: Hook ptrace
var libc = Process.getModuleByName("libc.so");
Interceptor.attach(libc.getExportByName("ptrace"), {
    onEnter: function(args) {
        if (args[0].toInt32() === 0) {  // PTRACE_TRACEME
            console.log("[*] Anti-debug: ptrace(TRACEME) bypassed");
            args[0] = ptr(-1);  // 改为无效请求
        }
    }
});

// Android: Hook Debug.isDebuggerConnected
Java.perform(function() {
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[*] Anti-debug: isDebuggerConnected bypassed");
        return false;
    };
});
```

---

## 完整性校验

### 常见校验方式

| 方式 | 分析方法 |
|------|---------|
| APK 签名校验 | 提取签名证书对比 → 搜索 `PackageManager.GET_SIGNATURES` |
| .so 文件哈希校验 | 定位校验代码 → Patch 跳过 |
| dex CRC 校验 | 搜索 `CRC32`/`Adler32` 调用 |
| assets 文件校验 | 搜索 `MessageDigest`/`DigestUtils` |

### 绕过方法

```
1. 定位校验函数（搜索相关 API 调用）
2. Frida Hook 使校验函数始终返回成功
3. 或直接 Patch 二进制（条件跳转 → 无条件跳转）
```
