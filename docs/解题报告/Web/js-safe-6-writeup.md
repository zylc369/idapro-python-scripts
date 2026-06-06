# JS Safe 6.0 — 反调试 + 代码混淆 逆向分析 Writeup

> CTF: Google CTF | 难度: Hard | 题目名: JS Safe 6.0
>
> 题目来源: 本地文件 `js_safe_6.html`
>
> Flag: `CTF{1M_4_C7F_p14y32_4N71_d38U9_721cK5_d0n7_w02K_0n_m3}`

**题目分类：Web 前端安全 + JavaScript 逆向**。本题考察的是 **Chrome DevTools `debug()` API 机制理解** + **tagged template 隐式调用** + **多层编码解码** + **基于 step 计数器的 flag 校验算法** 的组合。

核心思路可以用一句话概括：**题目把 flag 的每个字符藏在经过 ROT13+ROT47 编码的字符池中，用基于 `debug()` condition 的 step 计数器决定取字符的顺序，你需要理解整套机制正向模拟出正确的 flag。**

---

## 目录

- [第一章：你需要先知道的知识](#第一章你需要先知道的知识)
  - [1.1 Chrome DevTools Console 中的 debug() 函数](#11-chrome-devtools-console-中的-debug-函数)
  - [1.2 什么是 debug condition（调试条件）](#12-什么是-debug-condition调试条件)
  - [1.3 什么是 Chrome DevTools Protocol (CDP)](#13-什么是-chrome-devtools-protocol-cdp)
  - [1.4 什么是 includeCommandLineAPI](#14-什么是-includecommandlineapi)
  - [1.5 什么是 Tagged Template（标签模板）](#15-什么是-tagged-template标签模板)
  - [1.6 什么是 ROT13 和 ROT47 编码](#16-什么是-rot13-和-rot47-编码)
  - [1.7 JavaScript 中的 Unicode 隐身字符](#17-javascript-中的-unicode-隐身字符)
  - [1.8 什么是 Proxy 和 Object.defineProperty](#18-什么是-proxy-和-objectdefineproperty)
- [第二章：这道题是什么结构](#第二章这道题是什么结构)
  - [2.1 题目使用说明](#21-题目使用说明)
  - [2.2 整体架构图](#22-整体架构图)
  - [2.3 页面功能：ASCII 旋转立方体](#23-页面功能ascii-旋转立方体)
  - [2.4 三个核心函数：anti()、check()、unlock()](#24-三个核心函数anticheckunlock)
- [第三章：反调试机制深度解析](#第三章反调试机制深度解析)
  - [3.1 机制总览](#31-机制总览)
  - [3.2 机制一：instrument()——debug condition 性能计数器](#32-机制一instrumentdebug-condition-性能计数器)
  - [3.3 机制二：instrumentPrototype()——原型链 getter 劫持](#33-机制二instrumentprototype原型链-getter-劫持)
  - [3.4 机制三：instrumentPrototypeOfPrototype()——Proxy 原型拦截](#34-机制三instrumentprototypeofprototypeproxy-原型拦截)
  - [3.5 机制四：check() 函数自检](#35-机制四check-函数自检)
  - [3.6 机制五：HTML 长度校验](#36-机制五html-长度校验)
  - [3.7 机制六：double() 障眼法](#37-机制六double-障眼法)
  - [3.8 机制七：U+FFA0 隐藏标识符](#38-机制七u+ffa0-隐藏标识符)
  - [3.9 机制八：tagged template 隐式 ROT13](#39-机制八tagged-template-隐式-rot13)
  - [3.10 所有机制如何协同工作](#3a0-所有机制如何协同工作)
- [第四章：破解过程——从失败到成功](#第四章破解过程从失败到成功)
  - [4.1 第一步：静态分析——阅读源码](#41-第一步静态分析阅读源码)
  - [4.2 关键转折点：发现 pool 的 tagged template](#42-关键转折点发现-pool-的-tagged-template)
  - [4.3 最大的错误：误删 ROT13 步骤](#43-最大的错误误删-rot13-步骤)
  - [4.4 失败原因分析：为什么几十个版本全算错了](#44-失败原因分析为什么几十个版本全算错了)
  - [4.5 最终突破：回归正确的 pool 计算](#45-最终突破回归正确的-pool-计算)
  - [4.6 另一个关键教训：不要清除 intervals](#46-另一个关键教训不要清除-intervals)
- [第五章：完整攻击复现](#第五章完整攻击复现)
  - [5.1 自动化脚本（Python + Playwright）](#51-自动化脚本python--playwright)
  - [5.2 手动验证步骤](#52-手动验证步骤)
- [第六章：如何防御](#第六章如何防御)
- [第七章：总结](#第七章总结)

---

## 第一章：你需要先知道的知识

要理解这道题，你需要先了解几个 JavaScript 和 Chrome DevTools 的概念。别担心，我会用最通俗的方式解释每一个。

### 1.1 Chrome DevTools Console 中的 debug() 函数

当你在 Chrome 中按 F12 打开开发者工具（DevTools），切换到 Console（控制台）标签页，你不仅可以在里面执行普通 JavaScript 代码，还能使用一些**只有 Console 才提供的特殊函数**。`debug()` 就是其中之一。

**`debug()` 的作用**：给一个函数设置"条件断点"。当这个函数被调用时，Chrome 会在执行函数体之前，先执行你指定的条件代码。

```javascript
// 语法：debug(目标函数, "条件表达式字符串")
debug(myFunction, "console.log('myFunction 被调用了!'); false");

// 之后每次调用 myFunction()，控制台都会打印消息
myFunction();  // 输出: myFunction 被调用了!
```

关键细节：
- 条件表达式是一个**字符串**，Chrome 会在调用目标函数之前把它当作 JavaScript 执行
- 如果条件表达式返回 `true`（或任何真值），Chrome 会**暂停执行**（触发断点）
- 如果返回 `false`（或任何假值），Chrome **不暂停**，函数正常执行
- 条件表达式中可以执行任意代码，不仅仅是返回 true/false

> **核心要点**：条件表达式中的**所有代码都会被执行**，无论最终返回 true 还是 false。返回值只决定"是否暂停"。本题正是利用了这一点——在条件表达式中执行 `window.step += 源码长度`（累加 step），然后不管返回什么都让程序继续运行。

与之对应的还有 `undebug()`，用来移除断点：

```javascript
undebug(myFunction);  // 移除 myFunction 上的所有 debug 条件
```

**⚠️ 重要**：`debug()` 和 `undebug()` **只存在于 DevTools Console 环境中**。如果你在普通网页的 `<script>` 标签里直接调用 `debug()`，会报 `ReferenceError: debug is not defined`。题目要求你在 Console 中输入 `anti(debug)`，就是利用了这个 Console 专属 API。

### 1.2 什么是 debug condition（调试条件）

上一节说 `debug()` 可以设置条件表达式。这个条件表达式在 Chrome 内部有一个专门的名称：**debug condition**（调试条件）。

理解 debug condition 的关键在于它的**执行时机**和**执行上下文**：

```
调用 myFunction()
  │
  ├── 1. Chrome 检查 myFunction 是否有 debug condition
  │      ↓ 有
  ├── 2. Chrome 执行 debug condition（条件表达式）
  │      ↓
  ├── 3. 如果条件返回 true → 暂停执行（断点触发）
  │      如果条件返回 false → 不暂停，继续
  │      ↓
  └── 4. 执行 myFunction 的函数体
```

**关键特性**：当 Chrome 在执行一个 debug condition 时，如果这个 condition 内部又调用了其他被 `debug()` 标记的函数，Chrome **默认会抑制这些嵌套的 condition 评估**，直接执行被调用函数的函数体。这是为了防止无限嵌套（A 的 condition 调用 B → 触发 B 的 condition → B 的 condition 调用 C → 触发 C 的 condition → ...永无止境）。这个特性在本题中至关重要——它使得 check() 函数内部的 step 计数在 debug condition 上下文中有较低的增量（约 150/轮），而不是直接调用时的巨大增量（约 80000/轮）。

### 1.3 什么是 Chrome DevTools Protocol (CDP)

**Chrome DevTools Protocol（CDP）** 是 Chrome 浏览器提供的一套远程控制协议。它允许外部程序通过网络连接来控制 Chrome——就像你手动操作 DevTools 一样，但全部自动化。

用类比来理解：如果 DevTools 界面是你手动操作 Chrome的"方向盘"，那 CDP 就是"自动驾驶 API"——你可以用代码来做同样的事情。

本题中，我们用 **Playwright**（一个浏览器自动化库）通过 CDP 来：
- 打开 Chrome 浏览器
- 导航到指定页面
- 在页面的 JavaScript 环境中执行代码（相当于在 Console 中输入）
- 捕获 alert 弹框

CDP 中执行 JavaScript 的命令是 `Runtime.evaluate`：

```python
# 通过 CDP 在 Chrome 中执行 JavaScript
cdp_session.send("Runtime.evaluate", {
    "expression": "1 + 2",           # 要执行的 JS 代码
    "returnByValue": True,            # 返回值而不是引用
    "includeCommandLineAPI": True,    # 关键！见下一节
})
# 返回: {"result": {"value": 3}}
```

### 1.4 什么是 includeCommandLineAPI

这是本题自动化验证的关键参数，也是很多读者会困惑的地方。

还记得前面说 `debug()` 函数**只存在于 Console 环境中**吗？当你通过 CDP 的 `Runtime.evaluate` 执行代码时，默认情况下它是**普通 JavaScript 执行环境**，不包含 `debug()` 等 Console 专属函数。

`includeCommandLineAPI: true` 的作用就是告诉 Chrome：**"请在 Console API 环境中执行这段代码"**，使得 `debug()`、`undebug()`、`$()` 等函数可用。

```python
# ❌ 没有 includeCommandLineAPI → debug 未定义
cdp.send("Runtime.evaluate", {
    "expression": "debug(check, 'false')",
    "returnByValue": True,
})
# 报错: ReferenceError: debug is not defined

# ✅ 有 includeCommandLineAPI → 正常执行
cdp.send("Runtime.evaluate", {
    "expression": "debug(check, 'false')",
    "returnByValue": True,
    "includeCommandLineAPI": True,  # 关键！
})
# 成功
```

**这和我们手动在 DevTools Console 里输入命令有什么区别？**

从 JavaScript 执行的角度看，**几乎没有区别**。`Runtime.evaluate` + `includeCommandLineAPI` 就是让 CDP 在和 Console 相同的环境中执行代码。

有一个区别是：通过 CDP 执行的命令**不会出现在 Console 的历史记录中**——所以你用 CDP 执行了代码，在 DevTools Console 面板里看不到输入过的命令。但代码的执行效果（变量修改、函数调用等）是完全一样的。

### 1.5 什么是 Tagged Template（标签模板）

这是 ES6 引入的一个 JavaScript 特性，也是本题最精妙的trick之一。

普通的模板字符串用反引号包裹：

```javascript
const name = "Alice";
const greeting = `Hello, ${name}!`;  // "Hello, Alice!"
```

**Tagged template** 在模板字符串前面加一个函数名（称为"标签函数"）：

```javascript
function myTag(strings, ...values) {
    // strings: 不含表达式的字符串部分数组
    // values: 表达式的值
    return strings[0] + values[0] + strings[1];
}

const name = "Alice";
const result = myTag`Hello, ${name}!`;  // "Hello, Alice!"
```

当没有表达式时，标签函数收到一个单元素数组：

```javascript
function shout(parts) {
    return parts[0].toUpperCase();
}

shout`hello`;  // "HELLO"
```

**本题中的应用**：题目把 ROT13 函数（存储在变量名 `ﾠ` 中，即 U+FFA0）当作标签函数，对 pool 字符串进行隐式变换：

```javascript
// 表面上看：给 pool 赋一个模板字符串
let pool = ﾠ`?o>...\`5`;

// 实际上：ﾠ(ROT13函数) 被当作标签函数调用，pool 得到的是 ROT13 的结果
// 等价于：pool = rot13("?o>...`5")
```

这个trick非常隐蔽——代码看起来只是简单的赋值，但暗中调用了 ROT13 函数。

### 1.6 什么是 ROT13 和 ROT47 编码

**ROT13**（Rotate by 13 places）：把英文字母循环移动 13 位。a→n, b→o, ..., n→a, o→b。只变换字母，其他字符不变。ROT13 是自逆的：对结果再做一次 ROT13 就还原了。

```
ROT13("Hello") = "Uryyb"
ROT13("Uryyb") = "Hello"
```

**ROT47**：比 ROT13 更通用的版本，作用于 ASCII 可见字符范围（33-126）。每个字符的 ASCII 码移动 47 位。

```
ROT47("A")  → "p"   (65 → 112)
ROT47("p")  → "A"   (112 → 65)
```

本题中 pool 字符串经过 **ROT13 → ROT47** 两层变换，解码后得到真正的字符池。

### 1.7 JavaScript 中的 Unicode 隐身字符

JavaScript 允许在标识符（变量名、函数名）中使用 Unicode 字符。题目利用了一个特殊字符 **U+FFA0**（HALFWIDTH HANGUL FILLER，半角韩文填充符）。

这个字符的狡猾之处在于：
- 它在大多数编辑器中**看起来像一个空格**
- 但它是一个**合法的 JavaScript 标识符字符**
- 所以 `window.step` 和 `window.stepﾠ`（后面有 U+FFA0）是**两个完全不同的变量**

```javascript
window.step = 100;          // 普通 step 变量
window.stepﾠ = 5;           // step + U+FFA0，另一个完全不同的变量！

console.log(window.step);    // 100
console.log(window.stepﾠ);   // 5
```

在本题中，`double()` 函数看似会修改 `window.step`（翻倍），实际上修改的是 `window.stepﾠ`——一个完全无关的变量。这就是一个障眼法。

### 1.8 什么是 Proxy 和 Object.defineProperty

这两个是 JavaScript 的高级特性，题目用它们来实现"每次调用数组方法都计数"的效果。

**Object.defineProperty** 可以修改对象属性的描述符：

```javascript
const obj = { name: "Alice" };

// 把 name 属性替换为 getter——每次访问时执行函数
Object.defineProperty(obj, "name", {
    get: () => { console.log("name 被访问了!"); return "Alice"; }
});

console.log(obj.name);  // 先打印 "name 被访问了!"，然后打印 "Alice"
```

**Proxy** 可以拦截对象的所有操作：

```javascript
const handler = {
    get(target, prop) {
        console.log(`访问了属性: ${prop}`);
        return target[prop];
    }
};

const arr = new Proxy([1, 2, 3], handler);
arr.length;  // 打印 "访问了属性: length"
arr[0];      // 打印 "访问了属性: 0"
```

在本题中：
- `instrumentPrototype()` 用 `Object.defineProperty` 给 `Array.prototype` 上的方法（shift、splice 等）设置了 getter，每次访问这些方法时 `step++`
- `instrumentPrototypeOfPrototype()` 用 `Proxy` 包裹了 `Array.prototype` 的原型，拦截所有属性查找，每次也 `step++`

这两个机制共同构成了 step 计数器的一部分——即使没有 debug condition，这些 getter 和 proxy 也会在每次操作时增加 step。

### 1.9 什么是 Debugger.enable 和自动 resume

在 CDP 中，Chrome 的调试器默认是关闭的。`Debugger.enable` 命令打开调试器，让它能处理断点和 debug condition。

当 debug condition 返回 `true` 时，Chrome 会**暂停执行**（就像你手动设置了一个断点）。在真实的 DevTools 中，这会让程序停下来等你操作。但在自动化脚本中，没有人去点"继续"按钮——程序就卡住了。

解决方案：监听 `Debugger.paused` 事件，每次触发时自动调用 `Debugger.resume` 继续：

```python
cdp.send("Debugger.enable", {})

def on_paused(params):
    # 调试器暂停了，自动继续
    cdp.send("Debugger.resume", {})

cdp.on("Debugger.paused", on_paused)
```

**这不影响 flag 的计算**。因为 flag 的正确性取决于 step 计数器的值，而 step 是在 debug condition 的条件表达式执行过程中累加的——无论 Chrome 是否暂停过，条件表达式的执行结果都一样。`resume` 只是告诉 Chrome"我看到了，继续执行"，类似于你在 DevTools 里点了"继续"按钮。

---

## 第二章：这道题是什么结构

这一章我们从宏观角度看整个题目的运作流程，理解数据如何在各函数之间流转。

### 2.1 题目使用说明

题目给出了明确的使用步骤：

```
1. 用 Chrome 打开页面
2. 按 F12 打开 DevTools
3. 在 Console 中输入: anti(debug);       // 初始化反调试系统
4. 在 Console 中输入: unlock("密码");    // 尝试解锁 → 弹出 alert 显示密文内容
5. 可选: store("新密文");                // 存储新的加密内容
```

我们的目标是找到正确的"密码"，使得 `unlock("密码")` 触发 alert 弹框。

### 2.2 整体架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                     js_safe_6.html 页面                          │
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────┐                    │
│  │  渲染动画脚本      │    │  安全逻辑脚本      │                    │
│  │  renderFrame()    │    │  anti()           │                    │
│  │  setInterval      │    │  check()          │                    │
│  │  3D旋转立方体      │    │  unlock()         │                    │
│  │                   │    │  store()          │                    │
│  └──────────────────┘    └──────────────────┘                    │
│           │                       │                               │
│           │              ┌────────┴────────┐                     │
│           │              │  instrument()    │                     │
│           │              │  instrumentPrototype()                │
│           │              │  instrumentPrototypeOfPrototype()     │
│           │              └─────────────────┘                     │
│           │                       │                               │
│           └─────── 共同驱动 ───────┘                               │
│                       window.step 计数器                          │
│                                                                  │
│  localStorage: { content: [加密后的密文数组] }                      │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 页面功能：ASCII 旋转立方体

页面的外观是一个 ASCII 字符构成的 3D 旋转立方体动画，由 `renderFrame()` 函数每帧渲染。这个动画不是装饰——它被题目"征用"为 step 计数器的一部分：

- `renderFrame()` 在每帧中调用大量数组方法（map、forEach、join 等）和数学函数（sin、cos 等）
- 这些方法都被 `instrument()` 加了 debug condition
- 所以每次 `renderFrame()` 执行，`window.step` 都会增加一大截

在 check() 的 while 循环中，每次匹配一个字符后都调用 `renderFrame()`，用它来推进 step 计数器。

### 2.4 三个核心函数：anti()、check()、unlock()

#### anti(debug) —— 初始化

```javascript
function anti(debug) {
    window.step = 0;           // 步数计数器清零
    window.c = true;           // 启用 debug condition 计数（U+FFA0 后缀）
    window.success = false;    // 解锁状态：未解锁
    
    window.r = function(s) { /* ROT47 */ };  // ROT47 解码函数
    window.k = function(s) { /* ROT13 */ };  // ROT13 解码函数（变量名是 U+FFA0）
    
    window.check = function() { /* 密码校验 */ };
    
    // 对所有关键函数加上 debug condition（性能计数器 + 篡改检测）
    [Array, Array.prototype, String.prototype, Math, console, Reflect]
        .map(o => /* 提取所有函数 */)
        .flat().concat(check, eval)
        .forEach(instrument);  // 每个函数都加上 debug condition
    
    instrumentPrototype(Array.prototype);            // 数组方法 getter 劫持
    instrumentPrototypeOfPrototype(Array.prototype);  // Proxy 拦截
}
```

`anti()` 做了三件事：
1. 定义工具函数（r = ROT47, k = ROT13）和校验函数（check）
2. 给大量函数加 debug condition（通过 `instrument()`）
3. 修改 `Array.prototype` 的属性描述符和原型链（通过 `instrumentPrototype` 和 `instrumentPrototypeOfPrototype`）

#### check() —— 密码校验

这是最核心的函数。简化后的逻辑：

```javascript
function check() {
    // 反篡改检查：如果 step 不为 0 或 check 源码被修改，死循环
    // (通过 Function tagged template 实现，见第三章)
    
    try {
        window.step = 0;        // 重置计数器
        [0].step;               // 触发一次 Proxy → step=1
        
        const flag = (window.flag || '').split('');  // 待验证的 flag
        let i = 1337, j = 0;
        
        // ⚠️ 关键：pool 是 tagged template，U+FFA0(ROT13) 是标签函数！
        let pool = ROT13`?o>...\`5`;  // 先 ROT13
        pool = r(pool).split('');       // 再 ROT47，得到真正的字符池
        
        const double = Function.call`window.stepﾠ *= 2`;  // 障眼法，no-op
        
        while (!window.success) {
            // 用 step 计数器和伪随机数决定取 pool 中的哪个字符
            j = ((i || 1) * 16807 + window.step) % 2147483647;
            
            if (flag[0] == pool[j % pool.length] && window.step < 1000000) {
                // 匹配成功！移除已匹配的字符
                i = j;
                flag.shift();           // 移除 flag 第一个字符 → step++
                pool.splice(j % pool.length, 1);  // 移除 pool 中对应字符 → step++
                renderFrame();           // 渲染一帧 → step 大幅增加
                double();                // no-op（修改的是 window.stepﾠ）
                
                if (!pool.length && !flag.length) window.success = true;
            }
            // 不匹配 → 死循环（因为 success 永远不会变 true）
        }
    } catch(e) {}  // 静默吞掉所有错误
}
```

核心算法：
1. **pool** 是经过 ROT13+ROT47 解码后的 49 个字符
2. 用线性同余生成器（`j = (i * 16807 + step) % 2147483647`）产生伪随机数
3. `j % pool.length` 决定要检查 pool 中的哪个字符
4. 如果 flag 的当前第一个字符与 pool[j%len] 匹配，就从两者中都移除，并推进 step
5. 49 个字符全部匹配 → `success = true`
6. 如果 step 超过 1000000 还没匹配完 → 条件失败，死循环

#### unlock(flag) —— 解锁入口

```javascript
function unlock(flag) {
    // 1. 正则验证 flag 格式
    const match = /^CTF{([0-9a-zA-Z_@!?-]+)}$/.exec(flag);
    if (!match) return false;
    
    // 2. 提取花括号内的密码
    window.flag = match[1];
    
    // 3. 调用 check() 验证密码
    check();
    
    // 4. 如果验证通过，解密并显示
    if (!window.success) return;
    window.password = Array.from(window.flag).map(c => c.charCodeAt());
    const encrypted = JSON.parse(localStorage.content || '[]');
    const decrypted = encrypted.map((c, i) => c ^ password[i % password.length])
                               .map(String.fromCharCode).join('');
    alert("JS Safe opened! Content:" + decrypted);
}
```

注意正则表达式 `/^CTF{([0-9a-zA-Z_@!?-]+)}$/`：flag 只能包含字母、数字、下划线、`@`、`!`、`?`、`-`。这意味着 pool 解码后的所有字符都必须在这个范围内——这是验证 pool 计算是否正确的重要线索。

---

## 第三章：反调试机制深度解析

这一章我们逐个拆解题目的 8 个反调试/混淆机制，理解它们各自做什么、如何工作、以及它们如何协同构成 step 计数器。

> **核心发现**：这些"反调试机制"并不是要被"绕过"的障碍——它们是 step 计数器的**组成部分**，是 flag 校验算法的核心。正确理解并让它们正常运行，才能得到正确的 flag。

### 3.1 机制总览

| # | 机制 | 作用 | 对 step 的影响 |
|---|------|------|---------------|
| 1 | instrument() | 给函数加 debug condition（性能计数器） | 每次调用被 instrument 的函数，step += 函数源码长度 |
| 2 | instrumentPrototype() | 劫持 Array.prototype 方法为 getter | 每次访问数组方法（shift、splice等），step += 1 |
| 3 | instrumentPrototypeOfPrototype() | Proxy 拦截 Array 原型链 | 每次属性查找经过 Proxy，step += 1 |
| 4 | check() 自检 | 检测 check 源码是否被修改 | 无（防篡改，不影响 step） |
| 5 | HTML 长度校验 | 检测 HTML 是否被修改 | 无（防篡改，不影响 step） |
| 6 | double() 障眼法 | 看似翻倍 step，实际是 no-op | 无（障眼法） |
| 7 | U+FFA0 隐藏标识符 | 用不可见字符隐藏关键变量名 | 无（代码混淆） |
| 8 | tagged template ROT13 | 用标签模板隐式调用 ROT13 | 无（pool 编码） |

### 3.2 机制一：instrument()——debug condition 性能计数器

这是 step 计数器的**主要来源**。

```javascript
function instrument() {
    f = arguments[0];
    // 给函数 f 添加 debug condition
    debug(f, "window.c && function perf(){ const l = `" + f + "`.length; window.step += l; }() // ...");
    // 篡改检测
    debug(f, "document.documentElement.outerHTML.length !== 14347");
}
```

**这段代码做了什么？**

以 `renderFrame` 函数为例，调用 `instrument(renderFrame)` 后，相当于设置了：

```javascript
debug(renderFrame, "window.c && function perf(){ const l = `renderFrame函数的完整源码`.length; window.step += l; }()");
```

当 `renderFrame()` 被调用时：
1. Chrome 先执行 debug condition
2. condition 检查 `window.c`（true，由 anti() 设置）
3. 执行 `perf()` 函数：取 renderFrame 源码的长度（3858），加到 `window.step`
4. condition 返回 3858（truthy）→ Chrome 暂停执行
5. （在 DevTools 中你会看到断点；在自动化脚本中我们自动 resume）

每个被 instrument 的函数都会在每次调用时把**自己的源码长度**加到 step 上：

```
check          →  step += 914   (每次调用)
renderFrame    →  step += 3858  (每次调用)
r              →  step += 119   (每次调用)
shift          →  step += 34    (每次调用)
splice         →  step += 35    (每次调用)
...以此类推
```

**被 instrument 的函数列表**（第 302-304 行）：
```
Array 构造函数的所有方法
Array.prototype 的所有方法（shift、splice、map、join、forEach 等）
String.prototype 的所有方法（split、replace、toString 等）
Math 的所有方法（cos、sin、round、min 等）
console 的所有方法（log、clear 等）
Reflect 的所有方法
check 函数本身
eval 函数
```

### 3.3 机制二：instrumentPrototype()——原型链 getter 劫持

```javascript
function instrumentPrototype(o) {
    Object.entries(Object.getOwnPropertyDescriptors(o))
      .filter(p => p[1].value instanceof Function)
      .forEach(p => Object.defineProperty(o, p[0], {
        get: () => (step++) && p[1].value
      }));
}
```

**逐步解读**：

1. `Object.getOwnPropertyDescriptors(Array.prototype)` — 获取 Array.prototype 上所有属性的描述符
2. `.filter(p => p[1].value instanceof Function)` — 只保留函数类型的属性（shift、splice、map 等）
3. `.forEach(p => Object.defineProperty(...))` — 把每个函数属性替换为一个 getter

替换后的效果：当你访问 `[1,2,3].shift` 时：
1. JavaScript 引擎在数组实例上找不到 `shift` 属性
2. 上溯到 `Array.prototype`，找到了 getter
3. getter 执行：`step++`（返回旧值），然后 `旧值 && 原始shift函数`
4. 第一次调用时 step=0 → `0 && 原始函数` = 0 → **返回 0 而不是函数！**
5. 后续调用时 step≥1 → `step值 && 原始函数` = 原始函数 → 正常返回

> **核心发现**：getter 中的 `step++` 返回旧值。当 step=0 时，`0 && 函数` = 0（falsy），getter 返回 0 而不是原始函数。这意味着**在 step 被重置为 0 后，第一次访问数组方法会失败**！check() 函数通过先执行 `[0].step`（触发 Proxy 使 step 变为 1）来避免这个问题。

### 3.4 机制三：instrumentPrototypeOfPrototype()——Proxy 原型拦截

```javascript
function instrumentPrototypeOfPrototype(o) {
    const handler = {};
    Reflect.ownKeys(Reflect).forEach(h => 
        handler[h] = (a, b, c) => (step++) && Reflect[h](a, b, c)
    );
    Object.setPrototypeOf(o, new Proxy(Object.getPrototypeOf(o), handler));
}
```

**逐步解读**：

1. `Object.getPrototypeOf(Array.prototype)` — 获取 Array.prototype 的原型，即 `Object.prototype`
2. `new Proxy(Object.prototype, handler)` — 用 Proxy 包裹 Object.prototype
3. `Object.setPrototypeOf(Array.prototype, proxy)` — 把 Array.prototype 的原型设为这个 Proxy

Proxy 的 handler 拦截所有 Reflect 操作（get、set、has、deleteProperty 等），每次都 `step++`。

**效果**：当在数组上查找一个**不在 Array.prototype 自身属性上**的属性（比如 `[0].step`），引擎会继续上溯到 Array.prototype 的原型（即 Proxy），触发 Proxy 的 get 拦截器 → step++。

### 3.5 机制四：check() 函数自检

```javascript
// check() 函数的第一行（第 255 行）：
Function`[0].step; if (window.step == 0 || check.toString().length !== 914) while(true) debugger;`
```

**这段代码做了什么？**

1. `Function\`...\`` — 这是一个 tagged template，`Function` 是标签函数。`Function(strings)` 会创建一个新的 Function 对象
2. `[0].step` — 访问数组 `[0]` 的 `.step` 属性，触发 Proxy（step++）
3. `if (window.step == 0 || check.toString().length !== 914)` — 检查两个条件：
   - step 是否为 0（说明还没经过正常的初始化流程）
   - check 函数的源码长度是否为 914（检测是否被篡改）
4. `while(true) debugger;` — 如果检查失败，进入无限断点循环

**为什么 check.toString().length 是 914？** 因为 check() 函数的完整源码字符串长度就是 914 个字符。如果有人修改了 check() 的源码，长度会变化，这个检查就会触发。

### 3.6 机制五：HTML 长度校验

```javascript
// instrument() 中的第二个 debug condition（第 285 行）：
debug(f, "document.documentElement.outerHTML.length !== 14347");
```

每个被 instrument 的函数都有这个 debug condition。当 HTML 被修改（长度不等于 14347）时，condition 返回 true → Chrome 暂停执行（断点触发）。

这是防止你直接修改 HTML 文件来绕过反调试。

### 3.7 机制六：double() 障眼法

```javascript
// 第 264 行：
const double = Function.call`window.stepﾠ *= 2`;
```

**表面上看**：`double()` 会把 `window.step` 乘以 2。

**实际上**：

1. `Function.call\`window.stepﾠ *= 2\`` — 这是 tagged template
2. `Function.call(strings)` 创建一个新函数，函数体是 `window.stepﾠ *= 2`
3. 注意 `step` 后面的 `ﾠ`（U+FFA0），它是半角韩文填充符
4. 所以函数体实际是 `window.stepﾠ *= 2`（修改 `window["stepﾠ"]`），**不是** `window.step *= 2`
5. `window.step`（无 U+FFA0）和 `window.stepﾠ`（有 U+FFA0）是两个**完全不同的变量**
6. 调用 `double()` 只修改了 `window.stepﾠ`，对 `window.step` 没有任何影响

**这是一个精心设计的障眼法**——代码中有 `double()` 调用，让人以为 step 会被翻倍，但实际上什么都没发生。

### 3.8 机制七：U+FFA0 隐藏标识符

题目大量使用 U+FFA0（`ﾠ`）字符，它在编辑器中看起来像一个空格：

```javascript
window.cﾠ = true;    // 实际是 window["c" + U+FFA0]
let iﾠ = 1337;       // 实际是变量 i + U+FFA0
```

这些隐藏标识符使得：
- 代码阅读时容易忽略关键变量
- 搜索 "window.c" 找不到 "window.cﾠ"
- 以为 `window.c` 是一个布尔值，实际上是另一个完全不同的变量

### 3.9 机制八：tagged template 隐式 ROT13

```javascript
// 第 262 行：
let pool = ﾠ`?o>\`Wn0o0U0N?05o0ps}q0|mt\`ne\`us&400_pn0ss_mph_0\`5`;
```

**表面上看**：给 pool 赋一个普通的模板字符串。

**实际上**：`ﾠ`（U+FFA0）是 ROT13 函数的变量名。它作为 tagged template 的标签函数，对模板字符串的内容执行了 ROT13 变换。

所以这行代码等价于：
```javascript
let pool = rot13("?o>`Wn0o0U0N?05o0ps}q0|mt`ne`us&400_pn0ss_mph_0`5");
```

然后第 263 行又执行了 ROT47：
```javascript
pool = r(pool).split('');
```

最终 pool 经过 **ROT13 → ROT47** 两层变换：

```
原始字符串:  ?o>`Wn0o0U0N?05o0ps}q0|mt`ne`us&400_pn0ss_mph_0`5
     ↓ ROT13
中间结果:    ?b>`Ja0b0H0A?05b0cf}d0|zg`ar`hf&400_ca0ff_zcu_0`5
     ↓ ROT47
最终 pool:   n3m1y2_3_w_pn_d3_47N5_MK812C197Uc__042_770K4F0_1d
```

### 3.10 所有机制如何协同工作

现在我们理解了每个机制，来看看它们如何共同决定 flag 的计算：

```
anti(debug) 执行后:
  ├─ window.step = 0 (然后经过初始化变为 144)
  ├─ 所有函数被 instrument → debug condition 就绪
  ├─ Array.prototype 被 getter 劫持
  └─ Array.prototype 的原型被 Proxy 包裹

unlock("CTF{密码}") 执行时:
  ├─ 提取密码，设置 window.flag
  └─ 调用 check()
       ├─ window.step = 0; [0].step;  → step = 1 (Proxy 触发)
       ├─ pool = ROT13`...` → ROT47 → 得到 49 字符的字符池
       └─ while 循环 (49 次):
            ├─ j = (i * 16807 + step) % 2147483647  // 伪随机数
            ├─ 比较 flag[0] 与 pool[j % pool.length]
            ├─ 如果匹配:
            │    ├─ flag.shift()       → getter: step++   → Proxy: step++
            │    ├─ pool.splice(idx,1)  → getter: step++   → Proxy: step++
            │    ├─ renderFrame()       → debug condition: step += 3858
            │    │   └─ renderFrame 内部调用数十个 instrumented 函数
            │    │       每个都通过 debug condition 增加大量 step
            │    └─ double()            → no-op (修改的是 window.stepﾠ)
            └─ 如果不匹配: 死循环

最终: step 从 1 增长到 ~29529 (49 轮后)，小于 1000000 的上限
```

---

## 第四章：破解过程——从失败到成功

这一章记录了完整的破解过程，包括大量失败尝试和关键转折点。**失败记录是这篇 writeup 最有价值的部分**——它们展示了错误的思路是如何一步步被纠正的。

### 4.1 第一步：静态分析——阅读源码

首先阅读 HTML 源码（328 行），识别出关键信息：

**已识别**：
- 3 个核心函数：anti()、check()、unlock()
- 8 个反调试/混淆机制
- step 计数器是 flag 校验的核心
- U+FFA0 隐藏标识符的存在
- double() 是障眼法

**未识别（后来导致错误）**：
- pool 的 tagged template 语法中 `ﾠ` 是标签函数，意味着隐式的 ROT13 调用

### 4.2 关键转折点：发现 pool 的 tagged template

在分析第 262 行时：
```javascript
let pool = ﾠ`?o>\`Wn0o0U0N?05o0ps}q0|mt\`ne\`us&400_pn0ss_mph_0\`5`;
```

我正确地识别了 `ﾠ`（U+FFA0）是 ROT13 函数，也理解了它是 tagged template 的标签函数。**在最早期的版本中（v294-v295），我使用了包含 ROT13+ROT47 的正确 pool 计算**，通过 `window['\uFFA0'](String.fromCharCode(...))` 的方式。

### 4.3 最大的错误：误删 ROT13 步骤

在版本 v306 中，我"重新分析"源码时犯了一个致命错误。

**当时的推理过程**：
1. 看到第 262 行：`let pool = ﾠ\`...\`;`
2. 看到第 263 行：`pool = r(pool).split('');`
3. **错误推理**：我认为第 262 行只是赋值一个模板字符串，第 263 行才是唯一的变换（ROT47）
4. **忽略了**：`ﾠ` 不是普通空格，而是 ROT13 函数名，作为 tagged template 的标签在隐式调用

**错误结果**：
```
正确的 pool（ROT13+ROT47）: n3m1y2_3_w_pn_d3_47N5_MK812C197Uc__042_770K4F0_1d
错误的 pool（仅ROT47）:     n@m1(?_@_&_}n_d@_ADNB_M>E1?61FDUc__0A?_DD0>A90_1d
```

错误的 pool 包含 `(`、`&`、`}`、`>` 等字符，这些都不在 unlock 的正则表达式 `[0-9a-zA-Z_@!?-]` 范围内。

### 4.4 失败原因分析：为什么几十个版本全算错了

从 v306 到 v325（约 20 个版本），所有计算都基于错误的 pool。这期间产生了各种错误 flag：

```
v307: CTF{_U01@&dM?m_0_D9_}F_?6>@0nd1_N(@cDn>_A1_B1DEAA_D_?}  ← 包含 & } > ( @
v313: CTF{1M_A_6D9_}1A(@?_AND1_d@EUF_D?1c>B_d0nD_&0?>_0n_m@}  ← 包含 & } > ( @
v322: CTF{@__>&1?@?AB6m__>(1?UFc1DndD__D90DA@_Mn}__E0N01_dA}  ← 包含 & } > (
```

这些 flag 看起来"合理"，但全部包含不在正则范围内的字符。**如果我当时用 unlock() 的正则验证一下，就能立刻发现 pool 计算错误。**

还有一个系统性问题：**我过度关注了 step delta 的精确测量，而忽略了 pool 计算的正确性**。花了大量时间在 debug condition context vs 直接调用的 step 差异上，但真正的问题是 pool 本身就算错了。

### 4.5 最终突破：回归正确的 pool 计算

在 v326 中，我重新审视第 262 行，正确识别了 tagged template：

```javascript
// 使用和 check() 完全一样的方式计算 pool
INIT = "... var pool = window['\\uFFA0']`?o>\\`Wn0o0U0N?05o0ps}q0|mt\\`ne\\`us&400_pn0ss_mph_0\\`5`; "
       "pool = r(pool).split(''); ..."
```

**结果**：
```
Pool after ROT13: ?b>`Ja0b0H0A?05b0cf}d0|zg`ar`hf&400_ca0ff_zcu_0`5
Pool after ROT47: n3m1y2_3_w_pn_d3_47N5_MK812C197Uc__042_770K4F0_1d
```

所有字符都是 `[0-9a-zA-Z_]` 范围内的！通过了 unlock 的正则验证。

在 debug condition context 中运行正向计算，得到：
```
Flag: CTF{1M_4_C7F_p14y32_4N71_d38U9_721cK5_d0n7_w02K_0n_m3}
Verify: ok=True, matched=49, step=29529
```

### 4.6 另一个关键教训：不要清除 intervals

在 v327-v328 中，执行 `anti(debug)` 后，我习惯性地加入了清除 interval 的代码：

```python
# ❌ 错误操作
cdp.send("Runtime.evaluate", {
    "expression": "var _m=setTimeout(function(){},0);for(var _i=0;_i<=_m;_i++){clearInterval(_i)};",
})
```

这破坏了 anti-debug 机制。`anti()` 内部用 `setInterval(renderFrame, ...)` 启动了一个定时器，清除它后 step 计数器的行为发生了变化——从 144 变成了 1。

在 v333 中，我**去掉了所有多余操作**，只做两件事：
1. `anti(debug)`
2. `unlock(flag)`

**结果直接成功**。step=144，success=true，alert 弹出。

> **核心教训**：应该先尝试最简单的方式，而不是一开始就假设会崩溃然后做各种预防措施。过多的人为干预反而破坏了正常运行环境。

---

## 第五章：完整攻击复现

### 5.1 自动化脚本（Python + Playwright）

以下脚本会自动打开 Chrome、执行 anti(debug) 和 unlock()，并保持 Chrome 打开 60 秒让你看到 alert 弹框：

```python
#!/usr/bin/env python3
"""
JS Safe 6.0 自动化解题脚本
依赖: pip install playwright && playwright install chromium
"""
from playwright.sync_api import sync_playwright
import time

HTML_URL = "file:///你的路径/js_safe_6.html"
FLAG = "CTF{1M_4_C7F_p14y32_4N71_d38U9_721cK5_d0n7_w02K_0n_m3}"

alert_text = [None]

with sync_playwright() as p:
    browser = p.chromium.launch(
        headless=False,  # 显示浏览器窗口
        args=['--auto-open-devtools-for-tabs']
    )
    context = browser.new_context()
    page = context.new_page()

    def on_dialog(dialog):
        alert_text[0] = dialog.message
        print(f"*** ALERT: [{dialog.message}] ***")
        time.sleep(15)  # 让你看到弹框 15 秒
        dialog.accept()
    page.on("dialog", on_dialog)

    page.goto(HTML_URL, timeout=30000)
    page.wait_for_load_state("domcontentloaded")
    time.sleep(5)

    # 获取 CDP session
    cdp = context.new_cdp_session(page)
    
    # 启用 Debugger 并自动 resume
    cdp.send("Debugger.enable", {})
    def on_paused(params):
        try: cdp.send("Debugger.resume", {})
        except: pass
    cdp.on("Debugger.paused", on_paused)

    # 第一步：anti(debug)
    cdp.send("Runtime.evaluate", {
        "expression": "anti(debug)",
        "returnByValue": True,
        "includeCommandLineAPI": True,  # 提供 debug() 函数
        "timeout": 30000,
    })

    # 第二步：unlock(flag)
    cdp.send("Runtime.evaluate", {
        "expression": f'unlock("{FLAG}")',
        "returnByValue": True,
        "includeCommandLineAPI": True,
        "timeout": 60000,
    })

    time.sleep(5)
    print(f"Flag: {FLAG}")
    print(f"Alert: {alert_text[0]}")
    
    time.sleep(60)  # 保持 Chrome 打开
    browser.close()
```

### 5.2 手动验证步骤

如果你想手动验证：

1. 用 Chrome 打开 `js_safe_6.html`
2. 按 F12 打开 DevTools
3. 在 Console 中输入：
   ```javascript
   anti(debug);
   ```
4. 等待命令执行完成（Console 返回 undefined）
5. 在 Console 中输入：
   ```javascript
   unlock("CTF{1M_4_C7F_p14y32_4N71_d38U9_721cK5_d0n7_w02K_0n_m3}");
   ```
6. 看到 alert 弹框显示 "JS Safe opened! Content:"

---

## 第六章：如何防御

这道题是一个 CTF 逆向题，但从防御角度可以学到：

| 防御点 | 本题的弱点 | 改进建议 |
|--------|-----------|---------|
| 客户端校验 | check() 在浏览器中运行，所有逻辑可被逆向 | 敏感校验放在服务端 |
| 代码混淆 | U+FFA0 和 tagged template 只增加了阅读难度 | 使用专业混淆器（如 javascript-obfuscator） |
| 反调试 | debug condition + step 计数器可被正向模拟 | 结合服务端验证，不依赖纯客户端反调试 |
| 密钥存储 | flag 直接硬编码在字符池中 | 密钥不应出现在客户端代码中 |
| 算法强度 | 线性同余生成器（LCG）是可预测的伪随机 | 使用密码学安全的随机数生成器 |

**核心教训**：JavaScript 运行在客户端，所有代码对用户可见。无论使用多少混淆和反调试技术，只要攻击者有足够时间分析，就一定能逆向出逻辑。**真正的安全依赖于服务端验证，而不是客户端的隐藏。**

---

## 第七章：总结

### Flag

```
CTF{1M_4_C7F_p14y32_4N71_d38U9_721cK5_d0n7_w02K_0n_m3}
```

解码含义：**"I'M A CTF PLAYER, ANTI DEBUG TRACKS DON'T WORK ON ME"**（我是 CTF 选手，反调试追踪对我没用）

### 攻击链回顾

```
阅读源码 → 识别反调试机制 → 识别 U+FFA0 隐藏标识符 → 
识别 tagged template 隐式 ROT13 → 计算 pool (ROT13+ROT47) →
理解 step 计数器机制 → 正向模拟 check() while 循环 → 
计算正确 flag → 在 Chrome 中验证
```

### 关键洞察

1. **"反调试"机制不是障碍，而是算法的一部分**。step 计数器决定了 flag 的每个字符从 pool 的哪个位置取。绕过反调试反而会导致错误的 step 值。

2. **tagged template 是最隐蔽的 trick**。`ﾠ\`...\`` 看起来像普通赋值，实际上暗中了 ROT13 变换。一旦遗漏这一步，后面所有的计算都会产生包含非法字符的 flag。

3. **最简单的方式往往是最正确的**。最终成功的版本（v333）只做了两件事：`anti(debug)` 和 `unlock(flag)`。之前所有复杂的绕过、模拟、override 都是多余的。

### 工具链

| 工具 | 用途 |
|------|------|
| Chrome DevTools | 手动调试和验证 |
| Playwright | 浏览器自动化（Python） |
| CDP (Chrome DevTools Protocol) | 远程执行 JavaScript、控制调试器 |
| Python | 编写自动化脚本 |
| VS Code / 编辑器 | 静态分析源码 |

### 失败教训

| 错误 | 影响 | 教训 |
|------|------|------|
| 遗漏 tagged template 的 ROT13 | 20+ 个版本全部算错 flag | 仔细检查每一行代码的语法含义 |
| 清除 intervals | 改变了 step 初始值，check 无法通过 | 不要做多余操作，先试最简单的方式 |
| 过度关注 step delta 精度 | 忽略了 pool 计算的正确性 | 先验证基础假设，再优化细节 |
| 试图绕过反调试 | 破坏运行环境 | 理解机制比绕过机制更重要 |
