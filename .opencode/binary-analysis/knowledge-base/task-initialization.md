# 任务初始化流程

> **按Step顺序执行，不可跳过，不可省略任何步骤。**

---

## Step 1：创建任务目录（强制 — 第一步）

**为什么必须用脚本**：任务目录命名规范为 `YYYYMMDD_HHMMSS_XXXX`（时间戳 + 4 位随机 hex），同时注册 sessionID → task_dir 映射用于压缩恢复。手动创建会违反命名规范且丢失映射。

**规则**：
- **禁止**使用 `workdir` 参数
- **禁止**在项目根目录下创建任何文件
- **禁止**手动 `mkdir` 创建任务目录

**命令**：

```
$PYTHON_CMD "$SHARED_DIR/scripts/create_task_dir.py"
```

`$PYTHON_CMD` 和 `$SHARED_DIR` 是 Plugin 注入到上下文中的值，不是 shell 环境变量——执行时替换为实际路径。

---

## Step 2：环境检测（强制 — 第二步）

检测逆向分析所需的工具链和依赖包。

**命令**：

```
$PYTHON_CMD "$SHARED_DIR/scripts/detect_env.py" --output "$TASK_DIR/env.json"
```

- 成功 → 继续 Step 3
- **失败 → 停下来告知用户，禁止继续**
- 环境检测结果缓存 24h 到 `~/bw-security-analysis/env_cache.json`，无需每次重新检测
- 可用 `--force` 强制重新检测

---

## Step 3：初始化 $BA_PYTHON（强制 — 第三步）

从缓存中提取 venv Python 路径。`$BA_PYTHON` 用于执行带第三方包的 Python 脚本。

**命令**：

```
$BA_PYTHON = $PYTHON_CMD -c "import json, os; cache_path = os.path.expanduser('~/bw-security-analysis/env_cache.json'); print(json.load(open(cache_path)).get('data', {}).get('venv_python', '$PYTHON_CMD')) if os.path.isfile(cache_path) else print('$PYTHON_CMD')"
```

> 将 `$PYTHON_CMD` 和 `$SHARED_DIR` 替换为 Plugin 注入的实际值后再执行。输出即为 `$BA_PYTHON` 路径。

**强制**：带第三方包的 Python 脚本必须用 `$BA_PYTHON`，禁止用系统 Python（仅 `detect_env.py` 例外）。

---

## 变量总结

初始化完成后，以下变量必须已初始化：

| 变量 | 来源 | 用途 |
|------|------|------|
| `$TASK_DIR` | Step 1 create_task_dir.py | 任务工作目录 |
| `$BA_PYTHON` | Step 3 env_cache.json | 带第三方包的 venv Python |

其他变量（`$AGENT_DIR`、`$SHARED_DIR`、`$IDAT`、`$PYTHON_CMD`）由 Plugin 在每轮注入，不在此流程中初始化。
