# 任务初始化流程

> 所有分析 agent 的阶段 0 共享流程。**不可跳过，不可省略任何步骤。**

---

## Step 1：创建任务目录（强制 — 第一步）

**为什么必须用脚本**：任务目录命名规范为 `YYYYMMDD_HHMMSS_XXXX`（时间戳 + 4 位随机 hex），同时注册 sessionID → task_dir 映射用于压缩恢复。手动创建会违反命名规范且丢失映射。

**规则**：
- **禁止**使用 `workdir` 参数
- **禁止**在项目根目录下创建任何文件
- **禁止**手动 `mkdir` 创建任务目录
- 所有中间文件写入 `~/bw-security-analysis/workspace/<task_id>/`

**命令**：

```bash
TASK_DIR=$(python3 "$SHARED_DIR/scripts/create_task_dir.py")
```

脚本输出目录绝对路径到 stdout，直接赋值给 `TASK_DIR`。sessionID 从环境变量 `SESSION_ID` 读取（由 Plugin `tool.execute.before` hook 自动注入）。

---

## Step 2：环境检测（强制 — 第二步）

检测逆向分析所需的工具链和依赖包。

**命令**：

```bash
# binary-analysis agent
python3 "$SHARED_DIR/scripts/detect_env.py" --output "$TASK_DIR/env.json"

# mobile-analysis agent
python3 "$SHARED_DIR/scripts/detect_env.py" --agent mobile-analysis --output "$TASK_DIR/env.json"
```

- 成功 → 继续 Step 3
- **失败 → 停下来告知用户，禁止继续**
- 环境检测结果缓存 24h 到 `~/bw-security-analysis/env_cache.json`，无需每次重新检测
- 可用 `--force` 强制重新检测

---

## Step 3：初始化 $BA_PYTHON（强制 — 第三步）

从缓存中提取 venv Python 路径。`$BA_PYTHON` 用于执行带第三方包的 Python 脚本。

**命令**：

```bash
BA_PYTHON=$(python3 -c "
import json, os
cache_path = os.path.expanduser('~/bw-security-analysis/env_cache.json')
if os.path.isfile(cache_path):
    cache = json.load(open(cache_path))
    print(cache.get('data', {}).get('venv_python', 'python3'))
else:
    print('python3')
")
```

**强制**：带第三方包的 Python 脚本必须用 `$BA_PYTHON`，禁止用系统 Python（仅 `detect_env.py` 例外）。

---

## 变量总结

阶段 0 完成后，以下变量必须已初始化：

| 变量 | 来源 | 用途 |
|------|------|------|
| `$TASK_DIR` | Step 1 create_task_dir.py | 任务工作目录 |
| `$BA_PYTHON` | Step 3 env_cache.json | 带第三方包的 venv Python |

其他变量（`$AGENT_DIR`、`$SHARED_DIR`、`$IDAT`）由 Plugin 在每轮注入，不在此流程中初始化。
