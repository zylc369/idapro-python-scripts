环境信息由 Plugin 在每轮注入（见系统提示中的"环境信息"段）。在首次需要执行脚本的 bash 命令中，从环境信息提取路径赋值：

| 变量 | 来源 | 说明 |
|------|------|------|
| `$AGENT_DIR` | 环境信息"Agent 目录 ($AGENT_DIR)" | 本 Agent 的工具目录 |
| `$SHARED_DIR` | 环境信息"共享目录 ($SHARED_DIR)" | 共享分析能力目录 |
| `$IDAT` | 环境信息"IDA Pro"路径 + `/idat` | 需检查文件存在性 |
| `$BA_PYTHON` | 阶段 0 env.json 的 `venv_python` | 带第三方包的 venv Python |

**强制**：带第三方包的 Python 脚本必须用 `$BA_PYTHON`，禁止用系统 Python（仅 `detect_env.py` 例外）。
