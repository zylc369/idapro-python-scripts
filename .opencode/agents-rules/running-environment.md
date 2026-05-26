> 动态环境信息由 Plugin 注入到上下文中。环境检测见"阶段 0"。

**Python 命令**：统一使用 `$PYTHON_CMD`（由 Plugin 检测并注入，值为 `python3` 或 `python`）。所有脚本调用和内联 Python 命令都使用 `$PYTHON_CMD`，不需要区分平台。

**BA_PYTHON vs PYTHON_CMD**：`$PYTHON_CMD` 是系统 Python（无第三方包依赖），`$BA_PYTHON` 是 venv Python（有第三方包依赖）。
