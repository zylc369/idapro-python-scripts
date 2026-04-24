---
description: GUI 自动化交互 — 截图、视觉识别、键鼠操作
---

使用 Read 工具读取 `$SCRIPTS_DIR/knowledge-base/gui-automation.md`，按照其中的规范执行用户的 GUI 操作请求。

如果 `$SCRIPTS_DIR` 未设置，从 `~/bw-ida-pro-analysis/config.json` 的 `scripts_dir` 字段读取。如果 `$BA_PYTHON` 未设置，从 `~/bw-ida-pro-analysis/env_cache.json` 的 `venv_python` 字段读取。如果 `$TASK_DIR` 未设置，创建 `~/bw-ida-pro-analysis/workspace/gui_<timestamp>/` 作为工作目录，截图放在其中的 `view/` 子目录下。
