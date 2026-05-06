在阶段 A 之前必须按顺序执行以下 3 步。详细流程见 `$SHARED_DIR/knowledge-base/task-initialization.md`。

1. **创建任务目录**：`TASK_DIR=$(python3 "$SHARED_DIR/scripts/create_task_dir.py")`
2. **环境检测**：`python3 "$SHARED_DIR/scripts/detect_env.py" --output "$TASK_DIR/env.json"`
3. **初始化 $BA_PYTHON**：从 `~/bw-security-analysis/env_cache.json` 提取 `venv_python`

环境检测失败 → **停下来告知用户，禁止继续**。环境检测结果缓存 24h（`~/bw-security-analysis/env_cache.json`），无需每次重新检测。
