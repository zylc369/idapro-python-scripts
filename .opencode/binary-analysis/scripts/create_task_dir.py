"""创建任务目录并注册 sessionID 映射

用法:
    python create_task_dir.py

行为:
    在 ~/bw-ida-pro-analysis/workspace/ 下创建时间戳+随机数命名的目录，
    同时注册 sessionID → task_dir 映射到 .task_sessions/{sessionID}.json，
    用于压缩后精确恢复。

    sessionID 从环境变量 SESSION_ID 读取（由 Plugin tool.execute.before hook 注入）。
    如果 SESSION_ID 为空，则只创建目录不注册映射。

依赖: 仅标准库（os, json, random, datetime）
"""

import os
import json
import random
from datetime import datetime

WORKSPACE = os.path.expanduser("~/bw-ida-pro-analysis/workspace")
TASK_SESSIONS = os.path.join(WORKSPACE, ".task_sessions")


def _register(session_id, task_dir):
    """注册 sessionID → task_dir 映射"""
    if not session_id:
        return
    os.makedirs(TASK_SESSIONS, exist_ok=True)
    mapping_file = os.path.join(TASK_SESSIONS, f"{session_id}.json")
    with open(mapping_file, "w") as f:
        json.dump({"task_dir": task_dir}, f)


def create():
    """创建新任务目录并注册映射"""
    os.makedirs(WORKSPACE, exist_ok=True)
    name = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + format(random.randint(0, 65535), "04x")
    task_dir = os.path.join(WORKSPACE, name)
    os.makedirs(task_dir, exist_ok=True)

    session_id = os.environ.get("SESSION_ID", "")
    _register(session_id, task_dir)

    print(task_dir)


if __name__ == "__main__":
    create()
