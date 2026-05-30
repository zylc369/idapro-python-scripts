"""多轮对话 HTTP 服务器 — 提供命令式 JSON API 供调用方与目标模型交互"""

import json
import uuid
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

from api import OpenCodeGoClient

logger = logging.getLogger(__name__)


class Session:
    """维护与目标模型的对话历史"""

    def __init__(self):
        self.id = uuid.uuid4().hex[:12]
        self.history: list[dict] = []


class RunnerState:
    """服务器全局运行状态"""

    def __init__(self, client: OpenCodeGoClient, target_model: str):
        self.client = client
        self.target_model = target_model
        self.sessions: dict[str, Session] = {}
        self.current_session: Session | None = None

    def ensure_session(self) -> Session:
        if self.current_session is None:
            self.new_session()
        return self.current_session

    def new_session(self) -> Session:
        session = Session()
        self.sessions[session.id] = session
        self.current_session = session
        return session

    def send_prompt(self, content: str) -> str:
        """向目标模型发送提示词，自动维护历史并返回回复"""
        session = self.ensure_session()
        pending = {"role": "user", "content": content}
        reply = self.client.chat(self.target_model, session.history + [pending])
        session.history.append(pending)
        session.history.append({"role": "assistant", "content": reply})
        return reply


def _create_handler(state: RunnerState):
    """生成请求处理器类（闭包捕获 state）"""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self._json_ok(
                    {
                        "status": "ok",
                        "target_model": state.target_model,
                        "sessions": len(state.sessions),
                        "current_session": (
                            state.current_session.id if state.current_session else None
                        ),
                    }
                )
            else:
                self._json_error("未找到", 404)

        def do_POST(self):
            body = self._read_body()
            try:
                result = self._dispatch(body)
                if result is not None:
                    self._json_ok(result)
            except Exception as exc:
                logger.exception("请求处理失败")
                self._json_error(str(exc), 500)

        def _dispatch(self, body: dict):
            if self.path == "/prompt":
                return self._handle_prompt(body)
            if self.path == "/session/new":
                return self._handle_new_session()
            if self.path == "/shutdown":
                return self._handle_shutdown()
            self._json_error("未找到", 404)
            return None

        def _handle_prompt(self, body: dict) -> dict:
            content = body.get("content")
            if not content:
                raise ValueError("缺少 content 字段")
            reply = state.send_prompt(content)
            return {"content": reply}

        def _handle_new_session(self) -> dict:
            session = state.new_session()
            return {"session_id": session.id}

        def _handle_shutdown(self) -> dict:
            Thread(target=self.server.shutdown, daemon=True).start()
            return {"status": "ok"}

        def _read_body(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            return json.loads(self.rfile.read(length))

        def _json_ok(self, data: dict):
            self._write_json(200, data)

        def _json_error(self, message: str, status: int):
            self._write_json(status, {"error": message})

        def _write_json(self, status: int, data: dict):
            payload = json.dumps(data, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt, *args):
            logger.info(fmt, *args)

    return Handler


def run_server(host: str, port: int, state: RunnerState):
    """阻塞式启动 HTTP 服务器，直到 /shutdown 或 KeyboardInterrupt"""
    httpd = HTTPServer((host, port), _create_handler(state))
    logger.info("服务器启动: http://%s:%d", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        logger.info("服务器已关闭")
