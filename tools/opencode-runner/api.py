"""OpenCode Go API 客户端 — 封装 OpenAI 兼容和 Anthropic 兼容两种请求格式"""

import requests

OPENCODE_GO_BASE_URL = "https://opencode.ai/zen/go/v1"

MODEL_REGISTRY: dict[str, dict] = {
    "glm-5.1":          {"endpoint": "chat/completions", "format": "openai"},
    "glm-5":            {"endpoint": "chat/completions", "format": "openai"},
    "kimi-k2.5":        {"endpoint": "chat/completions", "format": "openai"},
    "kimi-k2.6":        {"endpoint": "chat/completions", "format": "openai"},
    "deepseek-v4-pro":  {"endpoint": "chat/completions", "format": "openai"},
    "deepseek-v4-flash":{"endpoint": "chat/completions", "format": "openai"},
    "mimo-v2.5":        {"endpoint": "chat/completions", "format": "openai"},
    "mimo-v2.5-pro":    {"endpoint": "chat/completions", "format": "openai"},
    "minimax-m2.7":     {"endpoint": "messages",         "format": "anthropic"},
    "minimax-m2.5":     {"endpoint": "messages",         "format": "anthropic"},
    "qwen3.7-max":      {"endpoint": "messages",         "format": "anthropic"},
    "qwen3.6-plus":     {"endpoint": "messages",         "format": "anthropic"},
}


def parse_model_id(model_id: str) -> tuple[str, str]:
    """解析 OpenCode 格式 'provider/model' → (provider, model)"""
    parts = model_id.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"模型 ID 格式错误，应为 'provider/model': {model_id}")
    return parts[0], parts[1]


def validate_model(model_id: str) -> str:
    """验证并返回模型短名（不含 provider 前缀）"""
    _, model = parse_model_id(model_id)
    if model not in MODEL_REGISTRY:
        available = ", ".join(sorted(MODEL_REGISTRY.keys()))
        raise ValueError(f"未知模型: {model}，可用模型: {available}")
    return model


class OpenCodeGoClient:
    """对 OpenCode Go REST API 的薄封装，自动区分 OpenAI / Anthropic 格式。"""

    def __init__(self, api_key: str, base_url: str = OPENCODE_GO_BASE_URL):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def chat(self, model: str, messages: list[dict], timeout: int = 120) -> str:
        """发送聊天请求，返回模型回复纯文本。"""
        info = MODEL_REGISTRY.get(model)
        if info is None:
            raise ValueError(f"未知模型: {model}")

        url = f"{self.base_url}/{info['endpoint']}"

        if info["format"] == "openai":
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            return self._call_openai(url, headers, model, messages, timeout)

        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
        }
        return self._call_anthropic(url, headers, model, messages, timeout)

    def _call_openai(self, url, headers, model, messages, timeout):
        resp = requests.post(
            url,
            headers=headers,
            json={"model": model, "messages": messages, "stream": False},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, TypeError, IndexError) as exc:
            raise ValueError(f"OpenAI 响应格式异常: {data}") from exc

    def _call_anthropic(self, url, headers, model, messages, timeout):
        resp = requests.post(
            url,
            headers=headers,
            json={"model": model, "messages": messages, "max_tokens": 4096},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        try:
            return "".join(
                block["text"] for block in data["content"] if block["type"] == "text"
            )
        except (KeyError, TypeError) as exc:
            raise ValueError(f"Anthropic 响应格式异常: {data}") from exc
