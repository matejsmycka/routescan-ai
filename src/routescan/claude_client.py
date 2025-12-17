import os
from typing import Iterable, Literal

from anthropic import Anthropic


Role = Literal["user", "assistant", "system"]


class ClaudeClient:
    def __init__(self, model: str = "claude-3-5-sonnet-latest", api_key: str | None = None):
        key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not key:
            msg = "ANTHROPIC_API_KEY is not set."
            raise RuntimeError(msg)
        self._client = Anthropic(api_key=key)
        self._model = model

    def complete(self, messages: Iterable[tuple[Role, str]], max_tokens: int = 2000) -> str:
        payload = [
            {"role": role, "content": [{"type": "text", "text": text}]}
            for role, text in messages
        ]
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            messages=payload,
        )
        parts = []
        for content in resp.content:
            if content.type == "text":
                parts.append(content.text)
        return "".join(parts)


