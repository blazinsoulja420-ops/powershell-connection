from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class ProviderError(RuntimeError):
    pass


class LMStudioProvider:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.base_url = str(cfg["base_url"]).rstrip("/")
        self.model = str(cfg["model"])
        self.timeout = int(cfg.get("timeout_seconds", 180))
        self.temperature = float(cfg.get("temperature", 0.1))
        self.max_tokens = int(cfg.get("max_tokens", 4096))
        env_name = cfg.get("api_token_env")
        self.api_token = os.environ.get(env_name) if env_name else None

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ProviderError(f"LM Studio HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise ProviderError(f"LM Studio connection failed: {exc}") from exc

    def list_models(self) -> list[str]:
        data = self._request("GET", "/models")
        return [str(item.get("id")) for item in data.get("data", []) if item.get("id")]

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        data = self._request("POST", "/chat/completions", payload)
        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"Unexpected LM Studio response shape: {data}") from exc
