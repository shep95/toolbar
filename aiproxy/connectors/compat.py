"""Connector for every provider that speaks OpenAI's chat-completions API.

Most of the world's model APIs (OpenAI, Google Gemini, xAI, DeepSeek, Qwen,
Kimi, GLM, Mistral, Upstage, Sarvam...) accept OpenAI-format requests at their
own base URL. They differ only in URL, auth header and a few parameter quirks,
which a ``ProviderSpec`` in ``catalog.py`` describes.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
import orjson

from .base import Connector, OpenAIStyleStreamHandler, StreamHandler, UpstreamCall


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    display_name: str
    country: str  # ISO 3166 alpha-2 of the company's home country
    base_url: str
    native_paths: frozenset[str] = frozenset({"chat/completions"})
    lists_models: bool = False
    # "bearer": Authorization: Bearer <key>
    # "header:<Name>": <Name>: <key>
    # "scheme:<Scheme>": Authorization: <Scheme> <key>
    # "oauth:gigachat": exchange the key for a short-lived token first
    auth: str = "bearer"
    # Ask for token usage at the end of streams (stream_options.include_usage)
    # and hide the extra usage-only chunk from clients that did not ask.
    inject_stream_usage: bool = False
    rename_fields: tuple[tuple[str, str], ...] = ()
    drop_fields: tuple[str, ...] = ()
    # Extra headers read from the environment: ((header, ENV_VAR), ...).
    env_headers: tuple[tuple[str, str], ...] = ()
    # Prefix model IDs with a value from the environment (Yandex folder URIs).
    model_template_env: str = ""
    verified: bool = True
    notes: str = ""
    docs: str = ""
    extra: dict[str, str] = field(default_factory=dict)


class OpenAICompatibleConnector(Connector):
    unified_response_is_native = True

    def __init__(self, spec: ProviderSpec, base_url: str, api_key: str | None, env: dict[str, str | None]):
        super().__init__(base_url, api_key)
        self.spec = spec
        self.name = spec.name
        self.display_name = spec.display_name
        self.country = spec.country
        self.verified = spec.verified
        self.native_paths = spec.native_paths
        self.lists_models = spec.lists_models
        self._static_headers = {header: value for header, var in spec.env_headers if (value := env.get(var))}
        self._model_template = env.get(spec.model_template_env) if spec.model_template_env else None
        self._token: str | None = None
        self._token_expires = 0.0
        self._token_lock = asyncio.Lock()
        self._oauth_url = spec.extra.get("oauth_url", "")
        self._oauth_scope = env.get(f"{spec.name.upper()}_SCOPE") or spec.extra.get("oauth_scope", "")

    async def headers(self, http: httpx.AsyncClient) -> dict[str, str]:
        auth = self.spec.auth
        headers = {"Content-Type": "application/json", **self._static_headers}
        if auth == "bearer":
            headers["Authorization"] = f"Bearer {self._api_key}"
        elif auth.startswith("header:"):
            headers[auth.split(":", 1)[1]] = self._api_key or ""
        elif auth.startswith("scheme:"):
            headers["Authorization"] = f"{auth.split(':', 1)[1]} {self._api_key}"
        elif auth.startswith("oauth:"):
            headers["Authorization"] = f"Bearer {await self._oauth_token(http)}"
        else:  # pragma: no cover - catalog is static
            raise ValueError(f"unknown auth style {auth}")
        return headers

    async def _oauth_token(self, http: httpx.AsyncClient) -> str:
        """GigaChat-style client-credentials exchange, cached until shortly before expiry."""
        if self._token and time.time() < self._token_expires:
            return self._token
        async with self._token_lock:
            if self._token and time.time() < self._token_expires:
                return self._token
            response = await http.post(
                self._oauth_url,
                data={"scope": self._oauth_scope},
                headers={
                    "Authorization": f"Basic {self._api_key}",
                    "RqUID": str(uuid.uuid4()),
                    "Accept": "application/json",
                },
            )
            response.raise_for_status()
            payload = orjson.loads(response.content)
            self._token = payload["access_token"]
            expires_ms = payload.get("expires_at") or (time.time() + 1500) * 1000
            self._token_expires = expires_ms / 1000 - 60
            return self._token

    def _model(self, model: str) -> str:
        if self._model_template and "://" not in model:
            return f"gpt://{self._model_template}/{model}"
        return model

    def _adapt(self, body: dict[str, Any]) -> dict[str, Any]:
        # Shallow copy: only top-level keys change, so nested message arrays
        # (which can be megabytes) are never duplicated.
        upstream = dict(body)
        for old, new in self.spec.rename_fields:
            if old in upstream:
                upstream.setdefault(new, upstream[old])
                del upstream[old]
        for key in self.spec.drop_fields:
            upstream.pop(key, None)
        return upstream

    def unified_request(self, body: dict[str, Any], model: str) -> UpstreamCall:
        upstream = self._adapt(body)
        upstream["model"] = self._model(model)
        stream = bool(upstream.get("stream"))
        if stream and self.spec.inject_stream_usage:
            options = dict(upstream.get("stream_options") or {})
            options["include_usage"] = True
            upstream["stream_options"] = options
        return UpstreamCall(path="chat/completions", body=upstream, stream=stream)

    def native_request(self, path: str, body: dict[str, Any]) -> UpstreamCall:
        call = super().native_request(path, body)
        if isinstance(body.get("model"), str) and self._model_template:
            call.body = {**body, "model": self._model(body["model"])}
        return call

    def unified_response(self, data: dict[str, Any]) -> dict[str, Any]:
        return data  # already OpenAI format

    def unified_stream_handler(self, body: dict[str, Any]) -> StreamHandler:
        client_wants_usage = bool((body.get("stream_options") or {}).get("include_usage"))
        return OpenAIStyleStreamHandler(
            drop_usage_only_chunks=self.spec.inject_stream_usage and not client_wants_usage,
            secrets=self.secrets,
        )
