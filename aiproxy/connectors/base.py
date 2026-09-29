"""Connector contract shared by every upstream provider.

A connector is the only place that knows a provider's base URL, auth header,
request body shape and response shape. When a provider changes its API, the
change is absorbed here and nothing else in the proxy moves.

Two ways in:

* **Unified** — the client speaks OpenAI's chat-completions format to
  ``/v1/chat/completions`` with ``model="<provider>/<model>"``. The connector
  translates the request to the provider's format and the response back.
* **Native** — the client speaks the provider's own format to
  ``/<provider>/v1/<path>`` (so official SDKs work by changing ``base_url``).
  The body is forwarded untouched; the connector only reads usage.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any


class UnsupportedRequest(ValueError):
    """The request cannot be expressed for this provider. Maps to HTTP 400."""


@dataclass
class Usage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None

    @property
    def total(self) -> int | None:
        if self.total_tokens is not None:
            return self.total_tokens
        if self.input_tokens is None and self.output_tokens is None:
            return None
        return (self.input_tokens or 0) + (self.output_tokens or 0)


@dataclass
class UpstreamCall:
    path: str
    body: dict[str, Any]
    stream: bool = False


@dataclass
class SSEEvent:
    event: str | None
    data: str


class SSEParser:
    """Incremental server-sent-events parser. Feed raw bytes, get whole events."""

    def __init__(self) -> None:
        self._buffer = ""

    def feed(self, chunk: bytes) -> list[SSEEvent]:
        self._buffer += chunk.decode("utf-8", errors="replace").replace("\r\n", "\n")
        events: list[SSEEvent] = []
        while "\n\n" in self._buffer:
            block, self._buffer = self._buffer.split("\n\n", 1)
            event = self._parse_block(block)
            if event is not None:
                events.append(event)
        return events

    def flush(self) -> list[SSEEvent]:
        block, self._buffer = self._buffer, ""
        event = self._parse_block(block)
        return [event] if event is not None else []

    @staticmethod
    def _parse_block(block: str) -> SSEEvent | None:
        name: str | None = None
        data_lines: list[str] = []
        for line in block.split("\n"):
            if not line or line.startswith(":"):
                continue
            key, _, value = line.partition(":")
            if value.startswith(" "):
                value = value[1:]
            if key == "event":
                name = value
            elif key == "data":
                data_lines.append(value)
        if name is None and not data_lines:
            return None
        return SSEEvent(event=name, data="\n".join(data_lines))


def sse(data: str, event: str | None = None) -> bytes:
    prefix = f"event: {event}\n" if event else ""
    return f"{prefix}data: {data}\n\n".encode("utf-8")


def usage_from_dict(usage: Any) -> Usage:
    """Read token counts from any of the usage shapes our providers return."""
    if not isinstance(usage, dict):
        return Usage()

    def as_int(value: Any) -> int | None:
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    input_tokens = as_int(usage.get("prompt_tokens"))
    if input_tokens is None:
        input_tokens = as_int(usage.get("input_tokens"))
        if input_tokens is not None:
            # Anthropic reports cached prompt tokens separately.
            input_tokens += (as_int(usage.get("cache_creation_input_tokens")) or 0) + (
                as_int(usage.get("cache_read_input_tokens")) or 0
            )
    output_tokens = as_int(usage.get("completion_tokens"))
    if output_tokens is None:
        output_tokens = as_int(usage.get("output_tokens"))
    return Usage(input_tokens=input_tokens, output_tokens=output_tokens, total_tokens=as_int(usage.get("total_tokens")))


@dataclass
class StreamState:
    usage: Usage = field(default_factory=Usage)
    model: str | None = None
    error: str | None = None


class StreamHandler:
    """Consumes upstream SSE events, tracks usage, and decides what to emit.

    ``handle`` returns the bytes to send to the client for one event. Native
    passthrough handlers re-emit each event unchanged; unified handlers
    translate it. ``finish`` returns any trailing bytes.
    """

    def __init__(self) -> None:
        self.state = StreamState()

    def handle(self, event: SSEEvent) -> bytes:
        raise NotImplementedError

    def finish(self) -> bytes:
        return b""


class OpenAIStyleStreamHandler(StreamHandler):
    """For OpenAI and Mistral chat streams (``data: {json}`` ... ``data: [DONE]``)."""

    def __init__(self, drop_usage_only_chunks: bool = False, model_prefix: str | None = None) -> None:
        super().__init__()
        self.drop_usage_only_chunks = drop_usage_only_chunks
        self.model_prefix = model_prefix

    def handle(self, event: SSEEvent) -> bytes:
        if event.data == "[DONE]":
            return sse("[DONE]")
        try:
            payload = json.loads(event.data)
        except ValueError:
            return sse(event.data, event.event)
        if not isinstance(payload, dict):
            return sse(event.data, event.event)
        if payload.get("error"):
            self.state.error = json.dumps(payload["error"])[:500]
        if payload.get("model"):
            self.state.model = payload["model"]
        # Responses API wraps usage inside `response`.
        usage = payload.get("usage") or (payload.get("response") or {}).get("usage")
        if usage:
            parsed = usage_from_dict(usage)
            if parsed.total is not None:
                self.state.usage = parsed
        if self.drop_usage_only_chunks and payload.get("usage") and not payload.get("choices"):
            return b""
        return sse(event.data, event.event)


def openai_chat_completion(
    *, id: str, model: str, text: str, finish_reason: str | None, usage: Usage
) -> dict[str, Any]:
    return {
        "id": id,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": finish_reason,
            }
        ],
        "usage": {
            "prompt_tokens": usage.input_tokens or 0,
            "completion_tokens": usage.output_tokens or 0,
            "total_tokens": usage.total or 0,
        },
    }


class Connector:
    """Base class. Subclasses fill in the provider specifics."""

    name: str = ""
    # Paths (relative to the provider's /v1) clients may call natively.
    native_paths: frozenset[str] = frozenset()

    def __init__(self, base_url: str, api_key: str | None) -> None:
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def headers(self) -> dict[str, str]:
        """Headers for the upstream call. Built from scratch: client headers are never forwarded."""
        raise NotImplementedError

    # --- unified (OpenAI chat format in, OpenAI chat format out) ---------
    def unified_request(self, body: dict[str, Any], model: str) -> UpstreamCall:
        raise NotImplementedError

    def unified_response(self, data: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def unified_stream_handler(self, body: dict[str, Any]) -> StreamHandler:
        raise NotImplementedError

    # --- native passthrough ----------------------------------------------
    def native_request(self, path: str, body: dict[str, Any]) -> UpstreamCall:
        if path not in self.native_paths:
            raise UnsupportedRequest(
                f"endpoint '{path}' is not available for {self.name}; allowed: {', '.join(sorted(self.native_paths))}"
            )
        return UpstreamCall(path=path, body=body, stream=bool(body.get("stream")))

    def native_stream_handler(self) -> StreamHandler:
        return OpenAIStyleStreamHandler()

    # --- usage --------------------------------------------------------------
    def extract_usage(self, data: Any) -> Usage:
        if not isinstance(data, dict):
            return Usage()
        return usage_from_dict(data.get("usage"))
