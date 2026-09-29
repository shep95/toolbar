"""Anthropic connector.

Base URL https://api.anthropic.com/v1, auth ``x-api-key`` plus a required
``anthropic-version`` header. The Messages API differs from OpenAI's chat
format (system prompt is a top-level field, ``max_tokens`` is required,
content blocks, different stop reasons and streaming events), so the unified
path translates in both directions.
"""

from __future__ import annotations

import json
import time
from typing import Any

from .base import (
    Connector,
    SSEEvent,
    StreamHandler,
    UnsupportedRequest,
    UpstreamCall,
    Usage,
    openai_chat_completion,
    sse,
    usage_from_dict,
)

_STOP_REASONS = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "max_tokens": "length",
    "tool_use": "tool_calls",
    "refusal": "content_filter",
    "pause_turn": "stop",
}

# OpenAI features with no faithful translation. Clients that need them should
# call the native endpoint /anthropic/v1/messages instead.
_UNSUPPORTED_FIELDS = ("tools", "tool_choice", "functions", "function_call", "response_format", "logprobs", "top_logprobs")


def _text_only(content: Any, role: str) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = []
        for part in content:
            if not isinstance(part, dict) or part.get("type") != "text" or not isinstance(part.get("text"), str):
                raise UnsupportedRequest(f"{role} messages may only contain text")
            texts.append(part["text"])
        return "\n".join(texts)
    raise UnsupportedRequest(f"{role} message content must be a string or a list of text parts")


def _convert_content(content: Any) -> str | list[dict[str, Any]]:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        raise UnsupportedRequest("message content must be a string or a list of content parts")
    blocks: list[dict[str, Any]] = []
    for part in content:
        if not isinstance(part, dict):
            raise UnsupportedRequest("content parts must be objects")
        kind = part.get("type")
        if kind == "text":
            blocks.append({"type": "text", "text": str(part.get("text", ""))})
        elif kind == "image_url":
            image = part.get("image_url")
            url = image.get("url") if isinstance(image, dict) else image
            if not isinstance(url, str) or not url:
                raise UnsupportedRequest("image_url parts need a url")
            if url.startswith("data:"):
                header, _, data = url.partition(",")
                media_type = header[len("data:") :].split(";")[0]
                blocks.append({"type": "image", "source": {"type": "base64", "media_type": media_type, "data": data}})
            else:
                blocks.append({"type": "image", "source": {"type": "url", "url": url}})
        else:
            raise UnsupportedRequest(f"content part type '{kind}' is not supported for anthropic via the unified endpoint")
    return blocks


class AnthropicConnector(Connector):
    name = "anthropic"
    native_paths = frozenset({"messages"})

    def __init__(self, base_url: str, api_key: str | None, version: str, default_max_tokens: int) -> None:
        super().__init__(base_url, api_key)
        self.version = version
        self.default_max_tokens = default_max_tokens

    def headers(self) -> dict[str, str]:
        return {
            "x-api-key": self._api_key or "",
            "anthropic-version": self.version,
            "Content-Type": "application/json",
        }

    # --- unified ---------------------------------------------------------
    def unified_request(self, body: dict[str, Any], model: str) -> UpstreamCall:
        for key in _UNSUPPORTED_FIELDS:
            if body.get(key):
                raise UnsupportedRequest(
                    f"'{key}' is not supported for anthropic via /v1/chat/completions; use /anthropic/v1/messages"
                )
        if body.get("n", 1) != 1:
            raise UnsupportedRequest("anthropic returns a single choice; n must be 1")

        system_parts: list[str] = []
        messages: list[dict[str, Any]] = []
        for message in body["messages"]:
            if not isinstance(message, dict):
                raise UnsupportedRequest("each message must be an object")
            role = message.get("role")
            if role in ("system", "developer"):
                system_parts.append(_text_only(message.get("content"), role))
            elif role in ("user", "assistant"):
                if message.get("tool_calls"):
                    raise UnsupportedRequest("tool calls are not supported for anthropic via the unified endpoint")
                messages.append({"role": role, "content": _convert_content(message.get("content"))})
            else:
                raise UnsupportedRequest(f"message role '{role}' is not supported for anthropic via the unified endpoint")
        if not messages:
            raise UnsupportedRequest("at least one user or assistant message is required")

        upstream: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": body.get("max_completion_tokens") or body.get("max_tokens") or self.default_max_tokens,
        }
        if system_parts:
            upstream["system"] = "\n\n".join(system_parts)
        for key in ("temperature", "top_p"):
            if body.get(key) is not None:
                upstream[key] = body[key]
        stop = body.get("stop")
        if stop:
            upstream["stop_sequences"] = [stop] if isinstance(stop, str) else list(stop)
        if isinstance(body.get("user"), str):
            upstream["metadata"] = {"user_id": body["user"]}
        stream = bool(body.get("stream"))
        if stream:
            upstream["stream"] = True
        return UpstreamCall(path="messages", body=upstream, stream=stream)

    def unified_response(self, data: dict[str, Any]) -> dict[str, Any]:
        text = "".join(
            block.get("text", "") for block in data.get("content") or [] if isinstance(block, dict) and block.get("type") == "text"
        )
        return openai_chat_completion(
            id=data.get("id", ""),
            model=data.get("model", ""),
            text=text,
            finish_reason=_STOP_REASONS.get(data.get("stop_reason") or "", "stop"),
            usage=self.extract_usage(data),
        )

    def unified_stream_handler(self, body: dict[str, Any]) -> StreamHandler:
        include_usage = bool((body.get("stream_options") or {}).get("include_usage"))
        return AnthropicToOpenAIStream(include_usage=include_usage)

    # --- native ----------------------------------------------------------
    def native_stream_handler(self) -> StreamHandler:
        return AnthropicNativeStream()


class _AnthropicStreamBase(StreamHandler):
    def _track(self, event: SSEEvent) -> dict[str, Any] | None:
        try:
            payload = json.loads(event.data)
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None
        kind = payload.get("type") or event.event
        if kind == "message_start":
            message = payload.get("message") or {}
            self.state.model = message.get("model")
            self.state.usage = usage_from_dict(message.get("usage"))
        elif kind == "message_delta":
            delta_usage = usage_from_dict(payload.get("usage"))
            if delta_usage.output_tokens is not None:
                self.state.usage = Usage(
                    input_tokens=self.state.usage.input_tokens,
                    output_tokens=delta_usage.output_tokens,
                )
        elif kind == "error":
            self.state.error = json.dumps(payload.get("error"))[:500]
        return payload


class AnthropicNativeStream(_AnthropicStreamBase):
    def handle(self, event: SSEEvent) -> bytes:
        self._track(event)
        return sse(event.data, event.event)


class AnthropicToOpenAIStream(_AnthropicStreamBase):
    """Translates Anthropic Messages stream events into OpenAI chat.completion.chunk events."""

    def __init__(self, include_usage: bool) -> None:
        super().__init__()
        self.include_usage = include_usage
        self.message_id = ""
        self.created = 0
        self.done = False

    def _chunk(self, delta: dict[str, Any], finish_reason: str | None = None) -> bytes:
        return sse(
            json.dumps(
                {
                    "id": self.message_id,
                    "object": "chat.completion.chunk",
                    "created": self.created,
                    "model": self.state.model or "",
                    "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
                }
            )
        )

    def handle(self, event: SSEEvent) -> bytes:
        payload = self._track(event)
        if payload is None:
            return b""
        kind = payload.get("type") or event.event
        if kind == "message_start":
            self.message_id = (payload.get("message") or {}).get("id", "")
            self.created = int(time.time())
            return self._chunk({"role": "assistant", "content": ""})
        if kind == "content_block_delta":
            delta = payload.get("delta") or {}
            if delta.get("type") == "text_delta":
                return self._chunk({"content": delta.get("text", "")})
            return b""
        if kind == "message_delta":
            stop_reason = (payload.get("delta") or {}).get("stop_reason")
            if stop_reason:
                return self._chunk({}, _STOP_REASONS.get(stop_reason, "stop"))
            return b""
        if kind == "message_stop":
            return self._final()
        if kind == "error":
            return sse(json.dumps({"error": payload.get("error")}))
        return b""  # ping, content_block_start/stop

    def _final(self) -> bytes:
        if self.done:
            return b""
        self.done = True
        out = b""
        if self.include_usage:
            usage = self.state.usage
            out += sse(
                json.dumps(
                    {
                        "id": self.message_id,
                        "object": "chat.completion.chunk",
                        "created": self.created,
                        "model": self.state.model or "",
                        "choices": [],
                        "usage": {
                            "prompt_tokens": usage.input_tokens or 0,
                            "completion_tokens": usage.output_tokens or 0,
                            "total_tokens": usage.total or 0,
                        },
                    }
                )
            )
        return out + sse("[DONE]")

    def finish(self) -> bytes:
        return b"" if self.done or self.state.error else self._final()
