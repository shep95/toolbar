"""OpenAI connector. Base URL https://api.openai.com/v1, auth ``Authorization: Bearer``."""

from __future__ import annotations

import copy
from typing import Any

from .base import Connector, OpenAIStyleStreamHandler, StreamHandler, UpstreamCall


class OpenAIConnector(Connector):
    name = "openai"
    native_paths = frozenset({"chat/completions", "completions", "embeddings", "responses"})

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}

    def unified_request(self, body: dict[str, Any], model: str) -> UpstreamCall:
        upstream = copy.deepcopy(body)
        upstream["model"] = model
        stream = bool(upstream.get("stream"))
        if stream:
            # Ask OpenAI to report token usage at the end of the stream so billing
            # can record it. If the client did not ask for it, the extra chunk is
            # stripped again before it reaches them.
            options = dict(upstream.get("stream_options") or {})
            options["include_usage"] = True
            upstream["stream_options"] = options
        return UpstreamCall(path="chat/completions", body=upstream, stream=stream)

    def unified_response(self, data: dict[str, Any]) -> dict[str, Any]:
        return data  # already OpenAI format

    def unified_stream_handler(self, body: dict[str, Any]) -> StreamHandler:
        client_wants_usage = bool((body.get("stream_options") or {}).get("include_usage"))
        return OpenAIStyleStreamHandler(drop_usage_only_chunks=not client_wants_usage)
