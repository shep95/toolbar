"""Mistral connector. Base URL https://api.mistral.ai/v1, auth ``Authorization: Bearer``.

Mistral's chat API is OpenAI-shaped but differs in a few parameter names and
rejects some OpenAI-only fields, which this connector adjusts.
"""

from __future__ import annotations

import copy
from typing import Any

from .base import Connector, OpenAIStyleStreamHandler, StreamHandler, UpstreamCall

# OpenAI-only fields Mistral does not accept.
_DROP_FIELDS = ("user", "stream_options", "logit_bias", "logprobs", "top_logprobs", "store", "metadata")


class MistralConnector(Connector):
    name = "mistral"
    native_paths = frozenset({"chat/completions", "embeddings", "fim/completions"})

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}

    def unified_request(self, body: dict[str, Any], model: str) -> UpstreamCall:
        upstream = copy.deepcopy(body)
        upstream["model"] = model
        if "max_completion_tokens" in upstream:
            upstream.setdefault("max_tokens", upstream["max_completion_tokens"])
            del upstream["max_completion_tokens"]
        if "seed" in upstream:
            upstream.setdefault("random_seed", upstream["seed"])
            del upstream["seed"]
        for key in _DROP_FIELDS:
            upstream.pop(key, None)
        return UpstreamCall(path="chat/completions", body=upstream, stream=bool(upstream.get("stream")))

    def unified_response(self, data: dict[str, Any]) -> dict[str, Any]:
        return data

    def unified_stream_handler(self, body: dict[str, Any]) -> StreamHandler:
        # Mistral always sends usage on its final content chunk, so nothing to strip.
        return OpenAIStyleStreamHandler()
