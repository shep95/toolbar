"""Connector registry: one connector per upstream provider.

To add a provider, write a ``Connector`` subclass and register it in
``build_connectors``. Nothing else in the proxy needs to change.
"""

from __future__ import annotations

from ..config import Settings
from .anthropic import AnthropicConnector
from .base import Connector, StreamHandler, UnsupportedRequest, UpstreamCall, Usage
from .mistral import MistralConnector
from .openai import OpenAIConnector

__all__ = [
    "Connector",
    "StreamHandler",
    "UnsupportedRequest",
    "UpstreamCall",
    "Usage",
    "build_connectors",
]


def _secret(value) -> str | None:
    return value.get_secret_value() if value else None


def build_connectors(settings: Settings) -> dict[str, Connector]:
    connectors: list[Connector] = [
        OpenAIConnector(settings.openai_base_url, _secret(settings.openai_api_key)),
        AnthropicConnector(
            settings.anthropic_base_url,
            _secret(settings.anthropic_api_key),
            version=settings.anthropic_version,
            default_max_tokens=settings.anthropic_default_max_tokens,
        ),
        MistralConnector(settings.mistral_base_url, _secret(settings.mistral_api_key)),
    ]
    return {c.name: c for c in connectors}
