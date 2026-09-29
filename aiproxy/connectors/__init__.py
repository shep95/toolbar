"""Connector registry: one connector per upstream provider.

Built-in providers are listed in ``catalog.py``. Operators can add any other
OpenAI-compatible API with the ``CUSTOM_PROVIDERS`` setting, without a code
change. A provider is only usable once its ``<NAME>_API_KEY`` is set.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import orjson

from ..config import Settings
from .anthropic import AnthropicConnector
from .base import Connector, StreamHandler, UnsupportedRequest, UpstreamCall, Usage
from .catalog import CATALOG
from .compat import OpenAICompatibleConnector, ProviderSpec

__all__ = [
    "Connector",
    "StreamHandler",
    "UnsupportedRequest",
    "UpstreamCall",
    "Usage",
    "build_connectors",
    "ConfigError",
]

_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
_RESERVED = {"v1", "admin", "any", "stripe", "healthz", "readyz", "docs", "openapi.json"}


class ConfigError(ValueError):
    pass


def _check_base_url(name: str, url: str, settings: Settings) -> str:
    parsed = urlparse(url)
    if parsed.scheme == "https" and parsed.netloc:
        return url
    if parsed.scheme == "http" and parsed.netloc and settings.allow_insecure_upstream:
        return url
    raise ConfigError(f"{name}: base URL must be an https:// URL (got {url!r})")


def _custom_specs(settings: Settings) -> list[tuple[ProviderSpec, str]]:
    if not settings.custom_providers.strip():
        return []
    try:
        entries = orjson.loads(settings.custom_providers)
    except orjson.JSONDecodeError as exc:
        raise ConfigError(f"CUSTOM_PROVIDERS is not valid JSON: {exc}") from None
    if not isinstance(entries, list):
        raise ConfigError("CUSTOM_PROVIDERS must be a JSON list")
    specs = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ConfigError("each CUSTOM_PROVIDERS entry must be an object")
        name = str(entry.get("name", ""))
        if not _NAME_RE.match(name) or name in _RESERVED:
            raise ConfigError(f"invalid custom provider name {name!r}")
        paths: Any = entry.get("native_paths") or ["chat/completions"]
        if not isinstance(paths, list) or not all(isinstance(p, str) and re.fullmatch(r"[a-z0-9/_-]{1,64}", p) for p in paths):
            raise ConfigError(f"{name}: native_paths must be a list of simple paths")
        spec = ProviderSpec(
            name=name,
            display_name=str(entry.get("display_name") or name),
            country=str(entry.get("country") or ""),
            base_url=str(entry.get("base_url") or ""),
            native_paths=frozenset(paths),
            lists_models=bool(entry.get("lists_models")),
            verified=False,
        )
        key_env = str(entry.get("api_key_env") or f"{name.upper().replace('-', '_')}_API_KEY")
        specs.append((spec, key_env))
    return specs


def build_connectors(settings: Settings) -> dict[str, Connector]:
    connectors: dict[str, Connector] = {}

    anthropic = AnthropicConnector(
        _check_base_url("anthropic", settings.anthropic_base_url, settings),
        settings.env_value("ANTHROPIC_API_KEY"),
        version=settings.anthropic_version,
        default_max_tokens=settings.anthropic_default_max_tokens,
    )
    connectors[anthropic.name] = anthropic

    specs = [(spec, f"{spec.name.upper()}_API_KEY") for spec in CATALOG] + _custom_specs(settings)
    for spec, key_env in specs:
        if spec.name in connectors:
            raise ConfigError(f"duplicate provider name {spec.name!r}")
        prefix = spec.name.upper().replace("-", "_")
        base_url = settings.env_value(f"{prefix}_BASE_URL") or spec.base_url
        env = {var: settings.env_value(var) for _, var in spec.env_headers}
        if spec.model_template_env:
            env[spec.model_template_env] = settings.env_value(spec.model_template_env)
        env[f"{prefix}_SCOPE"] = settings.env_value(f"{prefix}_SCOPE")
        connectors[spec.name] = OpenAICompatibleConnector(
            spec, _check_base_url(spec.name, base_url, settings), settings.env_value(key_env), env
        )
    return connectors
