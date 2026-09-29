"""Router: decides which provider a request targets and which connector handles it."""

from __future__ import annotations

from .connectors import Connector
from .errors import GatewayError
from .models import PROVIDER_ANY


def resolve_unified_model(model_field: object, key_provider: str, connectors: dict[str, Connector]) -> tuple[str, str]:
    """Split ``"anthropic/claude-sonnet-5-5"`` into ``("anthropic", "claude-sonnet-5-5")``.

    A key bound to a single provider may omit the prefix.
    """
    if not isinstance(model_field, str) or not model_field.strip() or len(model_field) > 200:
        raise GatewayError(400, "invalid_request", "'model' must be a non-empty string")
    prefix, sep, rest = model_field.partition("/")
    if sep and prefix in connectors and rest:
        return prefix, rest
    if key_provider != PROVIDER_ANY:
        return key_provider, model_field
    raise GatewayError(
        400,
        "invalid_request",
        "prefix 'model' with a provider, e.g. " + ", ".join(f"'{name}/<model>'" for name in sorted(connectors)),
    )


def select_connector(provider: str, key_provider: str, connectors: dict[str, Connector]) -> Connector:
    connector = connectors.get(provider)
    if connector is None:
        raise GatewayError(404, "unknown_provider", f"unknown provider '{provider}'")
    if key_provider not in (PROVIDER_ANY, provider):
        raise GatewayError(
            403, "key_provider_mismatch", f"this API key is restricted to provider '{key_provider}'"
        )
    if not connector.configured:
        raise GatewayError(503, "provider_not_configured", f"provider '{provider}' is not available right now")
    return connector
