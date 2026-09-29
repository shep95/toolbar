"""Runtime configuration.

Every secret (upstream provider keys, admin token, Stripe keys) is read from
environment variables only. Nothing sensitive is hard-coded in the source.
"""

from __future__ import annotations

from decimal import Decimal
from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- database -----------------------------------------------------------
    database_url: str = "postgresql+asyncpg://postgres@localhost:5432/aiproxy"
    database_pool_size: int = 10
    database_connect_timeout_seconds: float = 5.0

    # --- admin layer (separate auth from user keys) -------------------------
    admin_api_token: SecretStr | None = None

    # --- upstream credentials: environment only -----------------------------
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    mistral_api_key: SecretStr | None = None

    openai_base_url: str = "https://api.openai.com/v1"
    anthropic_base_url: str = "https://api.anthropic.com/v1"
    mistral_base_url: str = "https://api.mistral.ai/v1"
    anthropic_version: str = "2023-06-01"
    anthropic_default_max_tokens: int = 4096

    upstream_timeout_seconds: float = 120.0
    upstream_connect_timeout_seconds: float = 10.0

    # --- pricing ------------------------------------------------------------
    # Used when no row in the `pricing` table matches the request.
    default_fee_per_request: Decimal = Decimal("0.03")

    # --- gateway limits -----------------------------------------------------
    rate_limit_per_minute: int = 60
    # Failed-auth rejections stored in audit_log per client IP per minute;
    # beyond this they are only written to the application log.
    audit_auth_failures_per_minute_per_ip: int = 30
    max_request_bytes: int = 2_000_000
    require_https: bool = True
    # A transaction still "pending" after this long is treated as abandoned:
    # it is marked "error" and its reserved fee is refunded.
    pending_timeout_minutes: int = 60
    reconcile_interval_seconds: int = 60

    # --- Stripe (optional) --------------------------------------------------
    stripe_secret_key: SecretStr | None = None
    stripe_webhook_secret: SecretStr | None = None
    stripe_api_base: str = "https://api.stripe.com/v1"
    stripe_success_url: str = "https://example.com/billing/success"
    stripe_cancel_url: str = "https://example.com/billing/cancel"
    stripe_min_topup_usd: Decimal = Decimal("5")
    stripe_max_topup_usd: Decimal = Decimal("1000")

    log_level: str = "INFO"

    @field_validator("database_url")
    @classmethod
    def _normalise_database_url(cls, value: str) -> str:
        # Railway / Render / Heroku hand out `postgres://` or `postgresql://`
        # URLs. SQLAlchemy's async engine needs the asyncpg driver spelled out.
        if value.startswith("postgres://"):
            value = "postgresql://" + value[len("postgres://") :]
        if value.startswith("postgresql://"):
            value = "postgresql+asyncpg://" + value[len("postgresql://") :]
        return value

    @property
    def admin_enabled(self) -> bool:
        token = self.admin_api_token.get_secret_value() if self.admin_api_token else ""
        return len(token) >= 32

    @property
    def stripe_enabled(self) -> bool:
        return bool(self.stripe_secret_key and self.stripe_webhook_secret)


@lru_cache
def get_settings() -> Settings:
    return Settings()
