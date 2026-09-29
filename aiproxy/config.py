"""Runtime configuration.

Every secret (upstream provider keys, admin token, Stripe keys) is read from
environment variables only. Nothing sensitive is hard-coded in the source.

Provider credentials follow one pattern: ``<PROVIDER>_API_KEY`` and an
optional ``<PROVIDER>_BASE_URL`` override, e.g. ``DEEPSEEK_API_KEY``. See
``aiproxy/connectors/catalog.py`` for every supported provider.
"""

from __future__ import annotations

import os
from decimal import Decimal
from functools import lru_cache
from urllib.parse import parse_qsl, urlencode

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # extra="allow" so provider variables in a .env file (DEEPSEEK_API_KEY...)
    # are picked up without declaring a field for each of 40+ providers.
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="allow")

    # --- database -----------------------------------------------------------
    database_url: str = "postgresql+asyncpg://postgres@localhost:5432/aiproxy"
    database_pool_size: int = 20
    database_max_overflow: int = 20
    database_connect_timeout_seconds: float = 5.0

    # --- admin layer (separate auth from user keys) -------------------------
    admin_api_token: SecretStr | None = None
    # Optional comma-separated IPs/CIDRs allowed to reach /admin at all.
    admin_allowed_ips: str = ""
    admin_auth_failures_per_minute_per_ip: int = 10
    # Hostnames the admin area answers on (comma-separated). Empty: the
    # Railway domain in RAILWAY_PUBLIC_DOMAIN if set, otherwise any host.
    admin_allowed_hosts: str = ""
    # Dashboard sessions end after this much inactivity, and at the latest
    # this long after sign-in.
    admin_session_idle_minutes: int = 30
    admin_session_max_hours: int = 12
    admin_max_sessions: int = 20

    # --- upstream -----------------------------------------------------------
    # The three original providers keep explicit fields; every other provider
    # is read from <NAME>_API_KEY / <NAME>_BASE_URL (see env_value()).
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    mistral_api_key: SecretStr | None = None
    anthropic_base_url: str = "https://api.anthropic.com/v1"
    anthropic_version: str = "2023-06-01"
    anthropic_default_max_tokens: int = 4096

    # JSON list of extra OpenAI-compatible providers, e.g.
    # [{"name": "aleph", "base_url": "https://pharia.example.com/v1", "country": "DE"}]
    custom_providers: str = ""
    # Upstream base URLs must be https unless this is set (local testing only).
    allow_insecure_upstream: bool = False
    # Extra CA certificates to trust for upstream calls (e.g. GigaChat's CA).
    upstream_extra_ca_file: str = ""

    upstream_timeout_seconds: float = 120.0
    upstream_connect_timeout_seconds: float = 10.0
    upstream_http2: bool = True
    upstream_max_connections: int = 500
    upstream_keepalive_seconds: float = 120.0
    max_upstream_response_bytes: int = 32_000_000
    models_cache_seconds: int = 600

    # --- pricing ------------------------------------------------------------
    # One fee per completed round trip (request in -> provider -> response out),
    # used when no row in the `pricing` table matches the request.
    default_fee_per_request: Decimal = Decimal("0.03")
    pricing_cache_seconds: float = 30.0

    # --- gateway limits -----------------------------------------------------
    rate_limit_per_minute: int = 60
    # Every request from one client IP, before authentication.
    ip_rate_limit_per_minute: int = 3000
    # After this many failed authentications per minute an IP gets 429 without
    # touching the database.
    auth_failures_per_minute_per_ip: int = 60
    # Failed-auth rejections stored in audit_log per client IP per minute;
    # beyond this they are only written to the application log.
    audit_auth_failures_per_minute_per_ip: int = 30
    # How long an authenticated key stays cached in memory. Revocation and
    # suspension still take effect immediately for billed requests, because
    # the billing reservation re-checks both in the database.
    auth_cache_seconds: float = 30.0
    max_request_bytes: int = 2_000_000
    body_read_timeout_seconds: float = 30.0
    require_https: bool = True
    enable_docs: bool = False

    # --- cost-abuse guards --------------------------------------------------
    # Largest `n` (number of choices) a request may ask for.
    max_choices: int = 1
    # Provider service tiers that bill the operator extra; requests asking for
    # them are rejected.
    blocked_service_tiers: str = "priority,scale"
    # If > 0, reject requests asking for more output tokens than this, and
    # apply it when a request sets no limit.
    max_output_tokens: int = 0

    # --- general transactions -----------------------------------------------
    # By default a transaction's fee follows the account's country (set by an
    # admin). Set this to price by the country each transaction reports; only
    # do so for accounts you trust, since the caller chooses that country.
    price_by_transaction_country: bool = False

    # A transaction still "pending" after this long is treated as abandoned:
    # it is marked "error" and its reserved fee is refunded.
    pending_timeout_minutes: int = 60
    reconcile_interval_seconds: int = 30

    # --- Stripe (optional) --------------------------------------------------
    stripe_secret_key: SecretStr | None = None
    stripe_webhook_secret: SecretStr | None = None
    stripe_api_base: str = "https://api.stripe.com/v1"
    stripe_success_url: str = "https://example.com/billing/success"
    stripe_cancel_url: str = "https://example.com/billing/cancel"
    stripe_min_topup_usd: Decimal = Decimal("5")
    stripe_max_topup_usd: Decimal = Decimal("1000")

    # --- Opossum Protocol ---------------------------------------------------
    # One random secret (base64url, 32+ bytes); receipt signing, vault
    # encryption and pseudonym keys are all derived from it. Opossum is off
    # (503) until it is set. Generate: python -m aiproxy gen-opossum-key
    opossum_master_key: SecretStr | None = None
    opossum_fee_percent: Decimal = Decimal("3")
    # The processor's fee as quoted to users (Stripe US cards: 2.9% + 0.30).
    opossum_processor_fee_percent: Decimal = Decimal("2.9")
    opossum_processor_fee_flat: Decimal = Decimal("0.30")
    opossum_currencies: str = "USD,EUR,GBP,CAD,AUD"
    # Sandbox recipients settle instantly with test money and say so on every
    # receipt. Turn off to allow only real processors.
    opossum_sandbox_enabled: bool = True
    opossum_seed_sandbox_recipients: bool = True
    # Payments need an authenticator app on the account.
    opossum_require_mfa: bool = True
    opossum_kdf_iterations: int = 600_000
    opossum_session_idle_minutes: int = 30
    opossum_session_max_hours: int = 12
    opossum_max_backup_bytes: int = 5_000_000
    opossum_payments_per_hour: int = 20
    opossum_signin_failures_per_minute_per_ip: int = 10
    # Defaults for countries without their own row in op_jurisdictions.
    opossum_unverified_tx_limit: Decimal = Decimal("500")
    opossum_unverified_daily_limit: Decimal = Decimal("1000")
    opossum_verified_tx_limit: Decimal = Decimal("10000")
    opossum_retention_days: int = 1825
    # Countries payments may not come from or go to (ISO codes). Review this
    # against the sanctions rules that apply to you; it is not legal advice.
    opossum_blocked_countries: str = "CU,IR,KP,SY"
    # Official OFAC SDN list, downloaded and refreshed automatically.
    opossum_ofac_enabled: bool = True
    opossum_ofac_refresh_hours: int = 24
    # Identity checks through Stripe Identity (needs Identity activated in
    # the Stripe dashboard). A matching selfie costs more but is stronger.
    opossum_stripe_identity: bool = True
    opossum_identity_selfie: bool = False

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
        if value.startswith("postgresql+asyncpg://") and "?" in value:
            # libpq-style options (as many hosts hand out) are not understood
            # by asyncpg: `sslmode=require` must be spelled `ssl=require`.
            base, _, query = value.partition("?")
            params = []
            for key, val in parse_qsl(query, keep_blank_values=True):
                if key == "sslmode":
                    key = "ssl"
                elif key == "channel_binding":
                    continue
                params.append((key, val))
            value = base + ("?" + urlencode(params) if params else "")
        return value

    def env_value(self, name: str) -> str | None:
        """Read a setting that has no declared field, e.g. ``DEEPSEEK_API_KEY``.

        Looks at declared fields, then values passed to the constructor or
        found in .env, then the process environment.
        """
        attr = name.lower()
        if attr in type(self).model_fields:
            value = getattr(self, attr)
            if isinstance(value, SecretStr):
                value = value.get_secret_value()
            return str(value) if value not in (None, "") else None
        extra = self.model_extra or {}
        if attr in extra and extra[attr] not in (None, ""):
            value = extra[attr]
            return value.get_secret_value() if isinstance(value, SecretStr) else str(value)
        value = os.environ.get(name.upper())
        return value or None

    @property
    def admin_enabled(self) -> bool:
        token = self.admin_api_token.get_secret_value() if self.admin_api_token else ""
        return len(token) >= 32

    @property
    def stripe_enabled(self) -> bool:
        return bool(self.stripe_secret_key and self.stripe_webhook_secret)

    @property
    def blocked_tiers(self) -> frozenset[str]:
        return frozenset(t.strip().lower() for t in self.blocked_service_tiers.split(",") if t.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()
