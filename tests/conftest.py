from __future__ import annotations

import json
import os
import warnings
from collections.abc import Callable
from decimal import Decimal

import httpx
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from aiproxy.config import Settings
from aiproxy.db import Database
from aiproxy.main import create_app
from aiproxy.models import Base

warnings.filterwarnings("ignore", message=".*does \\*not\\* support Decimal.*")

ADMIN_TOKEN = "admin-" + "x" * 40
OPENAI_KEY = "sk-upstream-openai-secret-000000000000"
ANTHROPIC_KEY = "sk-ant-upstream-secret"
MISTRAL_KEY = "mistralupstreamsecret0000000000"
OPOSSUM_MASTER_KEY = "b3Bvc3N1bS10ZXN0LW1hc3Rlci1rZXktMDAwMDAwMDAwMA"


class FakeUpstream:
    """Stands in for every provider. Tests register a handler per URL path."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.handlers: dict[str, Callable[[httpx.Request], httpx.Response]] = {}
        self.default: Callable[[httpx.Request], httpx.Response] | None = None

    def on(self, path: str, handler: Callable[[httpx.Request], httpx.Response] | httpx.Response) -> None:
        self.handlers[path] = handler if callable(handler) else (lambda request, r=handler: r)

    def json_body(self, index: int = -1) -> dict:
        return json.loads(self.requests[index].content)

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        handler = self.handlers.get(request.url.path) or self.default
        if handler is None:
            return httpx.Response(404, json={"error": "no fake handler for " + request.url.path})
        result = handler(request)
        if hasattr(result, "__await__"):
            result = await result
        return result


def make_settings(**overrides) -> Settings:
    values = dict(
        database_url="sqlite+aiosqlite://",
        admin_api_token=ADMIN_TOKEN,
        openai_api_key=OPENAI_KEY,
        anthropic_api_key=ANTHROPIC_KEY,
        mistral_api_key=MISTRAL_KEY,
        openai_base_url="https://api.openai.test/v1",
        anthropic_base_url="https://api.anthropic.test/v1",
        mistral_base_url="https://api.mistral.test/v1",
        default_fee_per_request=Decimal("0.03"),
        rate_limit_per_minute=1000,
        require_https=True,
        stripe_secret_key="sk_test_stripe",
        stripe_webhook_secret="whsec_test",
        stripe_api_base="https://api.stripe.test/v1",
        opossum_master_key=OPOSSUM_MASTER_KEY,
    )
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture
async def database(tmp_path):
    url = os.environ.get("TEST_DATABASE_URL") or f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    db = Database(engine)
    yield db
    await engine.dispose()


@pytest.fixture
def upstream() -> FakeUpstream:
    return FakeUpstream()


@pytest.fixture
def settings_overrides() -> dict:
    return {}


@pytest.fixture
async def app(database, upstream, settings_overrides):
    http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    application = create_app(
        make_settings(**settings_overrides), database=database, http_client=http, run_reconciler=False
    )
    async with application.router.lifespan_context(application):
        yield application
    await http.aclose()


@pytest.fixture
async def client(app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://proxy.test") as c:
        yield c


ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture
def make_user(client):
    async def _make(balance: str = "10", provider: str = "any", email: str | None = None, **key_fields):
        import uuid

        email = email or f"user-{uuid.uuid4().hex[:8]}@example.com"
        r = await client.post("/admin/api/users", json={"email": email, "initial_balance": balance}, headers=ADMIN)
        assert r.status_code == 201, r.text
        user = r.json()
        r = await client.post(
            f"/admin/api/users/{user['id']}/keys", json={"provider": provider, **key_fields}, headers=ADMIN
        )
        assert r.status_code == 201, r.text
        key = r.json()
        return user, key

    return _make
