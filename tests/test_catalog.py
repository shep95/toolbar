"""Every provider in the catalog, custom providers and model discovery."""

from __future__ import annotations

import json
from decimal import Decimal

import httpx
import pytest

from aiproxy.config import Settings
from aiproxy.connectors import ConfigError, build_connectors
from aiproxy.connectors.catalog import CATALOG

from .conftest import ADMIN
from .test_gateway import auth
from .test_providers import balance_of, only_tx, parse_sse, sse_body, sse_response

ALL = [spec.name for spec in CATALOG]


def provider_settings() -> dict:
    values = {}
    for spec in CATALOG:
        values[f"{spec.name}_api_key"] = f"key-for-{spec.name}-0123456789"
        values[f"{spec.name}_base_url"] = f"https://{spec.name}.test/v1"
    values["yandex_folder_id"] = "b1gfolder"
    values["baidu_appid"] = "app-123"
    return values


@pytest.fixture
def settings_overrides():
    return provider_settings()


def chat_ok(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    return httpx.Response(
        200,
        json={
            "id": "x", "object": "chat.completion", "model": body.get("model", "m"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi from " + request.url.host}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
        },
    )


def gigachat_token(request: httpx.Request) -> httpx.Response:
    assert request.headers["authorization"] == "Basic key-for-gigachat-0123456789"
    assert request.headers["rquid"]
    assert b"scope=GIGACHAT_API_PERS" in request.content
    return httpx.Response(200, json={"access_token": "tok-1", "expires_at": 4102444800000})


def test_catalog_is_well_formed():
    names = [spec.name for spec in CATALOG]
    assert len(names) == len(set(names))
    assert all(spec.base_url.startswith("https://") for spec in CATALOG)
    assert all(len(spec.country) == 2 for spec in CATALOG)
    connectors = build_connectors(Settings(_env_file=None))
    countries = {c.country for c in connectors.values()}
    assert len(connectors) >= 40
    assert {"US", "CN", "FR", "CA", "IL", "KR", "JP", "IN", "SG", "AE", "RU"} <= countries


@pytest.mark.parametrize("provider", ALL)
async def test_every_provider_round_trip(provider, client, make_user, upstream, database):
    upstream.default = chat_ok
    upstream.on("/api/v2/oauth", gigachat_token)
    user, key = await make_user(balance="1")
    model = "yandexgpt/latest" if provider == "yandex" else "some-model"
    r = await client.post(
        "/v1/chat/completions",
        json={"model": f"{provider}/{model}", "messages": [{"role": "user", "content": "hi"}]},
        headers=auth(key),
    )
    assert r.status_code == 200, r.text
    assert r.json()["choices"][0]["message"]["content"] == f"hi from {provider}.test"
    assert r.headers["X-Fee-Charged"] == "0.030000"

    sent = [req for req in upstream.requests if req.url.path.endswith("/chat/completions")][-1]
    assert str(sent.url) == f"https://{provider}.test/v1/chat/completions"
    secret = f"key-for-{provider}-0123456789"
    if provider == "sarvam":
        assert sent.headers["api-subscription-key"] == secret
        assert "authorization" not in sent.headers
    elif provider == "yandex":
        assert sent.headers["authorization"] == f"Api-Key {secret}"
        assert sent.headers["openai-project"] == "b1gfolder"
        assert json.loads(sent.content)["model"] == "gpt://b1gfolder/yandexgpt/latest"
    elif provider == "gigachat":
        assert sent.headers["authorization"] == "Bearer tok-1"
    else:
        assert sent.headers["authorization"] == f"Bearer {secret}"
    if provider == "baidu":
        assert sent.headers["appid"] == "app-123"
    assert key["api_key"] not in str(sent.headers)

    tx = await only_tx(database)
    assert (tx.provider, tx.status, tx.tokens_used) == (provider, "success", 5)
    assert await balance_of(database, user) == Decimal("0.97")


async def test_gigachat_token_is_cached(client, make_user, upstream):
    upstream.default = chat_ok
    upstream.on("/api/v2/oauth", gigachat_token)
    _, key = await make_user()
    for _ in range(3):
        r = await client.post(
            "/v1/chat/completions",
            json={"model": "gigachat/GigaChat-2", "messages": [{"role": "user", "content": "hi"}]},
            headers=auth(key),
        )
        assert r.status_code == 200
    assert sum(1 for req in upstream.requests if req.url.path == "/api/v2/oauth") == 1


async def test_kimi_style_stream_usage_is_billed(client, make_user, upstream, database):
    body = sse_body(
        (None, {"id": "c", "model": "kimi-k2", "choices": [{"index": 0, "delta": {"content": "ok"}}]}),
        (None, {"id": "c", "model": "kimi-k2", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop",
                "usage": {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10}}]}),
        (None, "[DONE]"),
    )
    upstream.default = lambda request: sse_response(body)
    _, key = await make_user()
    r = await client.post(
        "/v1/chat/completions",
        json={"model": "moonshot/kimi-k2", "messages": [{"role": "user", "content": "hi"}], "stream": True},
        headers=auth(key),
    )
    assert parse_sse(r.text)[-1] == "[DONE]"
    assert (await only_tx(database)).tokens_used == 10


async def test_model_listing_across_providers(client, make_user, upstream):
    def models(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"object": "list", "data": [{"id": f"{request.url.host.split('.')[0]}-m1"}]})

    upstream.default = models
    upstream.on("/v1/models", models)
    _, key = await make_user()
    r = await client.get("/v1/models", headers=auth(key))
    assert r.status_code == 200
    ids = {m["id"] for m in r.json()["data"]}
    assert {"openai/openai-m1", "deepseek/deepseek-m1", "google/google-m1", "mistral/mistral-m1"} <= ids
    calls = len(upstream.requests)
    await client.get("/v1/models", headers=auth(key))
    assert len(upstream.requests) == calls  # cached

    # A key bound to one provider only sees that provider.
    _, bound = await make_user(provider="deepseek")
    ids = {m["id"] for m in (await client.get("/v1/models", headers=auth(bound))).json()["data"]}
    assert ids == {"deepseek/deepseek-m1"}

    # Native listing for official SDKs' models.list().
    r = await client.get("/deepseek/v1/models", headers=auth(bound))
    assert r.json()["data"][0]["id"] == "deepseek-m1"
    assert (await client.get("/openai/v1/models", headers=auth(bound))).status_code == 403


async def test_provider_listing_shows_countries(client, make_user):
    _, key = await make_user()
    data = (await client.get("/v1/providers", headers=auth(key))).json()["data"]
    by_name = {p["name"]: p for p in data}
    assert by_name["deepseek"]["country"] == "CN"
    assert by_name["sarvam"]["country"] == "IN"
    assert "base_url" not in by_name["openai"]
    admin = (await client.get("/admin/api/providers", headers=ADMIN)).json()
    assert len(admin) >= 40 and all("configured" in p for p in admin)


def test_custom_providers_and_config_validation():
    custom = json.dumps([{"name": "aleph", "base_url": "https://pharia.example.com/v1", "country": "DE",
                          "native_paths": ["chat/completions", "embeddings"]}])
    connectors = build_connectors(Settings(_env_file=None, custom_providers=custom, aleph_api_key="k" * 20))
    assert connectors["aleph"].configured and connectors["aleph"].country == "DE"
    assert connectors["aleph"].native_paths == frozenset({"chat/completions", "embeddings"})

    bad = [
        [{"name": "openai", "base_url": "https://x.example"}],  # duplicate
        [{"name": "Bad Name", "base_url": "https://x.example"}],
        [{"name": "admin", "base_url": "https://x.example"}],  # reserved route
        [{"name": "plain", "base_url": "http://x.example"}],  # not https
        [{"name": "ok", "base_url": "https://x.example", "native_paths": ["../../etc"]}],
    ]
    for entry in bad:
        with pytest.raises(ConfigError):
            build_connectors(Settings(_env_file=None, custom_providers=json.dumps(entry)))
    with pytest.raises(ConfigError):
        build_connectors(Settings(_env_file=None, custom_providers="{not json"))


def test_base_url_override_must_be_https():
    with pytest.raises(ConfigError):
        build_connectors(Settings(_env_file=None, deepseek_base_url="http://evil.example"))
    ok = build_connectors(Settings(_env_file=None, deepseek_base_url="http://localhost:9", allow_insecure_upstream=True))
    assert ok["deepseek"].base_url == "http://localhost:9"
    region = build_connectors(Settings(_env_file=None, qwen_base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"))
    assert region["qwen"].base_url.startswith("https://dashscope.aliyuncs.com")
