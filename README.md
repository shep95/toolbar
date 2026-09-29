# Transaction Fee Platform

A prepaid, per-transaction fee platform with a built-in universal AI API
gateway.

- **Any kind of digital business.** One API records transactions across eight domains: AI APIs, brokerage and trading, crypto, payments, remittance and FX, commerce, digital goods and gaming, and general. Each transaction is charged a small fee from the account's prepaid balance.
- **AI requests.** Users call 40 built-in AI providers across 11 countries through one key, and each completed request is a transaction too.
- **Fair worldwide.** The base fee is $0.03 in high-income economies and scales down with each country's World Bank income group, to as little as $0.006.
- **Prepaid balances.** Users top up by card through Stripe Checkout, which can show the price in their own currency.

Built with Python (FastAPI) and PostgreSQL. It runs live on Railway: see
[docs/railway.md](docs/railway.md).

## Transactions API

Record any transaction. The platform does not move the transaction's money.
It records the transaction and charges the fee.

```bash
curl https://your-host.example/v1/transactions \
  -H "Authorization: Bearer apx_..." -H "Content-Type: application/json" \
  -d '{"reference": "order-1001", "type": "order", "amount": "49.90", "currency": "EUR", "country": "DE"}'
```

```json
{"id": "…", "reference": "order-1001", "type": "order", "amount": "49.9", "currency": "EUR", "country": "DE",
 "fee": {"amount_usd": "0.030000", "country": null, "multiplier": "1"}, "balance_remaining_usd": "9.970000",
 "replayed": false, "created_at": "…"}
```

| Field | Required | Notes |
|---|---|---|
| `reference` | yes | Your own ID for the transaction. Sending the same reference again returns the original record and is never charged twice, so retries are safe. Reusing it for a different transaction returns 409. |
| `domain` | no | The kind of business, from the domains below. Defaults to the key's domain, or else `general`. |
| `type` | depends | In `general`, any label, defaulting to `transaction`. In other domains, one of that domain's types (required). Admins can price types differently. |
| `attributes` | depends | Domain-specific fields, checked per domain (see below) |
| `amount`, `currency` | no | The transaction's own value, in any ISO 4217 currency, kept for your records |
| `country` | no | Where the transaction happened (ISO 3166 alpha-2), kept for your records |
| `description`, `metadata` | no | Up to 500 characters, and up to 20 simple key/value pairs |

Other endpoints:

- `GET /v1/transactions` lists the account's own transactions, filtered by `?reference=` and limited by `?limit=`.
- `GET /v1/account` shows the balance, the account's country and its current per-transaction fee.

Refusals: an unknown or revoked key gets 401, a suspended account 403, and a
balance too low for the fee 402. Nothing is recorded or charged in those
cases.

## Domains

Each domain is a kind of digital business, with its own transaction types and
its own `attributes`. Those are checked on the way in, so every record in a
domain has the same shape.

| Domain | For | Types | Attributes (required ones in bold) |
|---|---|---|---|
| `ai` | AI APIs you run yourself | request, completion, embedding, image, audio, fine_tune | provider, model, input_tokens, output_tokens |
| `brokerage` | Robinhood-style brokers and trading apps | buy, sell, short, cover, option_buy, option_sell, dividend, deposit, withdrawal, transfer, fee | **symbol**, **quantity** (for trades), asset_class, price, exchange, order_type |
| `crypto` | MoonPay-style on-ramps, exchanges, wallets | onramp, offramp, buy, sell, swap, send, receive, stake, unstake | **asset** (**to_asset** for swaps), quantity, price, network, tx_hash, wallet_address |
| `payments` | Checkouts, payouts, peer-to-peer | charge, refund, payout, p2p, invoice, subscription, chargeback | method, card_brand, counterparty |
| `remittance` | Cross-border money transfer and FX | send, receive, fx | **destination_country** (send), **destination_currency** (fx), fx_rate, channel |
| `commerce` | Online stores and marketplaces | order, refund, fulfillment, cancellation | items, merchant, sku |
| `digital_goods` | In-app purchases, games, gift cards | purchase, redemption, gift, subscription, in_app | sku, platform, title |
| `general` | Anything else | any | none |

The built-in AI gateway's own requests are recorded automatically and are
not sent through this API.

```bash
# A brokerage recording a stock purchase
curl https://your-host.example/v1/transactions -H "Authorization: Bearer apx_..." -H "Content-Type: application/json" \
  -d '{"reference": "trade-88121", "domain": "brokerage", "type": "buy", "amount": "2275.20", "currency": "USD",
       "attributes": {"symbol": "AAPL", "quantity": "10", "price": "227.52", "order_type": "limit"}}'

# A crypto on-ramp recording a purchase of bitcoin
curl https://your-host.example/v1/transactions -H "Authorization: Bearer apx_..." -H "Content-Type: application/json" \
  -d '{"reference": "onramp-5531", "domain": "crypto", "type": "onramp", "amount": "100", "currency": "EUR",
       "country": "DE", "attributes": {"asset": "BTC", "quantity": "0.0015", "network": "bitcoin"}}'
```

- **Keys locked to a domain.** When issuing a key, an admin can lock it to one domain. A crypto business then gets a key that can only record crypto transactions, never AI or brokerage ones, and cannot use the AI gateway. With a locked key, `domain` can be left out.
- **Pricing per domain.** In the pricing panel, a rule whose provider is a domain name prices that domain. Setting the model to a type prices just that type, such as `crypto` / `onramp`. Country adjustment then applies on top.
- **Discovery.** `GET /v1/domains` lists every domain the key can use, with its types, attributes and this account's fee.
- **Admin view.** The **Domains** panel shows each domain's fee, locked keys and 30-day volume and revenue.
- **Adding a domain** is one entry in `aiproxy/domains.py`.

## Fees by country

The fee is the base price times the country's multiplier:

| World Bank income group | Multiplier | Fee | Examples |
|---|---|---|---|
| High income | 1.00 | $0.0300 | US, Canada, EU, UK, Japan, Korea, Australia, Gulf states |
| Upper-middle income | 0.60 | $0.0180 | Brazil, Mexico, China, South Africa, Türkiye, Indonesia |
| Lower-middle income | 0.35 | $0.0105 | India, Nigeria, Pakistan, Egypt, Philippines, Vietnam |
| Low income | 0.20 | $0.0060 | Ethiopia, Uganda, Afghanistan, Mozambique |

- **Who decides the country.** It is set per account by an admin, never by the user, so nobody can claim a cheaper country. An account with no country pays the full fee, and so does any unlisted country.
- **The same rule for AI requests.** They are adjusted the same way, and responses carry `X-Fee-Country`.
- **Overrides.** Admins can override any country in the dashboard's **countries** room, for example when the World Bank reclassifies a country each July. The table lives in `aiproxy/countries.py`.
- **Pricing by transaction country.** Set `PRICE_BY_TRANSACTION_COUNTRY=true` to price each transaction by the `country` it reports instead. Only do this for accounts you trust, since the caller chooses that country.
- **Local-currency payments.** Balances and fees are kept in US dollars. Customers can still pay top-ups in their own currency: switch on **Adaptive Pricing** in the Stripe dashboard under Settings → Payments. Stripe then shows the local price and still settles in USD, and the ledger notes what the customer actually paid.

## Providers

Set `<NAME>_API_KEY` to switch a provider on. Every base URL can be overridden
with `<NAME>_BASE_URL`, for example to use a China-region endpoint or to follow
a provider that moves its API. The full list, with docs links and notes, lives
in `aiproxy/connectors/catalog.py`.

| Country | Providers (`name`) |
|---|---|
| United States | OpenAI (`openai`), Anthropic Claude (`anthropic`), Google Gemini (`google`), xAI Grok (`xai`), Perplexity (`perplexity`), Groq (`groq`), Together AI (`together`), Fireworks AI (`fireworks`), Cerebras (`cerebras`), SambaNova (`sambanova`), OpenRouter (`openrouter`), DeepInfra (`deepinfra`), NVIDIA NIM (`nvidia`), Hugging Face (`huggingface`) |
| Canada | Cohere (`cohere`) |
| France | Mistral AI (`mistral`), LightOn Paradigm (`lighton`) |
| Israel | AI21 Labs Jamba (`ai21`) |
| China | DeepSeek (`deepseek`), Alibaba Qwen (`qwen`), Moonshot Kimi (`moonshot`), Zhipu GLM / Z.ai (`zhipu`), MiniMax (`minimax`), Baidu ERNIE (`baidu`), Tencent Hunyuan (`tencent`), ByteDance Doubao (`doubao`), StepFun (`stepfun`), iFlytek Spark (`iflytek`), Baichuan (`baichuan`)\*, 01.AI Yi (`yi`)\* |
| South Korea | Upstage Solar (`upstage`), NAVER HyperCLOVA X (`naver`) |
| Japan | Sakana AI (`sakana`), Preferred Networks PLaMo (`plamo`) |
| India | Sarvam AI (`sarvam`), Ola Krutrim (`krutrim`) |
| Singapore | AI Singapore SEA-LION (`sealion`) |
| United Arab Emirates | AI71 Falcon (`ai71`)\* |
| Russia | YandexGPT (`yandex`), Sber GigaChat (`gigachat`) |

\* Could not be confirmed against official documentation. Test these with a
real key before offering them.

Endpoints and auth formats come from each provider's official documentation.
Three providers need more than an API key:

- **Yandex** needs `YANDEX_FOLDER_ID`. A model such as `yandex/yandexgpt/latest` is sent as `gpt://<folder>/yandexgpt/latest`.
- **GigaChat** uses the base64 authorization key from Sber as `GIGACHAT_API_KEY`. The proxy exchanges it for short-lived tokens and refreshes them itself. It also needs the Russian Trusted Root CA in `UPSTREAM_EXTRA_CA_FILE`.
- **Baidu** optionally takes `BAIDU_APPID`.

Aleph Alpha (Germany) is self-hosted only, so it has no public URL to build
in. Add it, or any other OpenAI-compatible API, without code changes:

```bash
CUSTOM_PROVIDERS='[{"name": "aleph", "base_url": "https://pharia.example.com/v1", "country": "DE",
                    "native_paths": ["chat/completions", "embeddings"]}]'
ALEPH_API_KEY=...
```

Custom and overridden base URLs must use `https://`, so provider keys never
travel in plaintext.

## Components

| Component | Module | Job |
|---|---|---|
| Gateway | `aiproxy/gateway.py` | Front door. IP limits, key validation, user status, rate limit, body checks and cost-abuse guards, before anything else runs. |
| Router | `aiproxy/router.py` | Works out which provider the request targets and picks its connector. Enforces key-to-provider binding. |
| Billing engine | `aiproxy/billing.py` | Reserves the fee, logs the transaction, then settles (charge) or refunds (failure). Runs on every proxied request. |
| Upstream connector | `aiproxy/upstream.py` + `aiproxy/connectors/` | Makes the real provider call and handles the response, including streaming. `catalog.py` describes every provider. |
| Admin layer | `aiproxy/admin.py` + `aiproxy/static/admin.html` | Users, keys, balances, pricing, usage dashboard and audit log, behind a separate admin token. |

## Using the AI gateway

### Unified endpoint: OpenAI format for every provider

Send OpenAI chat-completions requests and prefix the model with the provider.

```python
from openai import OpenAI

client = OpenAI(api_key="apx_...", base_url="https://your-proxy.example/v1")
client.chat.completions.create(model="deepseek/deepseek-chat", messages=[...])
client.chat.completions.create(model="google/gemini-2.5-flash", messages=[...])
client.chat.completions.create(model="anthropic/claude-sonnet-5-5", messages=[...], stream=True)
client.chat.completions.create(model="qwen/qwen-plus", messages=[...])
client.models.list()     # every model on every configured provider, as "<provider>/<model>"
```

A key bound to a single provider may drop the prefix, as in `model="gpt-5"`.
Anthropic requests and responses are translated both ways, streaming
included. Through this endpoint Anthropic supports text and images. Tools
need the native endpoint.

### Native endpoints: official SDKs unchanged

Point any official SDK at `/<provider>/v1` and use the proxy key as the API key.

```python
anthropic.Anthropic(api_key="apx_...", base_url="https://your-proxy.example/anthropic")
openai.OpenAI(api_key="apx_...", base_url="https://your-proxy.example/deepseek/v1")
```

Each provider exposes only the endpoints listed for it in the catalog. That
is always `chat/completions`, plus `embeddings`, `responses` and others where
the provider offers them. Everything else returns 404, so the proxy cannot
reach files, fine-tuning or account endpoints on your provider accounts.

### Other endpoints

None of these are billed:

- `GET /v1/models` lists models, cached for 10 minutes.
- `GET /v1/providers` lists the providers this key can use, with their home country.
- `GET /v1/account` returns the caller's balance and key details.
- `POST /v1/billing/checkout` with `{"amount_usd": 20}` returns a Stripe Checkout URL, when Stripe is configured.

## The fee

Each completed AI round trip is charged the transaction fee: $0.03, adjusted
for the account's country as above. A round trip runs from
the user's request, through the provider, to the response delivered back. The
fee is reserved before the provider is called and settled once the response
is out.

| What happened | Charged |
|---|---|
| Provider answered, response delivered (normal or streamed) | $0.03 |
| Client hung up after the provider started working | $0.03, since the provider already did the work |
| Provider down, timed out, errored, or rejected the request | $0.00 |
| Request refused by the proxy (bad key, no balance, invalid, rate limited) | $0.00 |

Every response carries `X-Fee-Charged` and `X-Balance-Remaining` headers.
Streams carry `X-Fee-Reserved` instead. Admins can change the fee per
provider or model in the dashboard, and can add a per-1k-token component.

**Flat fees and your costs.** A flat fee does not scale with what the
provider charges you. One large request to an expensive model can cost you
far more than $0.03. The proxy blocks the easy ways to multiply cost: `n`
greater than 1 and premium service tiers. You can also cap output with
`MAX_OUTPUT_TOKENS`. For expensive models, add a per-1k-token rule in the
pricing panel.

## Speed

The hot path is built to add as little as possible on top of the provider:

- **One database round trip before the provider call.** On PostgreSQL, reserving the fee is a single auto-committed SQL statement. The user's row is locked for microseconds, so one busy customer's requests don't queue behind each other.
- **Settlement after the response.** For normal responses, the charge is written after the response has been sent.
- **Authentication and pricing are cached in memory.** Revocation and suspension still take effect immediately, because the fee reservation re-checks both.
- **Warm upstream connections.** One shared HTTP/2-capable client keeps provider connections alive for two minutes, so calls skip DNS and TLS setup.
- **Fast JSON.** orjson is used throughout. Responses already in the caller's format are passed through as raw bytes, never re-serialized.
- **Streams are forwarded as they arrive,** event by event.

Measured with `bench/bench.py` against a local fake provider that answers in
about 1 ms, with PostgreSQL 16, on a shared 4-core machine:

| Scenario | Before | After |
|---|---|---|
| Added latency, one request at a time | 11.4 ms | 3.6 ms |
| Throughput, 16 concurrent clients | 127 req/s | 300 req/s |
| p99 latency, 16 concurrent clients | 307 ms | 129 ms |
| Throughput, 16 concurrent streams | 123 req/s | 275 req/s |

At 16 concurrent clients the machine is CPU-bound: the benchmark client, fake
provider and database share the same four cores. Real provider calls take
hundreds of milliseconds to seconds, so the proxy's share of end-to-end time
is a few milliseconds. To reproduce:

```bash
uvicorn fake_upstream:app --app-dir bench --port 9100 &
OPENAI_BASE_URL=http://127.0.0.1:9100/v1 ALLOW_INSECURE_UPSTREAM=true uvicorn aiproxy.main:app &
python bench/bench.py --proxy http://127.0.0.1:8000 --direct http://127.0.0.1:9100/v1 --key apx_...
```

## Security

Each attack pattern and its defence. Every row has a test in `tests/test_security.py` or `tests/test_gateway.py`.

| Attack pattern | Defence |
|---|---|
| Stolen key used for spam | Per-key rate limit. The key can be revoked, which takes effect at once even while cached. |
| Guessing keys | 256-bit random keys. After `AUTH_FAILURES_PER_MINUTE_PER_IP` failures, the IP gets 429 without touching the database. |
| Flooding one endpoint from one IP | Per-IP limit before authentication. Memory per IP is constant and total tracked IPs are capped. |
| Filling the audit table | Stored failed-auth rows are capped per IP. The rest go only to the app log. Unknown-provider 404s are not stored. |
| Smuggling a provider key | Provider-shaped keys are rejected, and so is a request with two different credentials. Client headers are never forwarded upstream. |
| Cost amplification | `n` > 1 rejected, premium service tiers rejected, optional output-token cap. |
| Free requests by hanging up | Charged once the provider has been called. |
| Oversized or malicious input | Body size limit, 30 s body-read timeout against slow senders, a JSON nesting limit, and strict model-ID characters. |
| Leaking the operator's identity | Provider error bodies and stream error events are scrubbed of org IDs, project IDs and key fragments. Provider response headers are never forwarded. |
| Oversized provider responses | Capped at `MAX_UPSTREAM_RESPONSE_BYTES`. SSE events are capped at 8 MB. |
| Guessing the admin token | Separate 32+ character token, compared in constant time. The IP is locked out after 10 failures a minute, and failed dashboard sign-ins are written to the audit log. Optional `ADMIN_ALLOWED_IPS` makes `/admin` return 404 to everyone else. |
| Stealing the dashboard session | The token is exchanged for a random session ID held only in a `__Host-` cookie (Secure, HttpOnly, SameSite=Strict). Page scripts and the browser console cannot read it. Only its SHA-256 is stored. A session ends after 30 minutes idle or 12 hours, when the User-Agent changes, or on sign-out. |
| Cross-site requests to the dashboard | Sign-in and every cookie-authenticated change need the dashboard's own `Origin` (or `Sec-Fetch-Site: same-origin`) and an `X-Admin-Request` header. |
| Reaching the dashboard through another domain | `/admin` answers only on `ADMIN_ALLOWED_HOSTS`, which defaults to Railway's `RAILWAY_PUBLIC_DOMAIN`. Raw IPs, stray domains and DNS rebinding get 404. |
| Cross-site scripting in the dashboard | All content is rendered as text. The CSP pins the page's one script and one stylesheet by hash, and Trusted Types (`trusted-types 'none'`) forbids turning strings into markup. COOP, COEP and CORP isolate the page, and Permissions-Policy turns off camera, microphone, payment and similar APIs. |
| Clickjacking, sniffing, caching | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on API responses. |
| Downgrade to plain HTTP | Plain-HTTP requests are rejected, HSTS is sent, and upstream base URLs must be HTTPS. |
| Reconnaissance | No server banner. The OpenAPI docs are off unless `ENABLE_DOCS=true`. |
| Stripe webhook forgery, replay or over-credit | Signature check with a 5-minute window. Idempotent on the session ID. The credit is the lower of the subtotal and the total, and the body is capped at 1 MB. |
| SQL injection | Parameterized queries only. `bandit` runs in CI. |
| Vulnerable dependencies | `pip-audit` runs in CI. |

Other practices:

- Raw keys are never stored: only a SHA-256 hash and a display prefix.
- Provider credentials come from environment variables only.
- The container runs as a non-root user.

**Client IPs behind a proxy.** The IP-based defences rely on seeing the real
client IP. On Railway or Render the default `FORWARDED_ALLOW_IPS=*` is right,
because only the platform can reach the app. On a bare VPS, set it to your
reverse proxy's address so clients cannot spoof `X-Forwarded-For`.

## Request flow

```
client ──► gateway: HTTPS? per-IP limit? IP blocked for failed logins?
               │   key present, well-formed, known (cache or DB), active?  no ──► 401
               ├─ user suspended ─────────────────────► 403
               ├─ key bound to a different provider ──► 403
               ├─ over the key's rate limit ──────────► 429 + Retry-After
               ├─ body too large / slow / invalid ────► 413 / 408 / 400
               ├─ n > 1, premium tier, over token cap ► 400
               ▼
           router: provider from "provider/model" (or the key's provider)
               ▼
           billing.reserve: one SQL statement deducts $0.03 only if user active,
           key active and balance covers it, and logs a "pending" transaction
               ├─ cannot afford ──────────────────────► 402 (not forwarded)
               ├─ database down ──────────────────────► 503 (nothing sent upstream)
               ▼
           upstream connector: call the provider with the operator's credentials
               ├─ unreachable / timeout / 5xx ────────► 502 / 504, refunded
               ├─ provider 4xx ───────────────────────► same status, scrubbed body, refunded
               ▼
           response to client ──► then billing.complete marks it "success"
```

## Data model

Money is `NUMERIC(18,6)` dollars, never floats.

- **users**: `id`, `email`, `created_at`, `balance`, `status` (active / suspended).
- **api_keys**: `id`, `user_id`, `key_hash`, `key_prefix`, `name`, `provider`, `rate_limit_per_minute`, `created_at`, `last_used_at`, `status` (active / revoked).
- **transactions**: `id`, `user_id`, `api_key_id`, `provider`, `model_called`, `endpoint`, `tokens_used`, `input_tokens`, `output_tokens`, `fee_charged`, `timestamp`, `completed_at`, `status` (pending / success / failed / error), `upstream_status`, `latency_ms`, `error`, `request_id`.
- **pricing**, **balance_adjustments** and **audit_log**, as before.

`last_used_at` is written in batches every 10 seconds, not on every request.

## Admin

Scripts call the admin API with `Authorization: Bearer $ADMIN_API_TOKEN`.

The dashboard at `/admin` is split into rooms: overview, accounts, domains,
pricing, countries, ledger and security. Type the token once to unlock it.
The token is exchanged for a server-side session held in an HttpOnly cookie,
so it is never kept in the page. The page locks itself after 30 minutes
without activity. The **security** room lists signed-in browsers and can
sign them all out. New API keys are shown once and hidden again after 90
seconds.

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/api/overview` | Totals for the last 24 hours and 30 days, plus each provider's credential status and country |
| GET | `/admin/api/providers` | Every provider with country, endpoints and verification status |
| POST / GET | `/admin/api/users` | Create a user, or list users |
| GET / PATCH | `/admin/api/users/{id}` | Show a user, or set `status` |
| POST | `/admin/api/users/{id}/credits` | Add or remove balance |
| POST / GET | `/admin/api/users/{id}/keys` | Issue a key (the raw key is shown once), or list keys |
| DELETE | `/admin/api/keys/{id}` | Revoke a key |
| GET / PUT / DELETE | `/admin/api/pricing` | Fee rules per provider and model |
| GET | `/admin/api/transactions`, `/admin/api/usage`, `/admin/api/audit` | Usage and audit views |
| POST | `/admin/api/maintenance/reconcile` | Refund stale pending transactions now |
| GET / POST / DELETE | `/admin/session` | Dashboard session status, sign-in with `{"token": ...}`, sign-out |
| GET | `/admin/api/sessions` | Signed-in dashboard browsers |
| POST | `/admin/api/sessions/end-all` | Sign every dashboard out |

## Configuration

All settings are environment variables. `.env.example` lists every one.
The main ones:

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | — | `postgres://` URLs from Railway or Render work as-is |
| `ADMIN_API_TOKEN` | unset | At least 32 characters |
| `ADMIN_ALLOWED_IPS` | unset | IPs or CIDRs allowed to reach `/admin` |
| `ADMIN_ALLOWED_HOSTS` | `RAILWAY_PUBLIC_DOMAIN` | Hostnames `/admin` answers on; set it when you add a custom domain |
| `ADMIN_SESSION_IDLE_MINUTES` / `ADMIN_SESSION_MAX_HOURS` | `30` / `12` | Dashboard session lifetime |
| `<NAME>_API_KEY`, `<NAME>_BASE_URL` | unset / catalog | One pair per provider |
| `CUSTOM_PROVIDERS` | unset | JSON list of extra OpenAI-compatible providers |
| `DEFAULT_FEE_PER_REQUEST` | `0.03` | Per completed round trip |
| `RATE_LIMIT_PER_MINUTE` | `60` | Per key |
| `IP_RATE_LIMIT_PER_MINUTE` | `3000` | Per client IP, before authentication |
| `AUTH_FAILURES_PER_MINUTE_PER_IP` | `60` | Then 429 without a DB lookup |
| `AUTH_CACHE_SECONDS` | `30` | `0` disables the cache |
| `MAX_CHOICES` | `1` | Largest `n` allowed |
| `BLOCKED_SERVICE_TIERS` | `priority,scale` | |
| `MAX_OUTPUT_TOKENS` | `0` (off) | Cap on requested output tokens |
| `MAX_REQUEST_BYTES` | `2000000` | |
| `MAX_UPSTREAM_RESPONSE_BYTES` | `32000000` | |
| `UPSTREAM_HTTP2` | `true` | |
| `UPSTREAM_EXTRA_CA_FILE` | unset | Extra trusted CAs for provider TLS |
| `REQUIRE_HTTPS` | `true` | Set `false` only for local development |
| `ENABLE_DOCS` | `false` | Serves `/docs` and `/openapi.json` |
| `PENDING_TIMEOUT_MINUTES` | `60` | When a stuck transaction is refunded |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | unset | Both are needed to enable top-ups |

## Running it

Local development:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # fill it in; REQUIRE_HTTPS=false for local http
python -m aiproxy init-db
uvicorn aiproxy.main:app --reload
```

**Railway (recommended).** The repository includes `railway.json`. Follow
[docs/railway.md](docs/railway.md): deploy from GitHub, add PostgreSQL, set
`ADMIN_API_TOKEN` and provider keys, generate a domain. Then verify the live
deployment:

```bash
ADMIN_API_TOKEN=... python scripts/smoke_test.py --url https://<name>.up.railway.app
```

**Render or another container host.** Create a PostgreSQL database and a web
service from the `Dockerfile`, then set `DATABASE_URL`, `ADMIN_API_TOKEN` and
the provider keys.

On a VPS, run the container behind Caddy or nginx with TLS, and set
`FORWARDED_ALLOW_IPS` to the reverse proxy's address.

## Tests

```bash
pytest                                     # SQLite
TEST_DATABASE_URL=postgresql+asyncpg://user:pass@localhost/proxy_test pytest   # PostgreSQL
bandit -q -r aiproxy && pip-audit --skip-editable
```

The suite covers:

- A full billed round trip through every provider in the catalog, checking its URL and auth header.
- Model discovery, custom providers and config validation.
- Every row of the security table.
- Every failure mode, concurrent overspend and settle-once billing.
- The admin API and Stripe.

CI runs it on SQLite and PostgreSQL, with bandit and pip-audit.

## Known limitations

- **In-process limiters and caches.** Rate limiters and caches live in process memory. With several app instances, each enforces limits separately. Run one instance, or swap in a Redis-backed limiter, before scaling out.
- **Provider details are unverified live.** Endpoints come from official documentation, not from live calls. Starred providers above could not be confirmed there at all.
- **Some providers need an override.** Several have a China-region twin endpoint, and some are migrating URLs. Use `<NAME>_BASE_URL` when needed.
- **No schema migrations.** `init-db` creates missing tables but does not alter existing ones. Add Alembic before the first schema change in production.
- **Anthropic via the unified endpoint** supports text and images only. Tools need the native endpoint.
- **Token counts for native OpenAI streams** appear only if the client sets `stream_options.include_usage`. The flat fee is unaffected.
