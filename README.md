# AI API Proxy

A universal AI API proxy. Your users call one endpoint with a key you issued.
The proxy routes each request to the right upstream provider (OpenAI,
Anthropic or Mistral), charges a fee per request, tracks usage, and manages
user keys and balances.

Built with Python (FastAPI) and PostgreSQL.

## Components

Each component has one job and lives in its own module.

| Component | Module | Job |
|---|---|---|
| Gateway | `aiproxy/gateway.py` | Front door. Validates the key, the user's status, rate limit and body before anything else runs. |
| Router | `aiproxy/router.py` | Works out which provider the request targets and picks its connector. Enforces key-to-provider binding. |
| Billing engine | `aiproxy/billing.py` | Reserves the fee, logs the transaction, then settles (charge) or refunds (failure). Runs on every proxied request. |
| Upstream connector | `aiproxy/upstream.py` + `aiproxy/connectors/` | Makes the real provider call and handles the response, including streaming. One connector class per provider. |
| Admin layer | `aiproxy/admin.py` + `aiproxy/static/admin.html` | Users, keys, balances, pricing, usage dashboard and audit log, behind a separate admin token. |

Supporting modules: `payments.py` (Stripe top-ups), `ratelimit.py`,
`security.py` (key generation and hashing), `audit.py`, `models.py` (schema).

## Request flow

```
client ──► gateway: HTTPS? key present and well-formed? key in DB and active?
               │           no ──► 401 (logged)
               ├─ user suspended ──────────────────────► 403 (logged)
               ├─ key bound to a different provider ───► 403 (logged)
               ├─ over the key's rate limit ───────────► 429 + Retry-After (logged)
               ├─ body too large / invalid ────────────► 413 / 400 (logged)
               ▼
           router: provider from "provider/model" (or the key's provider)
               ▼
           billing.reserve: in one DB transaction, deduct the fee only if the
           user is active and balance > 0 and balance >= fee, then insert a
           "pending" transaction
               ├─ cannot afford ───────────────────────► 402 (logged, not forwarded)
               ├─ database down ───────────────────────► 503 (nothing sent upstream)
               ▼
           upstream connector: call the provider with the proxy's own credentials
               ├─ unreachable ─────────────────────────► 502, refunded, "failed"
               ├─ timeout ─────────────────────────────► 504, refunded, "failed"
               ├─ provider 5xx ────────────────────────► 502, refunded, "failed"
               ├─ provider 4xx (bad model, etc.) ──────► same status and body, refunded
               ├─ provider rejects OUR credentials ────► 502 (never blamed on the caller)
               ▼
           billing.complete: final fee from usage, mark "success"
               ▼
           response to client, with X-Fee-Charged and X-Balance-Remaining headers
```

The fee is reserved before the upstream call rather than deducted after it.
That way two concurrent requests can never both spend the user's last cent.
A reservation settles exactly once. It becomes either a charge or a full
refund, because settlement only touches a transaction still marked
`pending`. A background task refunds any transaction left pending longer than
`PENDING_TIMEOUT_MINUTES`, for example after a crash.

## Data model

Core tables from the spec, plus three supporting tables. Money is
`NUMERIC(18,6)` dollars, never floats.

- **users**: `id`, `email`, `created_at`, `balance`, `status` (active / suspended).
- **api_keys**: `id`, `user_id`, `key_hash`, `key_prefix`, `name`, `provider`, `rate_limit_per_minute`, `created_at`, `last_used_at`, `status` (active / revoked).
- **transactions**: `id`, `user_id`, `api_key_id`, `provider`, `model_called`, `endpoint`, `tokens_used`, `input_tokens`, `output_tokens`, `fee_charged`, `timestamp`, `completed_at`, `status` (pending / success / failed / error), `upstream_status`, `latency_ms`, `error`, `request_id`.
- **pricing**: admin-set fees per provider and model.
- **balance_adjustments**: every credit from an admin or Stripe. The Stripe session ID is unique, so a replayed webhook never credits twice.
- **audit_log**: every rejected request, with status, outcome, key prefix and IP.

`key_hash` is the SHA-256 of the key. The raw key is generated with 256 bits
of randomness, shown once when issued, and never stored. It looks like
`apx_` followed by 43 characters.

## Using the proxy

### Unified endpoint: OpenAI format for every provider

Send OpenAI chat-completions requests and prefix the model with the provider.
Anthropic requests and responses are translated both ways, streaming included.

```bash
curl https://your-proxy.example/v1/chat/completions \
  -H "Authorization: Bearer apx_..." \
  -H "Content-Type: application/json" \
  -d '{"model": "anthropic/claude-sonnet-5-5", "messages": [{"role": "user", "content": "Hello"}]}'
```

```python
from openai import OpenAI

client = OpenAI(api_key="apx_...", base_url="https://your-proxy.example/v1")
client.chat.completions.create(model="openai/gpt-5", messages=[...])
client.chat.completions.create(model="mistral/mistral-large-latest", messages=[...])
client.chat.completions.create(model="anthropic/claude-sonnet-5-5", messages=[...], stream=True)
```

A key bound to a single provider may drop the prefix, as in `model="gpt-5"`.
Through the unified endpoint, Anthropic supports text and images. Tool
calling and `response_format` return a 400 that points to the native
endpoint below.

### Native endpoints: official SDKs unchanged

Point any official SDK at `/<provider>/v1` and use the proxy key as the API key.
The body is forwarded untouched.

```python
import anthropic, openai

anthropic.Anthropic(api_key="apx_...", base_url="https://your-proxy.example/anthropic")
openai.OpenAI(api_key="apx_...", base_url="https://your-proxy.example/openai/v1")
openai.OpenAI(api_key="apx_...", base_url="https://your-proxy.example/mistral/v1")
```

Only these endpoints can be reached. Everything else returns 404, so the proxy
cannot be used to reach files, fine-tuning or account endpoints on your
provider accounts.

| Provider | Native endpoints |
|---|---|
| openai | `chat/completions`, `completions`, `embeddings`, `responses` |
| anthropic | `messages` |
| mistral | `chat/completions`, `embeddings`, `fim/completions` |

### Account and top-ups

- `GET /v1/account` returns the caller's balance and key details. It is not billed.
- `POST /v1/billing/checkout` with `{"amount_usd": 20}` returns a Stripe Checkout URL, when Stripe is configured.

## Admin

Every admin route needs `Authorization: Bearer $ADMIN_API_TOKEN`. That token
is separate from user keys: user keys cannot reach admin routes, and the admin
token cannot proxy traffic. If the token is unset or shorter than 32
characters, the admin API is disabled.

Open `/admin` in a browser for the dashboard. It shows overview numbers,
revenue per day, users, keys, pricing, recent transactions and rejected
requests. The page holds no data itself. It calls the API with the token you
type in.

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/api/overview` | Totals for the last 24 hours and 30 days, plus which providers are configured |
| POST | `/admin/api/users` | Create a user with `email` and an optional `initial_balance` |
| GET | `/admin/api/users` | List users, filtered by `q` and `status` |
| GET / PATCH | `/admin/api/users/{id}` | Show a user with their keys and credits, or set `status` |
| POST | `/admin/api/users/{id}/credits` | Add or remove balance with `amount` and `note` |
| POST | `/admin/api/users/{id}/keys` | Issue a key with `provider`, `name` and `rate_limit_per_minute`. The raw key is returned once. |
| GET | `/admin/api/users/{id}/keys` | List keys, without the raw key |
| DELETE | `/admin/api/keys/{id}` | Revoke a key |
| GET / PUT | `/admin/api/pricing` | List or upsert fee rules |
| DELETE | `/admin/api/pricing/{id}` | Delete a fee rule |
| GET | `/admin/api/transactions` | Transactions, filtered by user, key, provider or status |
| GET | `/admin/api/usage` | Daily totals per provider and top users |
| GET | `/admin/api/audit` | Rejected requests |
| POST | `/admin/api/maintenance/reconcile` | Refund stale pending transactions now |

Quick start:

```bash
TOKEN=...   # your ADMIN_API_TOKEN
USER=$(curl -s -X POST https://your-proxy.example/admin/api/users \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "initial_balance": "10"}' | jq -r .id)
curl -s -X POST https://your-proxy.example/admin/api/users/$USER/keys \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"provider": "any", "name": "alice laptop"}'
```

## Pricing

The default is a flat fee per request, set by `DEFAULT_FEE_PER_REQUEST`, which
defaults to $0.03. Admins can add rules. The most specific rule wins:
`(provider, model)`, then `(provider, *)`, then `(*, *)`, then the default.

Each rule has `fee_per_request` and `fee_per_1k_tokens`. With the token rate
at 0 the rule is a pure flat fee. Set it above 0 to switch to token-based
pricing, since token counts are already parsed from every provider's response
and stream.

With token-based pricing, the flat part is reserved up front and the token
part is charged on completion. A large response can therefore leave a balance
slightly negative, which blocks the user's next request until they top up.

## Failure model

| Failure | What happens |
|---|---|
| Upstream provider is down | 502 to the user, no charge, transaction marked `failed` |
| Upstream times out | 504, no charge |
| Stream drops mid-way or the provider sends an error event | Error event sent to the client, no charge |
| User key stolen and spammed | Per-key rate limit with 429 and `Retry-After`. The key can be revoked. |
| Balance runs out | Checked atomically before forwarding, 402 |
| Database down | 503 before anything is sent upstream. `/readyz` reports it. |
| Provider changes its API format | Only that provider's connector changes |
| Someone sends a provider key, or two credentials | 401 or 400 at the gateway. Client headers are never forwarded. |
| Flood of bad keys from one IP | Past 30 per minute, rejections go only to the app log so the audit table can't be flooded |
| Crash or bug after the fee was reserved | Refunded immediately on error, or by the background sweep |

## Security posture

- Raw keys are never stored. Only the SHA-256 hash and a short display prefix are kept.
- Provider credentials come from environment variables only. The admin layer can see whether a provider is configured, never the key.
- HTTPS is required. Plain-HTTP requests get a 400, except `/healthz` and `/readyz` for platform probes. HSTS is sent on every response.
- Every key has a rate limit.
- Every request is logged as a JSON line on stdout. Billed requests are rows in `transactions` and rejected ones are rows in `audit_log`. Raw keys and request bodies are never logged.
- Admin routes use a separate token, compared in constant time.
- The upstream request is built from scratch: client headers such as cookies and organisation IDs never reach the provider.
- Stripe webhooks are checked against the signing secret with a 5-minute replay window. Credits are idempotent.

## Configuration

All settings are environment variables. See `.env.example`.

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | — | `postgres://` URLs from Railway or Render work as-is |
| `ADMIN_API_TOKEN` | unset | At least 32 characters. `python -m aiproxy gen-admin-token` makes one. |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `MISTRAL_API_KEY` | unset | A provider without a key returns 503 |
| `DEFAULT_FEE_PER_REQUEST` | `0.03` | Dollars |
| `RATE_LIMIT_PER_MINUTE` | `60` | Per key, unless the key has its own limit |
| `REQUIRE_HTTPS` | `true` | Set `false` only for local development |
| `MAX_REQUEST_BYTES` | `2000000` | |
| `UPSTREAM_TIMEOUT_SECONDS` | `120` | |
| `PENDING_TIMEOUT_MINUTES` | `60` | When a stuck transaction is refunded |
| `ANTHROPIC_DEFAULT_MAX_TOKENS` | `4096` | Used when a unified request omits `max_tokens` |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | unset | Both are needed to enable top-ups |
| `STRIPE_SUCCESS_URL`, `STRIPE_CANCEL_URL` | example.com | Where Checkout sends the user back to |

## Running it

Local development:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env            # fill it in; REQUIRE_HTTPS=false for local http
python -m aiproxy init-db       # creates tables; safe to re-run
uvicorn aiproxy.main:app --reload
```

To deploy on Railway or Render:

1. Create a PostgreSQL database and a web service from this repository. It builds from the `Dockerfile`.
2. Set `DATABASE_URL`, `ADMIN_API_TOKEN` and the provider keys in the service's environment settings.
3. The container runs `init-db` on start, then serves on `$PORT`. The platform terminates TLS.
4. For Stripe, point a webhook at `https://<host>/stripe/webhook` for `checkout.session.completed` and `checkout.session.async_payment_succeeded`.

On a VPS, run the same container behind Caddy or nginx with TLS. The proxy
must set `X-Forwarded-Proto`.

## Tests

```bash
pytest                                     # SQLite
TEST_DATABASE_URL=postgresql+asyncpg://user:pass@localhost/proxy_test pytest   # PostgreSQL
```

The suite mocks every provider. It covers each rejection path, all three
connectors, streaming translation, every failure-model row, concurrent
overspend, settle-once billing, the reconciler, the admin API and Stripe
webhooks. CI runs it against both databases.

## Build order status

| Step | Status |
|---|---|
| 1. Database schema | Done |
| 2. Gateway: key validation | Done |
| 3. OpenAI connector | Done |
| 4. Billing engine | Done |
| 5. Admin panel | Done: API and dashboard |
| 6. Anthropic connector | Done, with OpenAI-format translation |
| 7. Rate limiting | Done, per key |
| 8. Stripe top-ups | Done |
| 9. More providers | Mistral done. Add one by subclassing `Connector` and registering it in `connectors/__init__.py`. |

## Known limitations

- The rate limiter keeps its counters in process memory. With more than one app instance, each instance enforces the limit separately. Swap in a Redis-backed limiter before scaling out.
- `init-db` creates missing tables but does not alter existing ones. Add Alembic before the first schema change in production.
- Through the unified endpoint, Anthropic requests support text and images only. Tools need the native endpoint.
- Native OpenAI streams report tokens only if the client sets `stream_options.include_usage`. Flat fees are unaffected. With token pricing, such a stream is charged the flat part only.
- If a client disconnects during a non-streaming call, the reservation is refunded by the background sweep rather than charged.
