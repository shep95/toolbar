# Deploying on Railway

The repository is ready for Railway as-is. `railway.json` tells Railway to:

- build from the `Dockerfile`;
- wait for `/readyz`, which only answers once the database is reachable, before switching traffic to a new deploy;
- restart the service if it crashes.

On start, the container waits up to a minute for PostgreSQL, creates any
missing tables, then serves on the port Railway provides in `$PORT`.

## 1. Create the project

1. Sign in at railway.com and click **New Project** → **Deploy from GitHub repo**.
2. Pick **shep95/toolbar**. If it isn't listed, click **Configure GitHub App** and give Railway access to the repository.
3. Railway starts a first build straight away. It fails the health check until the next steps are done, which is expected.

## 2. Add PostgreSQL

1. In the project canvas click **+ Create** → **Database** → **Add PostgreSQL**.
2. Open the app service (named `toolbar`), go to **Variables** → **New Variable** → **Add Reference**, and pick `DATABASE_URL` from the Postgres service. The value reads `${{Postgres.DATABASE_URL}}`, which uses Railway's private network, so database traffic never leaves Railway.

## 3. Set the variables

Under the app service → **Variables** → **Raw Editor**, paste and fill in:

```
ADMIN_API_TOKEN=<48+ random characters>
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
DEEPSEEK_API_KEY=
GOOGLE_API_KEY=
# ...any other <NAME>_API_KEY from .env.example
```

Generate the admin token on your own machine, and keep it out of chat and
tickets:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Only set keys for the providers you want to offer. The rest stay switched
off. Everything else has safe defaults, including the $0.03 fee, the rate
limits and HTTPS enforcement. `.env.example` lists every option.

Optional but recommended:

- `ADMIN_ALLOWED_IPS=<your office or home IP>`. Everyone else then gets 404 from `/admin`.
- `MAX_OUTPUT_TOKENS=8192`, or whatever suits your models. This caps what one $0.03 request can cost you.

## 4. Give it a public URL

App service → **Settings** → **Networking** → **Generate Domain**. You get
`https://<name>.up.railway.app`. Railway terminates TLS and forwards
`X-Forwarded-Proto: https`, which the proxy requires. To add your own domain,
use **Custom Domain** and add the CNAME record it shows.

## 5. Deploy and verify

Railway redeploys whenever variables change. Wait for the deployment to turn
**Active**, then run the post-deploy check from your machine:

```bash
pip install httpx
ADMIN_API_TOKEN=<your token> python scripts/smoke_test.py --url https://<name>.up.railway.app
```

It checks:

- health, database readiness and HTTPS enforcement;
- security headers and admin authentication;
- the full key lifecycle, provider and model listing;
- that bad keys, zero balances and cost-amplification requests are refused.

It uses throwaway test users and cleans them up afterwards. To also make one
real, billed call per model and confirm the $0.03 charge lands correctly:

```bash
python scripts/smoke_test.py --url https://<name>.up.railway.app \
  --model openai/gpt-5-mini --model deepseek/deepseek-chat
```

Then open `https://<name>.up.railway.app/admin`, enter the admin token,
create your first real user and issue their key.

## 6. Settings to keep

- **Replicas: keep at 1.** Rate limits and caches live in the app's memory. With more replicas, each enforces limits separately. See the README's known limitations before scaling out.
- **Region:** put the app and PostgreSQL in the same region. Every request makes one database round trip.
- **Stripe top-ups.** Users buy credit through Stripe Checkout, and the signed webhook adds it to their balance. The app needs:
  - `STRIPE_SUCCESS_URL` = `https://<name>.up.railway.app/billing/success`, and `STRIPE_CANCEL_URL` = `https://<name>.up.railway.app/billing/cancel`. The app serves both pages.
  - A webhook endpoint in Stripe pointing to `https://<name>.up.railway.app/stripe/webhook`, for the events `checkout.session.completed` and `checkout.session.async_payment_succeeded`. Put its signing secret (`whsec_...`) in `STRIPE_WEBHOOK_SECRET`.
  - A **restricted** key (`rk_live_...`) in `STRIPE_SECRET_KEY`. In Stripe's dashboard go to **Developers → API keys → Create restricted key**, and set **Checkout Sessions** to **Write** and everything else to **None**. If a checkout then fails with a permissions error in the app's logs, also give **Products** and **Prices** Write.

  Sales of your other products on the same Stripe account are ignored: only sessions this app created credit anything.
- **Backups:** the PostgreSQL service has a **Backups** tab. Turn backups on, since the database holds every balance.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Deploy fails the health check | `DATABASE_URL` is missing or not referencing the Postgres service. Deploy logs show `database not reachable yet` retries. |
| `/admin/api/...` returns 503 | `ADMIN_API_TOKEN` is unset or shorter than 32 characters |
| A provider returns 503 `provider_not_configured` | Its `<NAME>_API_KEY` variable is not set |
| A provider returns 502 `upstream_auth_failed` | The provider rejected the key in its variable |
| Deploy crashes with `base URL must be an https:// URL` | A `<NAME>_BASE_URL` override is not HTTPS |
| Every request returns 400 `https_required` | The request reached the app without Railway's TLS proxy, for example through a TCP proxy. Use the generated HTTPS domain. |

Logs are one JSON object per line. Filter in Railway's log view with, for
example, `@level:ERROR` or `"event":"upstream_failed"`.
