"""Check that a deployed proxy is fully operational.

    python scripts/smoke_test.py --url https://your-app.up.railway.app

    # also make one real, billed call per model (costs provider tokens):
    python scripts/smoke_test.py --url https://... --model openai/gpt-5-mini --model deepseek/deepseek-chat

Reads the admin token from --admin-token or the ADMIN_API_TOKEN environment
variable. It creates throwaway test users, then revokes their keys and
suspends them at the end. Exits non-zero if any check fails.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import uuid
import sys
import time
from decimal import Decimal

import httpx

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True, help="public base URL of the deployment")
    parser.add_argument("--admin-token", default=os.environ.get("ADMIN_API_TOKEN"))
    parser.add_argument("--model", action="append", default=[], help="provider/model for a real billed call (repeatable)")
    parser.add_argument(
        "--assume-https", action="store_true",
        help="send X-Forwarded-Proto: https (only for testing a local container without a TLS proxy)",
    )
    parser.add_argument(
        "--webhook-secret", default=os.environ.get("STRIPE_WEBHOOK_SECRET"),
        help="Stripe signing secret (whsec_...); enables the top-up checks (no card is charged)",
    )
    parser.add_argument(
        "--wait-seconds", type=int, default=0,
        help="first wait up to this long for the app to be ready and every --model provider to be configured",
    )
    args = parser.parse_args()
    if not args.admin_token:
        parser.error("pass --admin-token or set ADMIN_API_TOKEN")

    base = args.url.rstrip("/")
    extra = {"X-Forwarded-Proto": "https"} if args.assume_https else {}
    c = httpx.Client(base_url=base, headers=extra, timeout=60, follow_redirects=False)
    admin = {"Authorization": f"Bearer {args.admin_token}"}
    wait_until_ready(c, admin, [m.split("/", 1)[0] for m in args.model], args.wait_seconds)
    created_users: list[str] = []
    created_keys: list[str] = []

    try:
        # --- platform -------------------------------------------------------
        r = c.get("/healthz")
        check("liveness /healthz", r.status_code == 200, f"HTTP {r.status_code}")
        r = c.get("/readyz")
        check("database reachable /readyz", r.status_code == 200 and r.json().get("database") == "up", r.text[:80])

        if base.startswith("https://"):
            plain = httpx.get("http://" + base[len("https://"):] + "/v1/account", follow_redirects=False, timeout=30)
            check("plain HTTP is not served", plain.status_code in (301, 302, 307, 308, 400), f"HTTP {plain.status_code}")

        r = c.get("/v1/account")
        h = r.headers
        check("unauthenticated request is refused", r.status_code == 401, f"HTTP {r.status_code}")
        check(
            "security headers present",
            h.get("x-content-type-options") == "nosniff" and h.get("x-frame-options") == "DENY"
            and "max-age" in h.get("strict-transport-security", "") and h.get("cache-control") == "no-store",
        )
        check("server software not advertised", "uvicorn" not in h.get("server", "").lower(), h.get("server", "none"))
        check("API docs not exposed", c.get("/openapi.json").status_code == 404)

        # --- admin ----------------------------------------------------------
        r = c.get("/admin/api/overview", headers={"Authorization": "Bearer wrong-token"})
        check("admin rejects a wrong token", r.status_code == 401, f"HTTP {r.status_code}")
        r = c.get("/admin/api/overview", headers=admin)
        if not check("admin API reachable with the token", r.status_code == 200, f"HTTP {r.status_code}"):
            return summary()
        overview = r.json()
        configured = sorted(n for n, p in overview["providers"].items() if p["configured"])
        check("providers with credentials", bool(configured), ", ".join(configured) or "none: set <NAME>_API_KEY variables")
        check("dashboard page served", c.get("/admin").status_code == 200)

        # --- keys and rejections ---------------------------------------------
        stamp = int(time.time())
        r = c.post("/admin/api/users", json={"email": f"smoke-{stamp}@example.com", "initial_balance": "1.00"}, headers=admin)
        if not check("create user", r.status_code == 201, f"HTTP {r.status_code}"):
            return summary()
        user = r.json()
        created_users.append(user["id"])
        r = c.post(f"/admin/api/users/{user['id']}/keys", json={"provider": "any", "name": "smoke-test"}, headers=admin)
        if not check("issue key", r.status_code == 201 and r.json()["api_key"].startswith("apx_")):
            return summary()
        key = r.json()
        created_keys.append(key["id"])
        auth = {"Authorization": f"Bearer {key['api_key']}"}

        r = c.get("/v1/account", headers=auth)
        check("key authenticates", r.status_code == 200 and r.json()["balance"] == "1.000000", r.text[:80])
        r = c.get("/v1/providers", headers=auth)
        check("provider list", r.status_code == 200, f"{len(r.json().get('data', []))} providers" if r.status_code == 200 else r.text[:80])
        r = c.get("/v1/models", headers=auth)
        check("model list", r.status_code == 200, f"{len(r.json().get('data', []))} models" if r.status_code == 200 else r.text[:80])

        # --- general transactions and country-adjusted fees ----------------------
        spent = Decimal("0")
        ref = f"smoke-tx-{stamp}"
        body = {"reference": ref, "type": "payment", "amount": "250", "currency": "EUR", "country": "DE"}
        r = c.post("/v1/transactions", json=body, headers=auth)
        ok = r.status_code == 201 and r.json()["fee"]["amount_usd"] == "0.030000"
        check("record a transaction (base fee $0.03)", ok, r.text[:120] if not ok else "")
        if ok:
            spent += Decimal("0.03")
        r = c.post("/v1/transactions", json=body, headers=auth)
        check("same reference is not charged twice", r.status_code == 200 and r.json().get("replayed") is True,
              f"HTTP {r.status_code}")
        r = c.patch(f"/admin/api/users/{user['id']}", json={"country": "IN"}, headers=admin)
        r = c.post("/v1/transactions", json={**body, "reference": ref + "-in"}, headers=auth)
        ok = r.status_code == 201 and r.json()["fee"]["amount_usd"] == "0.010500"
        check("fee adjusts to the account's country (IN: $0.0105)", ok, r.text[:120] if not ok else "")
        if ok:
            spent += Decimal("0.0105")
        c.patch(f"/admin/api/users/{user['id']}", json={"country": None}, headers=admin)
        r = c.get("/v1/transactions", params={"reference": ref}, headers=auth)
        check("transactions can be listed", r.status_code == 200 and len(r.json().get("data", [])) == 1)

        # --- domains: brokerage, crypto, and keys locked to one domain ----------
        trade = {"reference": ref + "-trade", "domain": "brokerage", "type": "buy", "amount": "2275.20",
                 "currency": "USD", "attributes": {"symbol": "aapl", "quantity": "10", "price": "227.52"}}
        r = c.post("/v1/transactions", json=trade, headers=auth)
        ok = r.status_code == 201 and r.json().get("attributes", {}).get("symbol") == "AAPL"
        check("brokerage trade recorded (Robinhood-style)", ok, r.text[:120] if not ok else "")
        spent += Decimal("0.03") if ok else 0
        onramp = {"reference": ref + "-onramp", "domain": "crypto", "type": "onramp", "amount": "100",
                  "currency": "USD", "attributes": {"asset": "btc", "quantity": "0.0015", "network": "bitcoin"}}
        r = c.post("/v1/transactions", json=onramp, headers=auth)
        ok = r.status_code == 201 and r.json().get("attributes", {}).get("asset") == "BTC"
        check("crypto on-ramp recorded (MoonPay-style)", ok, r.text[:120] if not ok else "")
        spent += Decimal("0.03") if ok else 0
        bad = {**trade, "reference": ref + "-bad", "attributes": {"quantity": "10"}}
        r = c.post("/v1/transactions", json=bad, headers=auth)
        check("incomplete trade is refused and not charged", r.status_code == 400, f"HTTP {r.status_code}")
        r = c.post(f"/admin/api/users/{user['id']}/keys", json={"domain": "crypto", "name": "smoke-crypto"}, headers=admin)
        crypto_key = r.json()
        created_keys.append(crypto_key["id"])
        crypto_auth = {"Authorization": f"Bearer {crypto_key['api_key']}"}
        r1 = c.post("/v1/transactions", json={**trade, "reference": ref + "-x"}, headers=crypto_auth)
        r2 = c.get("/v1/providers", headers=crypto_auth)
        check("crypto-only key is kept out of other domains and the AI gateway",
              r1.status_code == 403 and r2.status_code == 403, f"HTTP {r1.status_code}/{r2.status_code}")
        r = c.get("/v1/domains", headers=auth)
        check("domains listed", r.status_code == 200 and len(r.json().get("data", [])) >= 8,
              f"{len(r.json().get('data', []))} domains" if r.status_code == 200 else f"HTTP {r.status_code}")

        # These checks need a provider that is switched on; none of them reaches it.
        probe = args.model[0] if args.model else (f"{configured[0]}/smoke-test-model" if configured else "openai/x")
        chat = {"model": probe, "messages": [{"role": "user", "content": "hi"}]}
        r = c.post("/v1/chat/completions", json=chat, headers={"Authorization": "Bearer sk-proj-" + "x" * 40})
        check("provider keys are refused", r.status_code == 401, f"HTTP {r.status_code}")
        if configured:
            r = c.post("/v1/chat/completions", json={**chat, "n": 5}, headers=auth)
            check("cost-amplification guard (n=5)", r.status_code == 400, f"HTTP {r.status_code}")

            r = c.post("/admin/api/users", json={"email": f"smoke-empty-{stamp}@example.com"}, headers=admin)
            empty = r.json()
            created_users.append(empty["id"])
            r = c.post(f"/admin/api/users/{empty['id']}/keys", json={"provider": "any"}, headers=admin)
            created_keys.append(r.json()["id"])
            r = c.post("/v1/chat/completions", json=chat, headers={"Authorization": f"Bearer {r.json()['api_key']}"})
            check("zero balance is refused before any provider call", r.status_code == 402, f"HTTP {r.status_code}")
        else:
            print("SKIP  cost guard and zero-balance checks (no provider has credentials yet)")

        # --- Stripe top-ups ---------------------------------------------------
        if args.webhook_secret:
            stripe_checks(c, admin, args.webhook_secret, auth, bool(overview.get("stripe_enabled")), stamp, created_users)
        else:
            print("SKIP  Stripe checks (pass --webhook-secret or set STRIPE_WEBHOOK_SECRET)")

        # --- real billed calls -------------------------------------------------
        balance = Decimal("1.00") - spent
        for model in args.model:
            r = c.post(
                "/v1/chat/completions",
                json={"model": model, "messages": [{"role": "user", "content": "Reply with the word ok."}], "max_tokens": 16},
                headers=auth,
            )
            ok = r.status_code == 200
            fee = r.headers.get("x-fee-charged")
            detail = f"fee {fee}" if ok else f"HTTP {r.status_code}: {r.text[:160]}"
            check(f"live call {model}", ok and fee is not None, detail)
            if ok and fee:
                balance -= Decimal(fee)
        if args.model:
            time.sleep(1)  # settlement is written just after the response
            r = c.get("/v1/account", headers=auth)
            got = Decimal(r.json()["balance"])
            check("balance matches fees charged", got == balance, f"expected {balance:.6f}, got {got:.6f}")
            r = c.get("/admin/api/transactions", params={"user_id": user["id"]}, headers=admin)
            statuses = sorted(t["status"] for t in r.json())
            check("transactions recorded", len(statuses) == len(args.model), ", ".join(statuses))
        else:
            print("SKIP  live provider calls (pass --model provider/model to run them)")
    finally:
        for key_id in created_keys:
            c.delete(f"/admin/api/keys/{key_id}", headers=admin)
        for user_id in created_users:
            c.patch(f"/admin/api/users/{user_id}", json={"status": "suspended"}, headers=admin)
        if created_keys:
            r = c.get("/v1/account", headers=auth) if "auth" in locals() else None
            if r is not None:
                check("revoked key stops working", r.status_code == 401, f"HTTP {r.status_code}")
    return summary()


def _signed(payload: bytes, secret: str) -> dict:
    ts = str(int(time.time()))
    sig = hmac.new(secret.encode(), ts.encode() + b"." + payload, hashlib.sha256).hexdigest()
    return {"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"}


def _event(user_id: str, session_id: str, cents: int, purpose: str | None = "aiproxy_topup") -> bytes:
    metadata = {"purpose": purpose, "user_id": user_id} if purpose else {"order": "other-product"}
    return json.dumps({
        "id": "evt_selfcheck_" + uuid.uuid4().hex[:12],
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": session_id, "client_reference_id": user_id, "payment_status": "paid", "currency": "usd",
            "amount_subtotal": cents, "amount_total": cents, "metadata": metadata,
        }},
    }).encode()


def stripe_checks(c, admin, secret, user_auth, stripe_key_set, stamp, created_users) -> None:
    """Exercise the live webhook with correctly signed events. No card is charged."""
    r = c.post("/admin/api/users", json={"email": f"smoke-stripe-{stamp}@example.com"}, headers=admin)
    user = r.json()
    created_users.append(user["id"])

    def balance() -> str:
        return c.get(f"/admin/api/users/{user['id']}", headers=admin).json()["balance"]

    session = f"cs_selfcheck_{stamp}_{uuid.uuid4().hex[:8]}"
    payload = _event(user["id"], session, 100)
    r = c.post("/stripe/webhook", content=payload, headers=_signed(payload, secret))
    check("webhook accepts a signed payment and credits $1.00", r.status_code == 200 and r.json().get("credited") == "1",
          r.text[:120])
    check("balance credited", balance() == "1.000000", balance())
    r = c.post("/stripe/webhook", content=payload, headers=_signed(payload, secret))
    check("replayed payment is not credited twice", r.json().get("duplicate") is True and balance() == "1.000000", r.text[:80])
    r = c.post("/stripe/webhook", content=payload, headers=_signed(payload, "whsec_wrong"))
    check("forged webhook signature is rejected", r.status_code == 400, f"HTTP {r.status_code}")
    other = _event(user["id"], session + "_other", 5000, purpose=None)
    r = c.post("/stripe/webhook", content=other, headers=_signed(other, secret))
    check("other products' sales are ignored", r.status_code == 200 and balance() == "1.000000", r.text[:80])

    if stripe_key_set:
        r = c.post("/v1/billing/checkout", json={"amount_usd": 5}, headers=user_auth)
        url = r.json().get("checkout_url", "") if r.status_code == 200 else ""
        check("checkout page can be opened", url.startswith("https://checkout.stripe.com/"),
              "unpaid page, expires by itself" if url else f"HTTP {r.status_code}: {r.text[:160]}")
    else:
        print("SKIP  checkout page (STRIPE_SECRET_KEY is not set on the app yet)")


def wait_until_ready(c: httpx.Client, admin: dict, providers: list[str], seconds: int) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if c.get("/readyz").status_code == 200:
                r = c.get("/admin/api/overview", headers=admin)
                configured = {n for n, p in r.json().get("providers", {}).items() if p["configured"]} if r.status_code == 200 else set()
                if r.status_code == 200 and set(providers) <= configured:
                    return
        except (httpx.HTTPError, ValueError):
            pass
        print("waiting for the deployment to be ready...", flush=True)
        time.sleep(5)


def summary() -> int:
    failed = [name for name, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    if failed:
        print("failed: " + "; ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
