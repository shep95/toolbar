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
import os
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

        # --- real billed calls -------------------------------------------------
        balance = Decimal("1.00")
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
