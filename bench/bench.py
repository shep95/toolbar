"""Measure the latency the proxy adds on top of the provider.

    python bench/bench.py --proxy http://127.0.0.1:8000 --direct http://127.0.0.1:9100/v1 \
        --key apx_... --requests 2000 --concurrency 32

Run bench/fake_upstream.py as the provider so its own time is near zero.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import time

import httpx

BODY = {"model": "openai/bench-model", "messages": [{"role": "user", "content": "hi"}]}


async def run(client: httpx.AsyncClient, url: str, headers: dict, body: dict, n: int, concurrency: int, stream: bool):
    latencies: list[float] = []
    ttfb: list[float] = []
    errors = 0
    queue = asyncio.Queue()
    for _ in range(n):
        queue.put_nowait(None)

    async def worker():
        nonlocal errors
        while not queue.empty():
            queue.get_nowait()
            start = time.perf_counter()
            try:
                if stream:
                    async with client.stream("POST", url, json=body, headers=headers) as r:
                        first = None
                        async for _ in r.aiter_raw():
                            if first is None:
                                first = time.perf_counter()
                        ok = r.status_code == 200
                    if first:
                        ttfb.append(first - start)
                else:
                    r = await client.post(url, json=body, headers=headers)
                    ok = r.status_code == 200
            except httpx.HTTPError:
                ok = False
            if ok:
                latencies.append(time.perf_counter() - start)
            else:
                errors += 1

    began = time.perf_counter()
    await asyncio.gather(*[worker() for _ in range(concurrency)])
    elapsed = time.perf_counter() - began
    latencies.sort()

    def pct(values, p):
        return values[min(len(values) - 1, int(len(values) * p))] * 1000 if values else float("nan")

    return {
        "ok": len(latencies),
        "errors": errors,
        "rps": len(latencies) / elapsed,
        "p50_ms": pct(latencies, 0.50),
        "p90_ms": pct(latencies, 0.90),
        "p99_ms": pct(latencies, 0.99),
        "mean_ms": statistics.fmean(latencies) * 1000 if latencies else float("nan"),
        "ttfb_p50_ms": pct(sorted(ttfb), 0.50) if ttfb else None,
    }


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--direct", help="provider base URL to measure without the proxy")
    parser.add_argument("--key", required=True)
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--stream", action="store_true")
    args = parser.parse_args()

    body = {**BODY, "stream": True} if args.stream else BODY
    limits = httpx.Limits(max_connections=args.concurrency, max_keepalive_connections=args.concurrency)
    async with httpx.AsyncClient(limits=limits, timeout=30, trust_env=False) as client:
        proxy_headers = {"Authorization": f"Bearer {args.key}", "X-Forwarded-Proto": "https"}
        url = args.proxy.rstrip("/") + "/v1/chat/completions"
        await run(client, url, proxy_headers, body, 100, args.concurrency, args.stream)  # warm-up
        through = await run(client, url, proxy_headers, body, args.requests, args.concurrency, args.stream)
        rows = [("through proxy", through)]
        if args.direct:
            direct_body = {**body, "model": "bench-model"}
            direct_url = args.direct.rstrip("/") + "/chat/completions"
            await run(client, direct_url, {}, direct_body, 100, args.concurrency, args.stream)
            direct = await run(client, direct_url, {}, direct_body, args.requests, args.concurrency, args.stream)
            rows.insert(0, ("direct to provider", direct))

    print(f"{'':20} {'ok':>6} {'err':>4} {'req/s':>8} {'p50 ms':>8} {'p90 ms':>8} {'p99 ms':>8}")
    for name, r in rows:
        print(f"{name:20} {r['ok']:>6} {r['errors']:>4} {r['rps']:>8.0f} {r['p50_ms']:>8.2f} {r['p90_ms']:>8.2f} {r['p99_ms']:>8.2f}")
    if args.direct:
        print(f"proxy overhead at p50: {rows[1][1]['p50_ms'] - rows[0][1]['p50_ms']:.2f} ms")


if __name__ == "__main__":
    asyncio.run(main())
