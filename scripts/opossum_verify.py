"""Verify an Opossum disclosure package independently of the relay.

    python scripts/opossum_verify.py package.json --jwks https://<host>/opossum/.well-known/jwks.json
    python scripts/opossum_verify.py package.json --jwks jwks.json   # a saved copy, fully offline

Checks each receipt's Ed25519 signature against the published key, checks
that every shown field matches a digest inside the signed receipt, and checks
proven notes against their commitments. Exit status is 0 only if every
receipt verifies.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aiproxy.opossum.crypto import ReceiptInvalid, check_memo, verify_presentation  # noqa: E402


def load_jwks(source: str) -> dict:
    if source.startswith("https://"):
        with urllib.request.urlopen(source, timeout=10) as resp:  # nosec B310 - https only
            return json.load(resp)
    return json.loads(Path(source).read_text())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("package", help="disclosure package (.json) or a single receipt presentation")
    parser.add_argument("--jwks", required=True, help="https URL or file with the relay's public keys")
    args = parser.parse_args()

    text = Path(args.package).read_text().strip()
    items = json.loads(text)["items"] if text.startswith("{") else [{"presentation": text}]
    jwks = load_jwks(args.jwks)
    failures = 0
    for number, item in enumerate(items, 1):
        try:
            result = verify_presentation(item["presentation"], jwks)
        except ReceiptInvalid as exc:
            failures += 1
            print(f"receipt {number}: NOT VALID - {exc}")
            continue
        test = " [TEST MONEY]" if result["issuer_claims"].get("test") else ""
        print(f"receipt {number}: valid, signed by key {result['kid']}{test}")
        for name, value in result["disclosed"].items():
            print(f"  {name}: {value}")
        print(f"  ({result['hidden']} other fields stay sealed)")
        memo = item.get("memo")
        if memo:
            ok = check_memo(result["disclosed"].get("memo_commitment", ""), memo.get("text", ""), memo.get("salt", ""))
            print(f"  proven note {'matches' if ok else 'DOES NOT match'}: {memo.get('text')!r}")
            failures += 0 if ok else 1
        if item.get("context"):
            print(f"  stated by the payer (not signed): {item['context']}")
    print(f"{len(items) - failures} of {len(items)} verified")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
