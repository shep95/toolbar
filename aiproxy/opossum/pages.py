"""Opossum pages and static files, served with a locked-down policy.

Only this site's own script and stylesheet run (``script-src 'self'``), no
third-party code is loaded, and Trusted Types forbids turning strings into
markup, so the ledger's contents can never become code.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from ..services import get_services
from .web import keys

router = APIRouter()
STATIC = Path(__file__).resolve().parent.parent / "static"

PAGE_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; manifest-src 'self'; "
        "require-trusted-types-for 'script'; trusted-types 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": (
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), "
        "microphone=(), midi=(), payment=(), usb=(), serial=(), hid=(), clipboard-read=(), clipboard-write=(self)"
    ),
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    "Cache-Control": "no-store",
}

FILES = {
    "/opossum": ("opossum.html", "text/html; charset=utf-8"),
    "/opossum/verify": ("opossum-verify.html", "text/html; charset=utf-8"),
    "/opossum/app.js": ("opossum.js", "text/javascript; charset=utf-8"),
    "/opossum/verify.js": ("opossum-verify.js", "text/javascript; charset=utf-8"),
    "/opossum/app.css": ("opossum.css", "text/css; charset=utf-8"),
    "/opossum/scene.svg": ("opossum-scene.svg", "image/svg+xml"),
}
_CACHE: dict[str, bytes] = {}


def _load(name: str) -> bytes:
    if name not in _CACHE:
        _CACHE[name] = (STATIC / name).read_bytes()
    return _CACHE[name]


def _serve(path: str):
    name, media = FILES[path]

    async def handler() -> Response:
        return Response(_load(name), media_type=media, headers=PAGE_HEADERS)

    return handler


for _path in FILES:
    router.add_api_route(_path, _serve(_path), methods=["GET"], include_in_schema=False)


@router.get("/opossum/.well-known/jwks.json", include_in_schema=False)
async def jwks(request: Request) -> JSONResponse:
    """The relay's receipt-signing public key, for anyone verifying receipts offline."""
    return JSONResponse(keys(get_services(request)).jwks(), headers={"Cache-Control": "public, max-age=300",
                                                                     "Access-Control-Allow-Origin": "*"})
