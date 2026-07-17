"""Lifted Sign — standalone ASGI application.

A single-host FastAPI app that composes the sign product surface:

* page shells (marketing landing, the sender SPA, the public signer + envelope pages, the
  developer docs, the legal pages),
* the tenant product API (``/api/mysign/*``), signup/login (``/api/sign-portal/auth/*``), the
  public signer + envelope APIs, and the operator console (``/api/sign-ops/*``),
* a ``/static`` mount over the web root (DS assets, vendored PDF.js, guides, SDK).

There is deliberately **no** host-application coupling: no admin Google gate, no host-based routing,
no activity feed / SSE broadcast / observability sink. Security is enforced by three concerns folded
into one middleware — a strict Content-Security-Policy + hardened headers on every response, an
OWASP Origin-based CSRF check on mutating API calls, and a public-route allowlist that requires a
sign session for everything else (the handlers then do authoritative cookie/Bearer/env-session
validation).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import mimetypes

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import config
from .http_helpers import (
    STRICT_CSP,
    WEB_DIR,
    _apply_security_headers,
    _csrf_origin_ok,
)
from .routers import developers, envelope, mysign, ops, portal, signer

log = logging.getLogger("sign")


# --- background: e-sign expiry sweep ----------------------------------------
async def _esign_expiry_poller() -> None:
    """Hourly: auto-expire e-sign envelopes whose signing window elapsed and email the sender.
    The sweep is idempotent and system-scoped, so a missed hour just expires on the next pass."""
    from . import esign

    while True:
        try:
            n = await asyncio.to_thread(esign.sweep_expired)
            if n:
                log.info("esign expiry sweep: %d envelope(s) expired", n)
        except Exception:
            log.debug("esign expiry sweep iteration failed", exc_info=True)
        await asyncio.sleep(3600)


@contextlib.asynccontextmanager
async def _lifespan(app: FastAPI):
    # Ensure every table exists before serving. The sign engine modules create their tables at
    # import time, so importing them here is the schema bootstrap for a fresh SQLite/Postgres DB.
    from . import (  # noqa: F401
        esign,
        esign_access,
        esign_disclosure,
        sign_accounts,
        sign_api_keys,
    )

    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    task = asyncio.create_task(_esign_expiry_poller())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="Lifted Sign", docs_url=None, redoc_url=None, lifespan=_lifespan)


# --- security / CSRF / session-allowlist middleware -------------------------
# Public routes need no sign session (the signer/envelope/portal-auth/developers surfaces plus the
# static mount and page shells). Everything else (the SPA's own /api/mysign + the operator console)
# requires a session cookie OR a developer Bearer key to even reach the handler, which then performs
# the authoritative validation. The page shells stay public so the SPA can load and show its login.
_PUBLIC_EXACT = frozenset(
    {
        "/",
        "/app",
        "/signapp",
        "/health",
        "/healthz",
        "/favicon.ico",
        "/privacy",
        "/terms",
        "/developers",
        "/developers/",
        "/robots.txt",
        "/sw.js",
        "/manifest.webmanifest",
    }
)
_PUBLIC_PREFIXES = (
    "/sign/",
    "/api/sign/token/",
    "/api/sign/disclosure",
    "/api/sign-portal/",
    "/envelope/",
    "/api/envelope/",
    "/static/",
    "/developers/",
)


def _is_public(path: str) -> bool:
    return path in _PUBLIC_EXACT or path.startswith(_PUBLIC_PREFIXES)


@app.middleware("http")
async def _gate(request: Request, call_next):
    path = request.url.path
    # (1) OWASP Origin-based CSRF defense on mutating API calls.
    if not _csrf_origin_ok(request):
        return _apply_security_headers(JSONResponse({"error": "bad origin"}, status_code=403))
    # (2) Public-route allowlist. Non-public paths require a sign session (cookie) or a developer
    # Bearer key just to reach the handler; the handler does the authoritative check.
    if not _is_public(path):
        from . import sign_portal_auth

        has_cookie = bool(request.cookies.get(sign_portal_auth.COOKIE))
        has_bearer = request.headers.get("authorization", "")[:7].lower() == "bearer "
        if not (has_cookie or has_bearer):
            if path.startswith("/api/"):
                return _apply_security_headers(
                    JSONResponse({"error": "unauthorized"}, status_code=401)
                )
            return _apply_security_headers(PlainTextResponse("Not found", status_code=404))
    # (3) Serve, then harden every response (CSP + security headers) idempotently.
    resp = await call_next(request)
    return _apply_security_headers(resp)


# --- page shells ------------------------------------------------------------
def _page(name: str) -> FileResponse:
    return FileResponse(
        WEB_DIR / name,
        headers={
            "Cache-Control": "no-store, must-revalidate",
            "Content-Security-Policy": STRICT_CSP,
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


@app.get("/")
async def landing() -> FileResponse:
    """Marketing landing page."""
    return _page("signland.html")


@app.get("/app")
@app.get("/signapp")
async def app_spa() -> FileResponse:
    """The sender SPA (signup → dashboard → account). Public shell; the SPA drives its own auth."""
    return _page("signapp.html")


@app.get("/privacy")
async def privacy() -> FileResponse:
    return _page("sign-privacy.html")


@app.get("/terms")
async def terms() -> FileResponse:
    return _page("sign-terms.html")


@app.get("/health")
@app.get("/healthz")
async def health() -> dict:
    return {"ok": True, "service": "lifted-sign"}


@app.get("/favicon.ico")
async def favicon():
    ico = WEB_DIR / "ds" / "assets" / "favicon-32.png"
    if ico.exists():
        return FileResponse(ico, media_type="image/png")
    return PlainTextResponse("", status_code=404)


# --- routers ----------------------------------------------------------------
app.include_router(portal.router)
app.include_router(mysign.router)
app.include_router(signer.router)
app.include_router(envelope.router)
app.include_router(developers.router)
app.include_router(ops.router)


# --- static mount -----------------------------------------------------------
# ES-module MIME so the vendored PDF.js (.mjs) loads as a module under the strict CSP —
# StaticFiles guesses from the OS registry, which doesn't always know .mjs, and nosniff would
# then refuse to execute it. Register explicitly, BEFORE the mount.
mimetypes.add_type("text/javascript", ".mjs")
app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")
