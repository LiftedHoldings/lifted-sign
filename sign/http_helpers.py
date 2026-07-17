"""Shared HTTP-layer helpers for the Lifted Sign server.

These are the standalone reimplementations of the request-scoped helpers that used
to live inline in the host application's ``app.py``. They deliberately have **no**
host coupling: no secret store, no telemetry sink, no activity feed, no admin Google
gate — every value comes from :mod:`sign.config` (the environment) and auth is delegated
to the sign-owned modules (``sign_portal_auth`` / ``sign_api_keys`` / ``esign`` /
``esign_access``).

Everything a router needs to authenticate, authorize, and harden a response is exposed
here so the route modules stay thin and every ownership/authn decision flows through a
single choke-point (``_require_owned`` for IDOR, ``_require_sign_acct`` for authn).
"""

from __future__ import annotations

import asyncio
import hmac
import os
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import JSONResponse

from . import config

# --- filesystem anchors -----------------------------------------------------
# Web assets (SPA shells, signer page, vendored DS + PDF.js + guides) live under
# <install root>/web. config.REPO_ROOT is the install root (see config.py).
WEB_DIR: Path = config.REPO_ROOT / "web"

# --- upload guard -----------------------------------------------------------
_MAX_SIGN_PDF_BYTES = 60 * 1024 * 1024  # e-sign upload cap (60 MB)


def _validate_sign_pdf(raw: bytes) -> str | None:
    """None if ``raw`` is an acceptable e-sign upload, else a user-safe rejection message.

    Rejects oversize, non-PDF, encrypted (needs password), 0-page and corrupt files at the
    ROUTE so no black-hole file/row is ever written and a bad PDF never becomes a 500
    downstream. The real validation lives in the PDF engine (``pdf_edit.validate_source``);
    this wrapper only adds the size cap and normalizes the error to a string.
    """
    from . import pdf_edit

    if len(raw) > _MAX_SIGN_PDF_BYTES:
        return "file too large (max 60 MB)"
    try:
        pdf_edit.validate_source(raw)
    except ValueError as e:
        return str(e)
    return None


# Back-compat alias — the route modules read naturally as "_pdf_upload_error".
_pdf_upload_error = _validate_sign_pdf


# --- public base URL --------------------------------------------------------
def _sign_public_base() -> str:
    """External base URL used to build signer links + email content. Comes straight from
    config (PUBLIC_BASE_URL); there is NO hardcoded fallback domain."""
    return (config.local().get("esign_public_url") or config.PUBLIC_BASE_URL).rstrip("/")


# --- client IP for the legal audit trail ------------------------------------
def _trusted_proxies() -> set[str]:
    """Trusted reverse-proxy IPs (so X-Forwarded-For is only honored behind them).

    config.py does not carry this key, so it is read from the environment here:
    SIGN_TRUSTED_PROXIES = comma-separated IPs (blank ⇒ trust nothing, i.e. always
    record the socket peer). Reported to the config owner for reconciliation.
    """
    raw = os.environ.get("SIGN_TRUSTED_PROXIES", "")
    return {p.strip() for p in raw.split(",") if p.strip()}


def _client_ip(req: Request) -> str:
    """Real client IP for the legal audit trail. X-Forwarded-For is attacker-controllable,
    so we ONLY honor it when the direct connection comes from a configured trusted proxy
    (SIGN_TRUSTED_PROXIES), taking the right-most hop that isn't itself a trusted proxy.
    Otherwise we record the socket IP. With no proxy configured the header is ignored."""
    peer = req.client.host if req.client else ""
    trusted = _trusted_proxies()
    if peer in trusted:
        hops = [h.strip() for h in req.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        for h in reversed(hops):  # closest real client = right-most non-proxy hop
            if h not in trusted:
                return h
    return peer


# --- OAuth CSRF-state primitives --------------------------------------------
# The Google sign-in redirect needs a one-time, unguessable `state` echoed back and compared
# constant-time (CSRF for the OAuth callback). This is pure HTTP-flow plumbing — it belongs to the
# request layer, not the signing engine — so it lives here rather than depending on a host module.
OAUTH_STATE_TTL = 600  # 10 min — the browser round-trip to Google and back


def _new_oauth_state() -> str:
    return secrets.token_urlsafe(24)


def _oauth_state_ok(cookie_state: str | None, param_state: str | None) -> bool:
    """True only if both values are present and equal (constant-time). A missing cookie or param
    fails closed — a stripped state cookie must never disable the CSRF check."""
    if not cookie_state or not param_state:
        return False
    return hmac.compare_digest(str(cookie_state), str(param_state))


# --- sign-session cookie ----------------------------------------------------
def _set_sign_cookie(resp, tok: str) -> None:
    """Set the SPA session cookie. samesite=lax (not strict) so the Google top-level redirect
    returns the cookie. secure + the __Host- prefix (config.cookie_secure()/config.cookie_name) are
    the default — browsers accept them only over HTTPS, so run behind TLS; SIGN_INSECURE_COOKIES
    drops both for plain-http local/LAN dev only."""
    from . import sign_portal_auth

    resp.set_cookie(
        sign_portal_auth.COOKIE,
        tok,
        max_age=sign_portal_auth.SESSION_TTL,
        httponly=True,
        secure=config.cookie_secure(),
        samesite="lax",
    )


def _sign_acct(req: Request) -> dict | None:
    from . import sign_portal_auth

    return sign_portal_auth.session_account(sign_portal_auth.session_cookie(req.cookies))


async def _require_sign_acct(req: Request):
    """Return (account, None) when authed, else (None, 401-response). The single authn gate for
    every /api/mysign/* handler. Accepts EITHER the SPA session cookie OR a developer Bearer API
    key (``Authorization: Bearer sk_live_…``) — both resolve to the same account and flow through
    the identical ``_require_owned`` IDOR choke-point, so a key grants no authority a logged-in
    user lacks. Cookie is tried first (the SPA's common path); Bearer is the programmatic path."""
    acct = _sign_acct(req)
    if not acct:
        auth = req.headers.get("authorization", "")
        if auth[:7].lower() == "bearer ":
            from . import sign_api_keys

            acct = await asyncio.to_thread(sign_api_keys.resolve, auth[7:].strip())
    if not acct:
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    return acct, None


def _require_sign_cookie(req: Request):
    """Cookie-session ONLY (NOT Bearer). Account-SECURITY routes (2FA enroll/disable, billing) use
    this so a developer API key — which is logged, committed, and shared with third parties — can
    never change the account's security config or re-enroll the 2FA phone. Returns (acct, err)."""
    acct = _sign_acct(req)
    if not acct:
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    return acct, None


async def _require_owned(aid: int, acct: dict, full: bool = False):
    """IDOR choke-point. Return (agreement, None) if this account owns ``aid``, else
    (None, 404-response). 404 (not 403) so aid existence isn't an oracle."""
    from . import esign

    agr = await asyncio.to_thread(esign.get_agreement_owned, aid, acct["id"], full)
    if not agr:
        return None, JSONResponse({"error": "not found"}, status_code=404)
    return agr, None


# --- response hardening -----------------------------------------------------
# One strict Content-Security-Policy for every page + API response. worker-src blob: is
# REQUIRED by the vendored PDF.js (the field editor / signer canvas load their worker from a
# blob URL); img-src data: covers rendered pages + adopted-signature data URIs. Everything
# else is first-party — no CDN, no external fonts (fonts are vendored under /static).
STRICT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "worker-src 'self' blob:; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


def _apply_security_headers(resp):
    """Attach hardened security headers to a response (idempotent via setdefault, so a route
    that set its own value wins)."""
    resp.headers.setdefault("Content-Security-Policy", STRICT_CSP)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


# --- CSRF / Origin defense --------------------------------------------------
# Our own hostname(s), derived from PUBLIC_BASE_URL — never a hardcoded host. The
# request's own Host is always added at check time, and localhost is allowed for dev.
def _own_hosts() -> set[str]:
    hosts = {"localhost", "127.0.0.1", "testserver"}
    h = (urlsplit(config.PUBLIC_BASE_URL).hostname or "").lower()
    if h:
        hosts.add(h)
    return hosts


# Paths that legitimately receive cross-origin / no-Origin state-changing POSTs (public
# token-gated signer actions). These are independently authenticated by the signer token.
_CSRF_EXEMPT_PREFIXES = ("/api/sign/token/",)


def _csrf_origin_ok(request: Request) -> bool:
    """OWASP Origin-based CSRF defense. Returns True if the request may proceed.

    Rules (non-breaking):
      (a) non-mutating method, or non-/api path  -> ALLOW
      (b) exempt public token prefix             -> ALLOW
      (c) NO Origin header                        -> ALLOW (curl, server-to-server, same-origin
          GETs, TestClient — none of which is a browser CSRF vector)
    Only when an Origin IS present and its host is not one of ours do we reject.
    """
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return True
    path = request.url.path
    if not path.startswith("/api/"):
        return True
    if any(path.startswith(p) for p in _CSRF_EXEMPT_PREFIXES):
        return True
    origin = request.headers.get("origin")
    if not origin:
        return True  # rule (c): absent Origin is allowed
    origin_host = (urlsplit(origin).hostname or "").lower()
    if not origin_host:
        return True
    allowed = _own_hosts()
    host_hdr = request.headers.get("host", "")
    if host_hdr:
        allowed.add(host_hdr.split(":", 1)[0].lower())
    return origin_host in allowed


__all__ = [
    "WEB_DIR",
    "STRICT_CSP",
    "_apply_security_headers",
    "_csrf_origin_ok",
    "_client_ip",
    "_sign_public_base",
    "_set_sign_cookie",
    "_sign_acct",
    "_require_sign_acct",
    "_require_sign_cookie",
    "_require_owned",
    "_validate_sign_pdf",
    "_pdf_upload_error",
    "OAUTH_STATE_TTL",
    "_new_oauth_state",
    "_oauth_state_ok",
    "Any",
]
