"""Per-account API rate limiting for the Lifted Sign tenant API.

A small, dependency-free **fixed-window** sustained-rate limiter for the
authenticated product API (``/api/mysign/*``). It reuses the same battle-tested
primitive the auth flows already lean on — :func:`sign.db.auth_rate_allowed`
(an atomic upsert-with-RETURNING that stays correct on SQLite *and* Postgres) —
so there is no new storage, no new dependency, and no in-process counter that a
multi-worker deploy would silently under-count.

Scope (what gets limited):
  * ONLY authenticated ``/api/mysign/*`` requests. Public/signer/health/landing
    routes and the ``/static`` mount are exempt (they never reach this module —
    the middleware calls :func:`check` only for the protected surface, and this
    module re-checks the path prefix as a belt-and-suspenders guard).
  * The auth endpoints (``/api/sign-portal/*``, ``/api/sign/*``) are NOT limited
    here — they carry their own purpose-built limiters (magic-link, phone-OTP,
    signup, TOTP lockout) in ``sign_portal_auth`` / ``webauth``. Double-limiting
    them would risk locking a legitimate self-hoster out of sign-in.

Budget key (who shares a bucket):
  * A developer ``Authorization: Bearer sk_…`` key gets a **per-key** budget,
    keyed on the key's short, non-secret, indexed prefix (never the full secret).
  * A browser session gets a **per-account** budget, keyed on the account id read
    from the HMAC-signed session cookie (a pure signature check — no DB hit).

Config:
  * ``SIGN_API_RATE_LIMIT`` — sustained requests allowed per account/key per
    window. Default ``120``. Read from the environment on each call so an
    operator (or a test) can tune it without a restart. Non-positive / unparsable
    values fall back to the default.
  * The window is a fixed 60 seconds (so the default reads as "120/min").

Fail-OPEN by construction: any error deriving the key, reading config, or talking
to the store returns ``None`` (allow). A limiter fault must never block legitimate
traffic — the worst case is that a burst slips through, never that the API goes
dark. The DB read is dispatched to a worker thread so the async event loop is
never blocked by the (fast, local) SQLite/PG round-trip.
"""

from __future__ import annotations

import asyncio
import os

from fastapi import Request
from fastapi.responses import JSONResponse

from . import db

# Env var the operator tunes; reported to config.py for adoption. Read per-call
# (see _limit) so it can be changed without a process restart.
RATE_LIMIT_ENV = "SIGN_API_RATE_LIMIT"
_DEFAULT_LIMIT = 120  # generous sustained default: 120 requests / minute / account
_WINDOW_SECONDS = 60  # fixed window ⇒ the default reads as "120/min"

# Only this surface is limited; everything else is exempt.
_PROTECTED_PREFIX = "/api/mysign/"

# Non-secret, indexed portion of an API key (mirrors sign_api_keys._PREFIX_LEN).
# Using the prefix — never the full key — keeps the raw secret out of the store.
_KEY_PREFIX_LEN = 14


def _limit() -> int:
    """Sustained per-window budget from ``SIGN_API_RATE_LIMIT`` (default 120).

    Read fresh each call so config changes take effect without a restart and so a
    test can drive the threshold. Any non-positive or unparsable value falls back
    to the generous default rather than accidentally throttling to zero.
    """
    raw = os.environ.get(RATE_LIMIT_ENV)
    if raw is None:
        return _DEFAULT_LIMIT
    try:
        val = int(str(raw).strip())
    except (TypeError, ValueError):
        return _DEFAULT_LIMIT
    return val if val > 0 else _DEFAULT_LIMIT


def _budget_key(request: Request) -> str | None:
    """Derive the rate-limit bucket for an authenticated request, or None.

    Cookie first (the SPA's common path), then Bearer (the programmatic path) —
    mirrors ``_require_sign_acct`` so the limiter and the authn gate agree on
    identity. Returns None when no authenticated identity can be derived, which
    makes the caller fail open (an unauthenticated request is handled by the
    session gate / handler, not throttled here).
    """
    # Session cookie -> per-account budget. The account id comes straight from the
    # HMAC-signed cookie (webauth._unsign) — a pure signature verification, no DB
    # round-trip and no PBKDF2 — so a forged/tampered cookie yields no key (open).
    from . import sign_portal_auth, webauth

    cookie = request.cookies.get(sign_portal_auth.COOKIE)
    if cookie:
        payload = webauth._unsign(cookie)
        if payload and payload.get("k") == "signacct" and payload.get("aid"):
            return f"apirate:acct:{int(payload['aid'])}"

    # Developer Bearer key -> per-key budget keyed on the non-secret prefix only.
    auth = request.headers.get("authorization", "") or ""
    if auth[:7].lower() == "bearer ":
        token = auth[7:].strip()
        if token:
            return f"apirate:key:{token[:_KEY_PREFIX_LEN]}"

    return None


async def check(request: Request) -> JSONResponse | None:
    """Enforce the sustained per-account/per-key budget for ``/api/mysign/*``.

    Returns a 429 ``{"error": "rate_limited"}`` JSONResponse (with a ``Retry-After``
    header) when the caller has exceeded its window budget, else ``None`` (allow).

    Fail-OPEN: any exception — key derivation, config read, or store error — is
    swallowed and returns ``None`` so a limiter fault can never block legitimate
    traffic. The store call runs in a worker thread to keep the event loop free.
    """
    try:
        path = request.url.path
        if not path.startswith(_PROTECTED_PREFIX):
            return None  # exempt: public/signer/health/auth/static and any non-product API
        key = _budget_key(request)
        if key is None:
            return None  # no authenticated identity -> let the session gate/handler decide
        allowed = await asyncio.to_thread(db.auth_rate_allowed, key, _limit(), _WINDOW_SECONDS)
        if allowed:
            return None
        return JSONResponse(
            {"error": "rate_limited"},
            status_code=429,
            headers={"Retry-After": str(_WINDOW_SECONDS)},
        )
    except Exception:
        # Fail open — a rate-limiter must never be the reason a real request fails.
        return None


__all__ = ["check", "RATE_LIMIT_ENV"]
