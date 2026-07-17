"""Unit tests for the per-account API rate limiter (sign.ratelimit).

Drives ``ratelimit.check`` directly with a minimal stub request (no live server
needed) and asserts the fixed-window budget: requests up to the limit are allowed
(``None``), the first over-limit request returns a 429 ``{"error":"rate_limited"}``
with a ``Retry-After`` header, exempt paths are never limited, and a limiter that
can't derive an identity fails OPEN.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from sign import db, ratelimit


# --- minimal request stub ---------------------------------------------------
def _req(path: str, *, bearer: str | None = None, cookie: str | None = None):
    """A stand-in for a Starlette Request exposing just what check() touches:
    ``.url.path``, ``.headers.get(...)``, ``.cookies.get(...)``."""
    from sign import sign_portal_auth

    headers = {}
    if bearer is not None:
        headers["authorization"] = f"Bearer {bearer}"
    cookies = {}
    if cookie is not None:
        cookies[sign_portal_auth.COOKIE] = cookie
    return SimpleNamespace(
        url=SimpleNamespace(path=path),
        headers=headers,
        cookies=cookies,
    )


def _run(coro):
    return asyncio.run(coro)


# --- tests ------------------------------------------------------------------
def test_check_blocks_after_limit(monkeypatch):
    """Bearer path: allow up to the limit, then 429 with the right body + header."""
    db.ensure_tables()  # idempotent — make sure auth_rate_limits exists
    monkeypatch.setenv(ratelimit.RATE_LIMIT_ENV, "3")
    # Unique key so the counter starts clean regardless of test ordering / rerun.
    import secrets

    token = "sk_test_" + secrets.token_urlsafe(8)
    req = _req("/api/mysign/agreements", bearer=token)

    # First 3 requests are within budget.
    for i in range(3):
        assert _run(ratelimit.check(req)) is None, f"request {i + 1} should be allowed"

    # 4th exceeds the window budget -> 429.
    resp = _run(ratelimit.check(req))
    assert resp is not None
    assert resp.status_code == 429
    assert resp.headers.get("Retry-After") == "60"
    assert b"rate_limited" in bytes(resp.body)


def test_exempt_path_never_limited(monkeypatch):
    """A non-/api/mysign path is exempt even far past the limit."""
    db.ensure_tables()
    monkeypatch.setenv(ratelimit.RATE_LIMIT_ENV, "1")
    req = _req("/api/sign-portal/auth/magic/start", bearer="sk_test_exempt")
    for _ in range(5):
        assert _run(ratelimit.check(req)) is None


def test_unauthenticated_fails_open(monkeypatch):
    """No cookie and no Bearer -> no identity -> fail open (never a 429)."""
    db.ensure_tables()
    monkeypatch.setenv(ratelimit.RATE_LIMIT_ENV, "1")
    req = _req("/api/mysign/agreements")
    for _ in range(5):
        assert _run(ratelimit.check(req)) is None


def test_default_limit_is_generous():
    """With the env var unset, the module defaults to 120/min."""
    import os

    os.environ.pop(ratelimit.RATE_LIMIT_ENV, None)
    assert ratelimit._limit() == 120
