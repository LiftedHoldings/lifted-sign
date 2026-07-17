"""Optional Google Sign-In (OAuth) for Lifted Sign sender accounts.

Standard server-side authorization-code flow: the caller builds a login URL
(:func:`google_login_url`), Google redirects back with a ``code``, and
:func:`exchange_code` swaps it for tokens using the client secret and returns
the Google-verified email address.

This is an OPTIONAL sign-in method. Credentials are read from the environment:

    GOOGLE_OAUTH_CLIENT_ID       OAuth 2.0 client id
    GOOGLE_OAUTH_CLIENT_SECRET   OAuth 2.0 client secret
    GOOGLE_OAUTH_REDIRECT        default redirect/callback URL (used when the
                                 caller does not pass one explicitly)

When the client id/secret are unset the functions degrade cleanly —
:func:`google_login_url` returns ``""`` and :func:`exchange_code` returns
``None`` — so a self-host install that never configures Google simply doesn't
offer that button. No host-application dependency; every value comes from the
process environment.
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Any
from urllib.parse import urlencode

import httpx

log = logging.getLogger(__name__)


def _google_cfg() -> dict[str, str]:
    return {
        "client_id": (os.environ.get("GOOGLE_OAUTH_CLIENT_ID") or "").strip(),
        "client_secret": (os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET") or "").strip(),
        "redirect": (os.environ.get("GOOGLE_OAUTH_REDIRECT") or "").strip(),
    }


def configured() -> bool:
    """True when both the OAuth client id and secret are present."""
    c = _google_cfg()
    return bool(c["client_id"] and c["client_secret"])


def google_login_url(state: str, redirect_uri: str = "", nonce: str | None = None) -> str:
    """Build the Google authorization URL. ``redirect_uri`` overrides the
    ``GOOGLE_OAUTH_REDIRECT`` default. Returns ``""`` when Google login is not
    configured (no client id, or no redirect available)."""
    c = _google_cfg()
    if not c["client_id"]:
        return ""
    ru = (redirect_uri or c["redirect"]).strip()
    if not ru:
        return ""
    q = {
        "client_id": c["client_id"],
        "redirect_uri": ru,
        "response_type": "code",
        "scope": "openid email",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    if nonce:
        q["nonce"] = nonce
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(q)


def _verify_google_id_token(idt: str, client_id: str) -> dict[str, Any] | None:
    """Verify a Google id_token's signature, audience and issuer. Returns the
    claims dict, or None on any failure (including google-auth being absent)."""
    if not idt or not client_id:
        return None
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token
    except ImportError:
        # Google sign-in is configured but the optional dependency isn't installed. Log it clearly
        # so this reads as a setup gap, not a mysterious "bad token" rejection.
        log.warning(
            "Google sign-in is configured but 'google-auth' is not installed "
            "(pip install 'lifted-sign[google]'); Google login is unavailable."
        )
        return None
    try:
        claims = google_id_token.verify_oauth2_token(
            idt, google_requests.Request(), audience=client_id
        )
        if claims.get("iss") not in (
            "accounts.google.com",
            "https://accounts.google.com",
        ):
            return None
        return claims
    except Exception:  # noqa: BLE001 — any verification failure is an invalid/expired token
        return None


def exchange_code(
    code: str, redirect_uri: str = "", expected_nonce: str | None = None
) -> str | None:
    """Exchange an authorization ``code`` for tokens (server-side, with the client
    secret) and return the Google-verified email after signature/audience/issuer
    validation. ``redirect_uri`` must match the one used to build the login URL;
    it falls back to ``GOOGLE_OAUTH_REDIRECT``. Returns None when Google login is
    not configured or verification fails."""
    c = _google_cfg()
    if not (c["client_id"] and c["client_secret"]):
        return None
    ru = (redirect_uri or c["redirect"]).strip()
    try:
        r = httpx.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": c["client_id"],
                "client_secret": c["client_secret"],
                "redirect_uri": ru,
                "grant_type": "authorization_code",
            },
            timeout=20,
        )
        r.raise_for_status()
        claims = _verify_google_id_token(r.json().get("id_token", ""), c["client_id"]) or {}
        if expected_nonce and not hmac.compare_digest(
            str(claims.get("nonce") or ""), expected_nonce
        ):
            return None
        # Require Google to have explicitly verified the email — never accept missing.
        if claims.get("email_verified") in (True, "true"):
            return claims.get("email")
    except Exception:
        return None
    return None
