"""Auth primitives for Lifted Sign: HMAC token signing, Twilio Verify SMS OTP,
and TOTP (RFC 6238) two-factor.

This is the standalone extraction of the pieces the signing product uses. It is
NOT a login gate: there is no admin Google gate, no public-route allowlist, and
no host-application coupling. Callers (``sign_portal_auth``, ``esign_access``,
``sign_accounts``) build their own session kinds on top of :func:`_sign` /
:func:`_unsign`, keyed off the one process secret :data:`sign.config.SECRET`.

  * :func:`_sign` / :func:`_unsign` — compact HMAC-SHA256 signed JSON tokens with
    an ``exp`` claim. Every session/OTP/reset token in the product is keyed off
    ``config.SECRET`` through these two functions.
  * Twilio Verify (:func:`_twilio_send` / :func:`_twilio_check`) —
    SMS phone-OTP. Credentials come from the environment; :func:`phone_login_ready`
    returns ``False`` when unset so the feature degrades cleanly (the product runs
    fine without SMS).
  * TOTP helpers — authenticator enrollment (:func:`gen_totp_secret`,
    :func:`totp_uri`, :func:`totp_qr`) and verification (:func:`_totp_match_step`,
    :func:`totp_verify`). Per-account seed storage lives in the caller
    (``sign_accounts`` / ``sign_portal_auth``); the global helpers here back the
    single-seed path and share the same primitives.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time

import httpx

from . import config


# --- HMAC signing secret ---------------------------------------------------------
def _secret() -> bytes:
    """The one signing key for every token in the product. ``config.SECRET`` is
    required and boot fails hard (config.py) if it is missing/weak, so there is
    no insecure fallback here."""
    return config.SECRET.encode("utf-8")


# --- signed tokens (session / OTP / state) ---------------------------------------
def _sign(payload: dict) -> str:
    body = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    sig = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{body}.{sig}"


def _unsign(token: str) -> dict | None:
    try:
        body, sig = token.split(".", 1)
        if not hmac.compare_digest(
            sig, hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()[:32]
        ):
            return None
        pad = "=" * (-len(body) % 4)
        data = json.loads(base64.urlsafe_b64decode(body + pad))
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None


# --- Twilio Verify SMS OTP -------------------------------------------------------
def _twilio() -> dict[str, str]:
    """Twilio Verify credentials from the environment. Any unset value disables
    SMS OTP (see :func:`phone_login_ready`)."""
    return {
        "account_sid": (os.environ.get("TWILIO_ACCOUNT_SID") or "").strip(),
        "auth_token": (os.environ.get("TWILIO_AUTH_TOKEN") or "").strip(),
        "verify_service_sid": (os.environ.get("TWILIO_VERIFY_SERVICE_SID") or "").strip(),
    }


def phone_login_ready() -> bool:
    """True only when all three Twilio Verify env vars are set. When False the
    caller should hide/disable the phone-OTP sign-in path."""
    t = _twilio()
    return bool(t["account_sid"] and t["auth_token"] and t["verify_service_sid"])


def _verify_url(suffix: str) -> str:
    return f"https://verify.twilio.com/v2/Services/{_twilio()['verify_service_sid']}/{suffix}"


def _twilio_send(phone: str) -> bool:
    """Dispatch an SMS OTP to ``phone`` via Twilio Verify. Returns True on a 2xx."""
    t = _twilio()
    r = httpx.post(
        _verify_url("Verifications"),
        auth=(t["account_sid"], t["auth_token"]),
        data={"To": phone, "Channel": "sms"},
        timeout=20,
    )
    return r.status_code < 400


def _twilio_check(phone: str, code: str) -> bool:
    """Check a user-entered ``code`` against Twilio Verify. True == approved."""
    t = _twilio()
    r = httpx.post(
        _verify_url("VerificationCheck"),
        auth=(t["account_sid"], t["auth_token"]),
        data={"To": phone, "Code": code.strip()},
        timeout=20,
    )
    return r.status_code < 400 and r.json().get("status") == "approved"


# --- TOTP (authenticator app) — RFC 6238, no external dependency -----------------
_FACTOR_FAIL_LIMIT = 5
_FACTOR_LOCK_SECONDS = 15 * 60
# Durable replay guard for the single-seed path: highest 30s step already consumed.
# Per-account callers keep their OWN per-account marker (see sign_portal_auth), which
# is required whenever more than one seed exists — a global marker would let one
# account's accepted code block another.
_TOTP_LAST_STEP_KEY = "totp_last_step"


def gen_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _b32decode(s: str) -> bytes:
    s = (s or "").upper().replace(" ", "")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def _hotp(secret_b32: str, counter: int) -> str:
    h = hmac.new(_b32decode(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o : o + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def _totp_match_step(secret_b32: str, code: str, window: int) -> int | None:
    """Return the absolute 30s step (t+d) whose HOTP equals ``code``, scanning
    +/-``window`` steps from highest to lowest so the newest valid step is
    preferred; else None."""
    code = (code or "").strip().replace(" ", "")
    if not secret_b32 or not code.isdigit():
        return None
    t = int(time.time() // 30)
    for d in range(window, -window - 1, -1):
        if hmac.compare_digest(_hotp(secret_b32, t + d), code):
            return t + d
    return None


def totp_verify(secret_b32: str, code: str, window: int = 1) -> bool:
    """Verify a TOTP code against +/-``window`` 30s steps with single-use replay
    protection: a code is rejected if its step is <= the highest step already
    consumed (durably recorded via ``db`` settings). GLOBAL marker — correct only
    for a single shared seed. Per-account callers must keep their own marker."""
    step = _totp_match_step(secret_b32, code, window)
    if step is None:
        return False
    from . import db

    try:
        last = int(db.get_setting(_TOTP_LAST_STEP_KEY, 0) or 0)
    except (TypeError, ValueError):
        last = 0
    if step <= last:
        return False
    try:
        db.set_setting(_TOTP_LAST_STEP_KEY, step)
    except Exception:
        # If we cannot persist the consumed step, fail closed rather than allow an
        # unprotected (replayable) acceptance.
        return False
    return True


def totp_uri(secret_b32: str, account: str = "user", issuer: str = "Lifted Sign") -> str:
    # MINIMAL otpauth URI — some authenticators choke on the optional digits/period
    # params and assume 6-digit/30s anyway (which matches this verifier).
    from urllib.parse import quote

    return (
        f"otpauth://totp/{quote(issuer)}:{quote(account)}"
        f"?secret={secret_b32}&issuer={quote(issuer)}"
    )


def totp_secret() -> str | None:
    """The single-seed TOTP secret (settings-backed), decrypted at rest. LEGACY
    plaintext passes through unchanged."""
    from . import crypto, db

    v = db.get_setting("totp_secret")
    if not v:
        return None
    return crypto.decrypt(v) if crypto.looks_encrypted(v) else v


def save_totp_secret(s: str) -> None:
    from . import crypto, db

    db.set_setting("totp_secret", crypto.encrypt(s))


def totp_enrolled() -> bool:
    return bool(totp_secret())


def totp_login_locked(key: str) -> bool:
    from . import db

    return db.auth_limit_locked(f"totp:{(key or '').lower()}")


def totp_login_record(key: str, ok: bool) -> None:
    key = (key or "").lower()
    if not key:
        return
    from . import db

    db.auth_limit_record(f"totp:{key}", ok, _FACTOR_FAIL_LIMIT, _FACTOR_LOCK_SECONDS)


def totp_qr(uri: str) -> str:
    """Render the otpauth URI as a black-on-white PNG data URI (most reliable for
    camera scanning; the secret never leaves the server)."""
    try:
        import io

        import segno

        buf = io.BytesIO()
        segno.make(uri, error="m").save(
            buf, kind="png", scale=7, border=4, dark="#000000", light="#ffffff"
        )
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return ""
