"""LiftedSign sender-account auth — a parallel tenant to admin webauth + portal hub_auth.

Sessions are signed with the SAME webauth secret but a DISTINCT kind ("signacct"), so an
admin (k=sess), portal (k=hub), or envelope (k=envsess) token can NEVER be replayed as a sign
session, and a sign token is rejected by the admin gate (webauth.session_email pins k=sess) and
by require_env_session (pins k=envsess). See the P1 threat model (T4/T5/T6).

The signing key is guaranteed real: config refuses to boot without a strong SIGN_SECRET
(config._require_secret fails closed on a missing/weak/placeholder value), so a session token is
always keyed off a genuine secret and the signed cookie can be trusted as the only thing between
an attacker and a forged account session. HMAC verification (webauth._unsign) still gates every
token; there is no separate dev-secret special case because a weak secret can never reach here.
"""

from __future__ import annotations

import re
import secrets
import time

from . import db, sign_accounts, webauth

COOKIE = "__Host-ls_sign"
COOKIE_2FA = "__Host-ls_sign_2fa"  # short-lived "password/Google ok, TOTP still required"
STATE_COOKIE = "__Host-ls_sign_state"
NONCE_COOKIE = "__Host-ls_sign_nonce"
SESSION_TTL = 7 * 24 * 3600  # 7 days — senders, not admins
PENDING_2FA_TTL = 300  # 5 min to finish the authenticator step

_FACTOR_FAIL_LIMIT = 5
_FACTOR_LOCK_SECONDS = 15 * 60
_SIGNUP_IP_LIMIT = 5  # accounts per IP
_SIGNUP_IP_WINDOW = 24 * 3600
_RESET_TTL = 900  # 15 min password-reset code lifetime


# --- sessions --------------------------------------------------------------------
def make_session(account_id: int, ttl: float = SESSION_TTL) -> str:
    return webauth._sign(
        {
            "k": "signacct",
            "aid": int(account_id),
            "sv": sign_accounts.session_version(account_id),
            "exp": time.time() + ttl,
        }
    )


def session_account(cookie: str | None) -> dict | None:
    if not cookie:
        return None
    d = webauth._unsign(cookie)
    if not (d and d.get("k") == "signacct" and d.get("aid")):
        return None
    acct = sign_accounts.account_by_id(int(d["aid"]))
    if not acct or acct.get("status") != "active":
        return None
    # Per-account revocation epoch (logout / password change bumps it).
    if int(d.get("sv", 0)) != sign_accounts.session_version(acct["id"]):
        return None
    return acct


def session_cookie(cookies: dict) -> str | None:
    return cookies.get(COOKIE)


def pending_2fa_cookie(cookies: dict) -> str | None:
    return cookies.get(COOKIE_2FA)


def oauth_state_cookie(cookies: dict) -> str | None:
    return cookies.get(STATE_COOKIE)


def oauth_nonce_cookie(cookies: dict) -> str | None:
    return cookies.get(NONCE_COOKIE)


# --- pre-2FA half-session (password/Google ok, TOTP pending) ---------------------
def make_2fa_pending(account_id: int) -> str:
    """A distinct kind so it can NEVER be accepted as a full session (T6). Redeemable only
    at /api/sign-portal/auth/2fa with a correct TOTP code."""
    return webauth._sign(
        {
            "k": "signacct2fa",
            "aid": int(account_id),
            "jti": secrets.token_urlsafe(12),
            "exp": time.time() + PENDING_2FA_TTL,
        }
    )


def redeem_2fa_pending(cookie: str | None) -> dict | None:
    if not cookie:
        return None
    d = webauth._unsign(cookie)
    if d and d.get("k") == "signacct2fa" and d.get("aid"):
        return d
    return None


# --- phone-OTP signup/login (Twilio Verify) --------------------------------------
COOKIE_PHONE = "__Host-ls_sign_phone"  # carries the phone the OTP was sent to (signed, short-lived)
PENDING_PHONE_TTL = 600  # 10 min to enter the SMS code
_PHONE_IP_LIMIT = 8  # OTP-start requests per IP per hour (SMS-bomb / enumeration guard)
_PHONE_IP_WINDOW = 3600
_PHONE_NUM_LIMIT = 5  # OTP-start requests per phone number per 15 min
_PHONE_NUM_WINDOW = 900


def make_phone_pending(phone: str, email: str = "", name: str = "") -> str:
    """A signed, distinct-kind ('signacctphone') half-session. The phone is baked in HERE — at OTP
    SEND — so verify checks the code against THIS number, never one an attacker swaps in at verify.
    Carries the (optional) signup email/name so a new number can create an account in one step."""
    return webauth._sign(
        {
            "k": "signacctphone",
            "ph": _e164(phone),
            "em": (email or "").strip().lower()[:120],
            "nm": (name or "").strip()[:80],
            "jti": secrets.token_urlsafe(12),
            "exp": time.time() + PENDING_PHONE_TTL,
        }
    )


def redeem_phone_pending(cookie: str | None) -> dict | None:
    if not cookie:
        return None
    d = webauth._unsign(cookie)
    if d and d.get("k") == "signacctphone" and d.get("ph"):
        return d
    return None


def phone_start_allowed(ip: str, phone: str) -> bool:
    """Throttle OTP sends per IP AND per number (defense-in-depth over Twilio's own limits)."""
    ok_ip = db.auth_rate_allowed(f"signphone:ip:{ip or '?'}", _PHONE_IP_LIMIT, _PHONE_IP_WINDOW)
    ok_num = db.auth_rate_allowed(
        f"signphone:num:{_e164(phone)}", _PHONE_NUM_LIMIT, _PHONE_NUM_WINDOW
    )
    return ok_ip and ok_num


# --- password login --------------------------------------------------------------
def _pw_lock_key(email: str, ip: str) -> str:
    return f"signacct:pw:{(email or '').strip().lower()}:{(ip or 'noip').strip()}"


def login_locked(email: str, ip: str) -> bool:
    return db.auth_limit_locked(_pw_lock_key(email, ip))


def check_password_login(email: str, password: str, ip: str = "") -> dict | None:
    """Return the account dict on success, else None. Enumeration-safe: a full PBKDF2 always
    runs (verify_password), and the caller returns a uniform error for both unknown-email and
    wrong-password. Malformed input is NOT counted as a guess (mirrors webauth M-3)."""
    email = (email or "").strip().lower()
    if not email or not password:
        return None
    if login_locked(email, ip):
        return None
    acct = sign_accounts.account_by_email(email)
    # Always run the KDF (dummy when no account) so timing is uniform.
    ok = sign_accounts.verify_password(password, (acct or {}).get("pw_hash", ""))
    db.auth_limit_record(_pw_lock_key(email, ip), ok, _FACTOR_FAIL_LIMIT, _FACTOR_LOCK_SECONDS)
    if ok and acct and acct.get("status") == "active":
        return acct
    return None


# --- signup rate-limit (T9) ------------------------------------------------------
def signup_allowed(ip: str) -> bool:
    return db.auth_rate_allowed(
        f"signacct:signup:{(ip or 'noip').strip()}", _SIGNUP_IP_LIMIT, _SIGNUP_IP_WINDOW
    )


# --- TOTP (optional, per-account; NOT forced) ------------------------------------
def totp_locked(account_id: int) -> bool:
    return db.auth_limit_locked(f"signacct:totp:{int(account_id)}")


def totp_record(account_id: int, ok: bool) -> None:
    db.auth_limit_record(
        f"signacct:totp:{int(account_id)}", ok, _FACTOR_FAIL_LIMIT, _FACTOR_LOCK_SECONDS
    )


# Per-account replay marker (the global admin TOTP marker must NOT be shared across accounts).
def _totp_last_step_key(account_id: int) -> str:
    return f"sign_totp_last_step:{int(account_id)}"


def verify_totp_for_account(account_id: int, code: str, window: int = 1) -> bool:
    """Per-account TOTP verify with a per-account single-use replay marker (T6). Mirrors
    webauth.totp_verify but keyed per account so one account's accepted step can't block
    another. Returns False (and records a miss) on any failure."""
    if totp_locked(account_id):
        return False
    secret_b32 = sign_accounts.totp_secret(account_id)
    step = webauth._totp_match_step(secret_b32, code, window) if secret_b32 else None
    if step is None:
        totp_record(account_id, False)
        return False
    try:
        last = int(db.get_setting(_totp_last_step_key(account_id), 0) or 0)
    except (TypeError, ValueError):
        last = 0
    if step <= last:
        totp_record(account_id, False)
        return False
    try:
        db.set_setting(_totp_last_step_key(account_id), step)
    except Exception:
        return False
    totp_record(account_id, True)
    return True


# --- self-issued email password-reset code ---------------------------------------
# 6-digit code, HMAC(webauth._secret()) stored in settings with TTL, single-use, sent from the
# configured MAIL_FROM alias (mirrors esign_access._send_email_otp). Never stores/echoes the raw code.
def _reset_key(account_id: int) -> str:
    return f"signacct_reset:{int(account_id)}"


def _reset_from() -> str:
    from . import config

    return (config.local().get("esign", {}) or {}).get("otp_from") or config.MAIL_FROM


def send_reset_code(email: str) -> dict:
    """ENUMERATION-SAFE (T9): always returns {"ok": True}. Sends a code only if the account
    exists; the caller must not reveal existence."""
    import hashlib
    import hmac

    acct = sign_accounts.account_by_email(email)
    if not acct:
        return {"ok": True}
    if not db.auth_rate_allowed(f"signacct:resetsend:{acct['id']}", 5, 3600):
        return {"ok": True}
    from . import integrations, mailer

    code = "".join(secrets.choice("0123456789") for _ in range(6))
    salt = secrets.token_hex(8)
    h = hmac.new(webauth._secret(), (salt + code).encode("utf-8"), hashlib.sha256).hexdigest()
    db.set_setting(_reset_key(acct["id"]), {"h": h, "salt": salt, "exp": time.time() + _RESET_TTL})
    text = (
        f"Your LiftedSign password reset code is {code}\n\n"
        "It expires in 15 minutes. If you didn't request this, you can ignore this email."
    )
    try:
        html = mailer.otp_html(code)
    except Exception:
        html = ""
    try:
        integrations.send_email(
            acct["email"],
            "Your LiftedSign password reset code",
            text,
            html=html,
            from_addr=_reset_from(),
        )
    except Exception:
        pass
    return {"ok": True}


def confirm_reset(email: str, code: str, new_password: str) -> bool:
    import hashlib
    import hmac

    acct = sign_accounts.account_by_email(email)
    code = (code or "").strip()
    if not acct or not (code.isdigit() and len(code) == 6):
        return False
    if not sign_accounts.password_ok(new_password):
        return False
    # Brute-force guard: bound code guesses to _FACTOR_FAIL_LIMIT before a lockout, and
    # burn the code once the lock trips (a 6-digit code must not be guessable at all).
    lock_key = f"signacct:resetconfirm:{int(acct['id'])}"
    if db.auth_limit_locked(lock_key):
        return False
    rec = db.get_setting(_reset_key(acct["id"]), None)
    if not isinstance(rec, dict) or float(rec.get("exp", 0) or 0) < time.time():
        db.auth_limit_record(lock_key, False, _FACTOR_FAIL_LIMIT, _FACTOR_LOCK_SECONDS)
        return False
    cand = hmac.new(
        webauth._secret(), (str(rec.get("salt", "")) + code).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(cand, str(rec.get("h", ""))):
        db.auth_limit_record(lock_key, False, _FACTOR_FAIL_LIMIT, _FACTOR_LOCK_SECONDS)
        if db.auth_limit_locked(lock_key):
            db.set_setting(_reset_key(acct["id"]), 0)  # burn the code once brute-force lock trips
        return False
    db.auth_limit_record(lock_key, True, _FACTOR_FAIL_LIMIT, _FACTOR_LOCK_SECONDS)  # clear counter
    db.set_setting(_reset_key(acct["id"]), 0)  # single-use
    sign_accounts.set_password(acct["id"], new_password)  # also bumps session_ver (logout-all)
    return True


# --- email verification (password signups; Google accounts are pre-verified) -----
_VERIFY_TTL = 7 * 86400


def make_verify_token(account_id: int, email: str) -> str:
    """Signed, expiring email-verification token (same HMAC secret as sessions). Binds the
    account id + email so a changed email invalidates a stale link."""
    return webauth._sign(
        {
            "k": "signverify",
            "aid": int(account_id),
            "em": (email or "").strip().lower(),
            "exp": time.time() + _VERIFY_TTL,
        }
    )


def read_verify_token(token: str) -> dict | None:
    d = webauth._unsign(token)
    if not (d and d.get("k") == "signverify" and d.get("aid") and d.get("em")):
        return None
    return d


def send_verify_email(acct: dict) -> None:
    """Email a one-click verification link to a password account. Best-effort, rate-limited.
    Google accounts never need this (email already verified by Google)."""
    if not acct or not acct.get("email") or acct.get("google_sub"):
        return
    if not db.auth_rate_allowed(f"signacct:verifysend:{acct['id']}", 5, 3600):
        return
    from . import config, integrations

    tok = make_verify_token(acct["id"], acct["email"])
    base = config.PUBLIC_BASE_URL
    link = f"{base.rstrip('/')}/api/sign-portal/verify-email?token={tok}"
    text = (
        "Confirm your LiftedSign email to start sending documents:\n\n"
        f"{link}\n\nThis link expires in 7 days. If you didn't sign up, you can ignore this email."
    )
    html = (
        '<div style="font-family:system-ui,Segoe UI,sans-serif;max-width:480px;margin:0 auto">'
        '<h2 style="color:#2E6BFF">Confirm your email</h2>'
        "<p>Tap below to verify your LiftedSign account and start sending documents.</p>"
        f'<p><a href="{link}" style="display:inline-block;background:#2E6BFF;color:#fff;'
        'padding:12px 22px;border-radius:9px;text-decoration:none;font-weight:600">Verify email</a></p>'
        '<p style="color:#6b7280;font-size:12px">This link expires in 7 days. If you didn\'t sign up, ignore this email.</p></div>'
    )
    try:
        integrations.send_email(
            acct["email"], "Confirm your LiftedSign email", text, html=html, from_addr=_reset_from()
        )
    except Exception:
        pass


# --- Twilio SMS 2FA (login second factor + phone enrollment) ----------------------
# Twilio Verify owns the code lifecycle (generation/TTL/delivery/fraud). We add per-account
# app-level rate-limits + lockout on top for defense-in-depth. Reuses webauth's Verify client.
def _e164(phone: str) -> str:
    """Best-effort E.164 normalization: keep a leading +, strip formatting; a bare 10-digit
    number is treated as US (+1)."""
    p = re.sub(r"[^\d+]", "", (phone or "").strip())
    if not p:
        return ""
    if p.startswith("+"):
        return p
    digits = re.sub(r"\D", "", p)
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 11 and digits.startswith("1"):
        return "+" + digits
    return "+" + digits


def valid_phone(phone: str) -> bool:
    return bool(re.match(r"^\+\d{10,15}$", _e164(phone)))


def send_phone_code(phone: str) -> bool:
    """Twilio-Verify OTP to an arbitrary phone (enrollment or login). False if unconfigured/invalid."""
    p = _e164(phone)
    if not valid_phone(p) or not webauth.phone_login_ready():
        return False
    try:
        return webauth._twilio_send(p)
    except Exception:
        return False


def check_phone_code(phone: str, code: str) -> bool:
    p = _e164(phone)
    code = (code or "").strip()
    if not valid_phone(p) or not (code.isdigit() and 4 <= len(code) <= 8):
        return False
    try:
        return webauth._twilio_check(p, code)
    except Exception:
        return False


def sms_2fa_locked(account_id: int) -> bool:
    return db.auth_limit_locked(f"signacct:sms2fa:{int(account_id)}")


def send_login_sms(acct: dict) -> bool:
    """Send the login OTP to the account's stored phone (only if SMS 2FA is armed). Rate-limited."""
    if not acct or not acct.get("phone") or not acct.get("sms_2fa"):
        return False
    if not db.auth_rate_allowed(f"signacct:sms2fasend:{acct['id']}", 5, 900):
        return False
    return send_phone_code(acct["phone"])


def verify_login_sms(account_id: int, code: str) -> bool:
    """Verify a login SMS code against the account's stored phone, with per-account lockout."""
    if sms_2fa_locked(account_id):
        return False
    acct = sign_accounts.account_by_id(int(account_id))
    ok = bool(acct and acct.get("phone")) and check_phone_code(acct["phone"], code)
    db.auth_limit_record(
        f"signacct:sms2fa:{int(account_id)}", ok, _FACTOR_FAIL_LIMIT, _FACTOR_LOCK_SECONDS
    )
    return ok


# --- Google OAuth (reuses hub_auth's redirect-uri-explicit helpers) --------------
def sign_redirect_uri() -> str:
    from . import config

    base = config.PUBLIC_BASE_URL.rstrip("/")
    return f"{base}/api/sign-portal/auth/google/callback"


def google_login_url(state: str, nonce: str) -> str:
    from . import hub_auth

    return hub_auth.google_login_url(state, sign_redirect_uri(), nonce=nonce)


def google_exchange(code: str, expected_nonce: str | None = None) -> str | None:
    from . import hub_auth

    return hub_auth.exchange_code(code, sign_redirect_uri(), expected_nonce=expected_nonce)
