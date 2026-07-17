"""LiftedSign sender accounts — the multi-tenant sender identity for a Lifted Sign install.

A *sign account* is a self-serve customer who signs up, logs in (password and/or Google),
and sends documents for signature from their own scoped dashboard. This is a PARALLEL tenant
to the admin (webauth) and portal (hub_auth) identities — a sign account is NEVER an
admin and can only ever see its own agreements (owner_account_id == this account's id).

Security properties (see the P1 threat model):
  * Passwords are PBKDF2-HMAC-SHA256, per-account 16-byte salt, 200k iters, constant-time
    compare. verify_password ALWAYS runs a full PBKDF2 (even with no account / google-only
    account) so there is no user-existence timing oracle.
  * Emails are stored lowercased; a UNIQUE index on LOWER(email) makes signup idempotent-safe.
  * session_ver is a per-account revocation epoch: logout / password-change bumps it so every
    outstanding session token for that account dies.
  * Billing is a STUB seam: new signups land sub_status='active' with NO payment call. can_send()
    is the single server-side paywall the send/remind routes consult. A real charge is later
    inserted at the activate seam — this module imports no payment processor (nmi/maverick/stripe).

ensure_tables() self-runs at import (mirrors esign.py) so the public signup route can rely on
the table existing at process boot, before any lazy e-sign import fires.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from . import db

# Single P1 plan. Payments are deferred; this is display + gate metadata only.
PLAN = {"id": "pro_unlimited", "price": "$29.99/mo", "name": "Pro (Unlimited)"}

PW_ITERS = 200_000
_DUMMY_HASH = "pbkdf2$%d$%s$%s" % (
    PW_ITERS,
    base64.b64encode(b"\x00" * 16).decode(),
    base64.b64encode(b"\x00" * 32).decode(),
)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS sign_accounts (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL,
  name          TEXT DEFAULT '',
  pw_hash       TEXT DEFAULT '',
  google_sub    TEXT DEFAULT '',
  totp_secret   TEXT DEFAULT '',
  status        TEXT DEFAULT 'active',
  sub_status    TEXT DEFAULT 'active',
  plan          TEXT DEFAULT 'pro_unlimited',
  session_ver   INTEGER DEFAULT 0,
  created_at    REAL,
  last_login_at REAL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sign_accounts_email ON sign_accounts(LOWER(email));
CREATE INDEX IF NOT EXISTS idx_sign_accounts_gsub ON sign_accounts(google_sub);
"""


def ensure_tables() -> None:
    conn = db.connect()
    try:
        conn.executescript(_SCHEMA)
        # db._columns handles BOTH backends — a raw PRAGMA is a syntax error on Postgres.
        acols = set(db._columns(conn, "sign_accounts"))
        for col, ddl in (
            # email_verified: 1 once the address is confirmed (Google accounts are 1 at creation —
            # Google already verified the email; password signups start 0 until the link is clicked).
            ("email_verified", "email_verified INTEGER DEFAULT 0"),
            # Twilio-Verify SMS 2FA (opt-in, per account). phone = E.164; sms_2fa = enforce at login.
            ("phone", "phone TEXT DEFAULT ''"),
            ("sms_2fa", "sms_2fa INTEGER DEFAULT 0"),
        ):
            if col not in acols:
                conn.execute(f"ALTER TABLE sign_accounts ADD COLUMN {ddl}")
                if col == "email_verified":
                    # Grandfather EXISTING accounts at the one-time migration (they signed up
                    # before verification existed — don't lock them out of sending). Runs only
                    # when the column is first added; new signups get 0/1 from create_account.
                    conn.execute("UPDATE sign_accounts SET email_verified=1")
        conn.commit()
    finally:
        conn.close()


# --- password hashing (no new dependency; mirrors esign_access._pbkdf2) ----------
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dig = hashlib.pbkdf2_hmac("sha256", (pw or "").encode("utf-8"), salt, PW_ITERS)
    return f"pbkdf2${PW_ITERS}${_b64(salt)}${_b64(dig)}"


def verify_password(pw: str, stored: str) -> bool:
    """Constant-time verify. ALWAYS runs a full PBKDF2 (using a dummy record when `stored`
    is empty / malformed) so an attacker can't distinguish "no such account" / "google-only
    account" from "wrong password" by timing (CHAL-5-style oracle defense)."""
    rec = stored if (stored or "").startswith("pbkdf2$") else _DUMMY_HASH
    try:
        _, iters_s, salt_b64, dig_b64 = rec.split("$", 3)
        iters = int(iters_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dig_b64)
    except Exception:
        _, iters_s, salt_b64, dig_b64 = _DUMMY_HASH.split("$", 3)
        iters = PW_ITERS
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dig_b64)
    cand = hashlib.pbkdf2_hmac("sha256", (pw or "").encode("utf-8"), salt, iters)
    ok = hmac.compare_digest(cand, expected)
    # Never authenticate against the dummy record or an account with no real password.
    if not (stored or "").startswith("pbkdf2$"):
        return False
    return ok


def password_ok(pw: str) -> bool:
    """Minimum password floor (T9). 8+ chars; keep simple to avoid lockout friction."""
    return isinstance(pw, str) and len(pw) >= 8


# --- account CRUD ----------------------------------------------------------------
def _row(r) -> dict | None:
    return dict(r) if r else None


def account_by_id(aid: int) -> dict | None:
    if not aid:
        return None
    conn = db.connect()
    try:
        return _row(conn.execute("SELECT * FROM sign_accounts WHERE id=?", (int(aid),)).fetchone())
    finally:
        conn.close()


def account_by_email(email: str) -> dict | None:
    em = (email or "").strip().lower()
    if not em:
        return None
    conn = db.connect()
    try:
        return _row(
            conn.execute("SELECT * FROM sign_accounts WHERE LOWER(email)=?", (em,)).fetchone()
        )
    finally:
        conn.close()


def account_by_phone(phone: str) -> dict | None:
    """Exact match on the stored E.164 phone — the lookup for phone-OTP login. Callers pass an
    already-normalized number (sign_portal_auth._e164)."""
    p = (phone or "").strip()
    if not p:
        return None
    conn = db.connect()
    try:
        return _row(conn.execute("SELECT * FROM sign_accounts WHERE phone=?", (p,)).fetchone())
    finally:
        conn.close()


def attach_phone(aid: int, phone: str) -> None:
    """Store a verified E.164 phone as the account's login identity (phone-OTP auth). Does NOT set
    sms_2fa — that flag is the opt-in login-2nd-factor; phone-OTP is already the primary factor."""
    _update(aid, phone=(phone or "").strip())


def account_by_google_sub(sub: str) -> dict | None:
    sub = (sub or "").strip()
    if not sub:
        return None
    conn = db.connect()
    try:
        return _row(
            conn.execute("SELECT * FROM sign_accounts WHERE google_sub=?", (sub,)).fetchone()
        )
    finally:
        conn.close()


def create_account(email: str, name: str = "", pw: str | None = None, google_sub: str = "") -> dict:
    """Create a sender account. sub_status='active' at creation (active-on-signup; payments
    deferred). Returns the account dict, or {"error":"exists"} on a duplicate email."""
    em = (email or "").strip().lower()
    if not em or "@" not in em:
        return {"error": "invalid_email"}
    if account_by_email(em):
        return {"error": "exists"}
    pw_hash = hash_password(pw) if pw else ""
    conn = db.connect()
    try:
        try:
            aid = db.insert_returning(
                conn,
                "INSERT INTO sign_accounts"
                "(email,name,pw_hash,google_sub,status,sub_status,plan,session_ver,created_at,email_verified)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    em,
                    (name or "").strip(),
                    pw_hash,
                    (google_sub or "").strip(),
                    "active",
                    "active",
                    PLAN["id"],
                    0,
                    time.time(),
                    1 if (google_sub or "").strip() else 0,  # Google already verified the email
                ),
            )
            conn.commit()
        except Exception:
            # Unique-index race: someone inserted the same email between the check and here.
            conn.rollback()
            return {"error": "exists"}
    finally:
        conn.close()
    return account_by_id(aid) or {"error": "exists"}


def _update(aid: int, **cols) -> None:
    if not aid or not cols:
        return
    sets = ", ".join(f"{k}=?" for k in cols)
    conn = db.connect()
    try:
        conn.execute(
            f"UPDATE sign_accounts SET {sets} WHERE id=?",
            (*cols.values(), int(aid)),
        )
        conn.commit()
    finally:
        conn.close()


def set_password(aid: int, pw: str) -> None:
    _update(aid, pw_hash=hash_password(pw))
    bump_session_version(aid)  # a password change logs out all existing sessions


def link_google(aid: int, sub: str) -> None:
    _update(aid, google_sub=(sub or "").strip())


def touch_login(aid: int) -> None:
    _update(aid, last_login_at=time.time())


def set_email_verified(aid: int) -> None:
    _update(aid, email_verified=1)


def is_email_verified(acct: dict | None) -> bool:
    return bool(acct and acct.get("email_verified"))


def set_phone_2fa(aid: int, phone: str, enabled: bool) -> None:
    """Store the E.164 phone (verified by the caller via Twilio) and toggle SMS 2FA at login."""
    _update(aid, phone=(phone or "").strip(), sms_2fa=1 if enabled else 0)


def disable_sms_2fa(aid: int) -> None:
    _update(aid, sms_2fa=0)


def set_totp(aid: int, enc_secret: str) -> None:
    _update(aid, totp_secret=enc_secret or "")


def clear_totp(aid: int) -> None:
    _update(aid, totp_secret="")


def totp_secret(aid: int) -> str:
    """Decrypted TOTP base32 secret, or '' if TOTP not armed."""
    from . import crypto

    acct = account_by_id(aid)
    v = (acct or {}).get("totp_secret") or ""
    if not v:
        return ""
    return crypto.decrypt(v) if crypto.looks_encrypted(v) else v


# --- session-version revocation epoch --------------------------------------------
def session_version(aid: int) -> int:
    acct = account_by_id(aid)
    return int((acct or {}).get("session_ver") or 0)


def bump_session_version(aid: int) -> int:
    conn = db.connect()
    try:
        conn.execute("UPDATE sign_accounts SET session_ver=session_ver+1 WHERE id=?", (int(aid),))
        conn.commit()
    finally:
        conn.close()
    return session_version(aid)


# --- billing stub (BILLING_MODE-style seam) --------------------------------------
def sub_status(aid: int) -> str:
    acct = account_by_id(aid)
    return (acct or {}).get("sub_status") or "canceled"


def set_sub_status(aid: int, status: str) -> None:
    if status in ("active", "past_due", "canceled"):
        _update(aid, sub_status=status)


def can_send(aid: int) -> bool:
    """The single server-side paywall the send/remind routes consult (T8). An account may
    send only while its account is active AND its subscription is active/past_due; a canceled
    subscription or suspended account blocks sending (read/download stay open elsewhere)."""
    acct = account_by_id(aid)
    if not acct:
        return False
    return acct.get("status") == "active" and (acct.get("sub_status") or "") in (
        "active",
        "past_due",
    )


def activate_subscription(aid: int) -> dict:
    """BILLING SEAM (deferred payments). P1 flips sub_status active with NO processor call.

    This is the EXACT point where a real charge is later inserted. It must NEVER be reachable to
    re-activate a canceled account from an untrusted client body without a charge — the
    /api/mysign route that calls this is deferred for real billing; in P1 it only re-affirms an
    already-active signup.
    """
    acct = account_by_id(aid)
    if not acct:
        return {"ok": False, "error": "not_found"}
    # P1: re-affirm ONLY. Flipping a canceled/past_due account back to active is a paid
    # transition that belongs behind a real charge — refuse it here so this route can
    # never grant free reactivation.
    if acct.get("sub_status") != "active":
        return {"ok": False, "error": "billing_required", "sub_status": acct.get("sub_status")}
    _update(aid, sub_status="active", plan=PLAN["id"])
    return {"ok": True, "sub_status": "active", "plan": PLAN["id"], "billing": "deferred"}


def account_count() -> int:
    conn = db.connect()
    try:
        return int(conn.execute("SELECT COUNT(*) FROM sign_accounts").fetchone()[0])
    finally:
        conn.close()


def list_accounts() -> list[dict]:
    """Every sign account, newest-signup first — the admin/operator read surface.

    This is the ONLY all-accounts reader; every other function is single-account scoped
    (by id/email/google_sub) so a self-serve `/api/mysign/*` handler can never enumerate the
    tenant table. Only server-side operator code behind the admin gate calls this. Returns raw
    rows (incl. status/sub_status/last_login_at) — the operator console projects the client-safe
    subset; secrets (pw_hash/totp_secret) are never rendered.
    """
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT * FROM sign_accounts ORDER BY created_at DESC, id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_account(aid: int) -> bool:
    """Hard-delete a single sign account row (operator purge of a test tenant).

    Does NOT touch that account's agreements — the operator purge deletes the owned e-sign rows
    first, then calls this. Kept here so the sign_accounts table is only ever mutated through this
    module. Returns True if a row was removed."""
    if not aid:
        return False
    conn = db.connect()
    try:
        cur = conn.execute("DELETE FROM sign_accounts WHERE id=?", (int(aid),))
        conn.commit()
        return bool(getattr(cur, "rowcount", 0))
    finally:
        conn.close()


def public_view(acct: dict | None) -> dict:
    """The client-safe projection of an account (never pw_hash / totp_secret / google_sub)."""
    if not acct:
        return {}
    return {
        "id": acct.get("id"),
        "email": acct.get("email"),
        "name": acct.get("name") or "",
        "plan": acct.get("plan") or PLAN["id"],
        "plan_price": PLAN["price"],
        "sub_status": acct.get("sub_status") or "active",
        "status": acct.get("status") or "active",
        "totp_enabled": bool(acct.get("totp_secret")),
        "email_verified": bool(acct.get("email_verified")),
        "is_google": bool(acct.get("google_sub")),
        "sms_2fa": bool(acct.get("sms_2fa")),
        "phone_masked": _mask_phone(acct.get("phone") or ""),
    }


def _mask_phone(p: str) -> str:
    p = (p or "").strip()
    return ("•" * max(0, len(p) - 4) + p[-4:]) if len(p) >= 4 else ""


ensure_tables()
