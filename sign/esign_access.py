"""LiftedSign access-control core — challenge hashing/verify, envelope sessions, identity.

THREAT MODEL (read before touching this file):
  * An *envelope session* (__Host-ls_env cookie) is a PROVEN-IDENTITY token only. It is minted
    ONLY after a Google email-match (ENV-4) or an EMAIL-OTP approval (ENV-5) — never from
    knowledge of an envelope_id or a signer token (ENV-1). It is scoped to exactly ONE
    {envelope_id, signer_id} pair (ENV-2) and is short-lived (30 min, ENV-3).
    L-29/L-32: the OTP is a SELF-ISSUED 6-digit code emailed from our own MAIL_FROM alias (see
    _send_email_otp); the legacy Twilio-Verify SMS branch was REMOVED — both call sites
    hardcode channel='email', so there is no live SMS-OTP path despite older comments.
  * Every /api/envelope/* handler MUST re-authorize via require_env_session(): authz comes ONLY
    from the signed token, never the path/body (IDOR defense). The path env_id is used solely to
    DETECT a token/path mismatch (cross-envelope attempt) → 403.
  * The sender access-lock CHALLENGE is stored as a salted PBKDF2 digest, Fernet-wrapped at rest
    (PII-3). For low-entropy types (ssn_last4 = 10^4, dob) the hash is offline-brute-forceable in
    milliseconds — so the REAL defense is ONLINE rate-limit + lockout (CHAL-3 / RL-1/2), not the KDF.
  * Compares are constant-time (hmac.compare_digest on fixed-length digests). A full PBKDF2 runs
    even when no record exists, to deny a timing/existence oracle (CHAL-5).
  * NEVER store, return, or log a raw challenge value, normalized input, SSN, DOB, or OTP code.
    agreement_events.detail is TYPE-ONLY (CHAL-6). Catch-and-generic any exception that could carry
    a secret into a message.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import re
import secrets
import time


from . import db, esign, webauth, crypto

# --- challenge hashing (CHAL-1 / CHAL-2 / PII-3) ---------------------------------
PBKDF2_ITERS = 200_000
# L-34 OPERATOR GUIDANCE — challenge-type entropy. PREFER a high-entropy `code` or `text`
# secret shared out-of-band. The identity types are LOW entropy and the PBKDF2 hash gives
# them almost NO confidentiality against a determined attacker (their entire keyspace is
# brute-forceable offline in well under a second): ssn_last4 ≈ 10^4, dob ≈ 36,500, full ssn
# ≈ 10^9. Their ONLY real protection is the ONLINE rate-limit + lockout (verify_challenge),
# so they are acceptable as a light "is this the right person" gate but MUST NOT be relied on
# as a secret. `ssn` is offered but is the worst choice (GLBA / state SSN-protection exposure
# for negligible benefit) — the admin UI labels it "not recommended". Steer signers to `code`/`text`.
_TYPES = ("none", "code", "text", "dob", "ssn", "ssn_last4")
_DUMMY_SALT = b"\x00" * 16  # keep timing uniform when no challenge record exists (CHAL-5)

# --- envelope session (ENV-1 / ENV-2 / ENV-3) ------------------------------------
ENV_SESSION_TTL = 1800  # 30 min absolute (ENV-3)
COOKIE = "__Host-ls_env"  # __Host- => Secure + Path=/ + no Domain (ENV-3)


def _to_iso_date(v: str) -> str:
    """Normalize a DOB to 'YYYY-MM-DD'. Accepts ISO, MM/DD/YYYY, M/D/YYYY, MMDDYYYY, YYYYMMDD.
    On failure returns the raw stripped string (a non-matching normalization → fails closed)."""
    v = (v or "").strip()
    if not v:
        return ""
    try:
        return datetime.date.fromisoformat(v).isoformat()
    except Exception:
        pass
    # L-28: only 4-digit-year formats — a two-digit year (%y) is ambiguous (e.g. '65' →
    # 1965 or 2065) and would silently fail-closed, locking out a legitimate signer who mistypes.
    for fmt in ("%m/%d/%Y", "%m-%d-%Y", "%m%d%Y", "%Y%m%d"):
        try:
            return datetime.datetime.strptime(v, fmt).date().isoformat()
        except Exception:
            continue
    return v


def normalize_challenge(value: str, ctype: str) -> str:
    """Deterministic normalization BEFORE hashing/compare (CHAL-2). Never logged."""
    v = (value or "").strip()
    if ctype in ("code", "text"):
        return re.sub(r"\s+", " ", v).casefold()
    if ctype in ("ssn", "ssn_last4"):
        return re.sub(r"\D", "", v)  # digits only; strips dashes/spaces
    if ctype == "dob":
        return _to_iso_date(v)  # -> 'YYYY-MM-DD'
    return v


def _pbkdf2(normalized: str, salt: bytes, iters: int = PBKDF2_ITERS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", normalized.encode("utf-8"), salt, iters)


def hash_challenge(value: str, ctype: str) -> tuple[str, str, int]:
    """Return (salt_b64, wrapped_hash, iters). wrapped_hash = crypto.encrypt(base64(digest))
    (PII-3 Fernet-at-rest). NEVER returns or logs `value`."""
    salt = secrets.token_bytes(16)
    digest = _pbkdf2(normalize_challenge(value, ctype), salt, PBKDF2_ITERS)
    return (
        base64.b64encode(salt).decode(),
        crypto.encrypt(base64.b64encode(digest).decode()),
        PBKDF2_ITERS,
    )


def _chal_fails(key: str) -> int:
    """Current recorded fail count for a lockout key (small int only — RL-1)."""
    conn = db.connect()
    try:
        row = conn.execute("SELECT fails FROM auth_limits WHERE key=?", (key,)).fetchone()
        return int(row["fails"]) if row and row["fails"] is not None else 0
    except Exception:
        return 0
    finally:
        conn.close()


def verify_challenge(envelope_id: str, signer_id: int, value: str, ip: str) -> dict:
    """Verify a sender access-lock challenge. Returns ONE of:
      {"ok": True}
      {"ok": False, "locked": True, "retry_after": 900}
      {"ok": False, "attempts_remaining": <int>}
    Never reveals which field was wrong, the type, or whether the signer/record exists (CHAL-5).
    The rate-limit (not the KDF) is the real defense for low-entropy types (CHAL-3)."""
    client_ip = ip or ""
    lk = f"chal:{signer_id}:{client_ip}"
    gk = f"chal:{signer_id}"
    # (2) PER-IP lock is the PRIMARY defense (CHAL-3). We deliberately do NOT honor a
    # per-signer *lock* here: a cross-IP global lock would let one attacker IP lock the
    # genuine signer out network-wide (DoS, sec-review M3). Per-IP lockout (5/900) caps a
    # single attacker; the global below is only a soft abuse speed-bump.
    if db.auth_limit_locked(lk):
        return {"ok": False, "locked": True, "retry_after": 900}
    # (3) Coarse per-signer global window — a soft, short speed-bump against many-IP brute
    # force. Set high enough that one IP (capped at 5 by its per-IP lock) can't exhaust it,
    # and a SHORT retry so exhausting it only delays everyone briefly (not an hour lock).
    if not db.auth_rate_allowed(gk, 40, 3600):
        return {"ok": False, "locked": True, "retry_after": 120}

    # (4) Resolve signer; ALWAYS run a full PBKDF2 regardless of existence (CHAL-5 timing).
    ctype = ""
    ok = False
    try:
        s = esign.signer_for_envelope(envelope_id, signer_id)
        if s and (s.get("challenge_type") or "none") != "none" and s.get("challenge_hash"):
            ctype = s["challenge_type"]
            stored = base64.b64decode(crypto.decrypt(s["challenge_hash"]))
            salt = base64.b64decode(s["challenge_salt"]) if s.get("challenge_salt") else _DUMMY_SALT
            # CHAL-5 / L-24: iters are PINNED to PBKDF2_ITERS for verification. hash_challenge
            # always writes records at PBKDF2_ITERS, so this matches every stored digest while
            # keeping the real path's PBKDF2 cost identical to the dummy/no-record path below —
            # a per-record challenge_iters could otherwise leak record existence via timing.
            cand = _pbkdf2(normalize_challenge(value, ctype), salt, PBKDF2_ITERS)
            ok = hmac.compare_digest(cand, stored)
        else:
            # No record / no challenge: burn an equivalent PBKDF2 and fail (no existence oracle).
            _pbkdf2(normalize_challenge(value, "code"), _DUMMY_SALT, PBKDF2_ITERS)
            ok = False
            s = s if s else None
    except Exception:
        # Never let an exception carry a secret out; fail closed.
        try:
            _pbkdf2("x", _DUMMY_SALT, PBKDF2_ITERS)
        except Exception:
            pass
        ok = False
        s = None

    # (5) Record the attempt for lockout accounting.
    # L-27 (concurrency note): db.auth_limit_record runs its read-modify-write under a single
    # BEGIN IMMEDIATE, so the fail COUNTER is incremented and the lock applied atomically — the
    # cap can't be corrupted by concurrent writers. The only residual race is that N requests
    # already in-flight past the (5) upfront auth_limit_locked() check can each perform one
    # PBKDF2 compare before any is recorded, so the *effective* number of guesses allowed before
    # the lock engages is approximately 5 + (in-flight concurrency), not exactly 5. For a
    # low-entropy challenge this is an acceptable, bounded slack (DEFER: a hard per-request serial
    # gate would require holding a write lock across the ~200ms PBKDF2 and serialize all verifies).
    db.auth_limit_record(lk, ok, fail_limit=5, lock_seconds=900)

    # (6) Audit — TYPE ONLY (CHAL-6). Skip entirely when no real record exists (no oracle).
    has_record = bool(
        s and (s.get("challenge_type") or "none") != "none" and s.get("challenge_hash")
    )
    if has_record:
        conn = db.connect()
        try:
            if ok:
                esign._event(
                    conn,
                    s["agreement_id"],
                    esign.ACCESS_CHALLENGE_PASSED,
                    signer_id=signer_id,
                    ip=client_ip,
                    detail=f"type={ctype}",
                )
                # CHAL-4 (signing page): persist the pass marker on the signer row.
                conn.execute(
                    "UPDATE agreement_signers SET challenge_passed_at=? WHERE id=?",
                    (time.time(), signer_id),
                )
            elif db.auth_limit_locked(lk):
                esign._event(
                    conn,
                    s["agreement_id"],
                    esign.ACCESS_CHALLENGE_LOCKED,
                    signer_id=signer_id,
                    ip=client_ip,
                    detail=f"type={ctype}",
                )
            else:
                esign._event(
                    conn,
                    s["agreement_id"],
                    esign.ACCESS_CHALLENGE_FAILED,
                    signer_id=signer_id,
                    ip=client_ip,
                    detail=f"type={ctype}",
                )
            conn.commit()
        finally:
            conn.close()

    # (7) Return shape.
    if ok:
        return {"ok": True}
    if db.auth_limit_locked(lk):
        return {"ok": False, "locked": True, "retry_after": 900}
    return {"ok": False, "attempts_remaining": max(0, 5 - _chal_fails(lk))}


# --- envelope session mint/verify (ENV-1 / ENV-2 / ENV-3 / TRAN-2) ---------------
def mint_env_session(
    envelope_id: str,
    signer_id: int,
    email_lc: str,
    method: str,
    chal_ok: bool,
    epoch: int = 0,
) -> str:
    """ENV-1: only callable AFTER a proven identity (Google/OTP). Reuses webauth._sign (same secret).
    Binds the session to exactly one {env_id, signer_id} and the agreement's current epoch (TRAN-2)."""
    return webauth._sign(
        {
            "k": "envsess",
            "env_id": envelope_id,
            "signer_id": int(signer_id),
            "email_lc": (email_lc or "").lower(),
            "m": method,
            "chal_ok": bool(chal_ok),
            "ep": int(epoch or 0),
            "exp": time.time() + ENV_SESSION_TTL,
        }
    )


def read_env_session(cookie: str | None) -> dict | None:
    if not cookie:
        return None
    d = webauth._unsign(cookie)  # verifies HMAC + exp
    return d if d and d.get("k") == "envsess" else None


def require_env_session(env_id_from_path: str, cookie: str | None):
    """ENV-2 / TRAN-2 — the IDOR + void guard.

    Returns one of:
      (session_dict, agreement, signer)              — authorized
      (session_dict, agreement, signer, "voided")    — authorized but the doc is voided/cancelled
      None                                           — DENY (caller maps to 401/403)

    Authz NEVER trusts env_id/signer_id from the path or body — only from the signed token.
    The path env_id is used solely to DETECT a token/path mismatch (cross-envelope attempt)."""
    d = read_env_session(cookie)
    if not d:
        return None
    # Resolve from the TOKEN's env_id, not the path.
    agr = esign.agreement_by_envelope(d.get("env_id", ""))
    if not agr:
        return None
    # The path must match the token (cross-envelope attempt otherwise).
    if d.get("env_id") != env_id_from_path:
        return None
    s = esign.signer_for_envelope(d["env_id"], d.get("signer_id"))
    if not s:
        return None
    if int(s.get("agreement_id") or 0) != int(agr.get("id") or -1):
        return None
    # TRAN-2: epoch check — a sender revoke / void bumps the epoch and kills live sessions.
    if int(d.get("ep", 0)) != int(agr.get("env_session_epoch", 0) or 0):
        return None
    if agr.get("status") in ("voided", "cancelled"):
        return (d, agr, s, "voided")
    return (d, agr, s)


# --- identity verification (ENV-4 / ENV-5) ---------------------------------------
def match_google_signer(envelope_id: str, verified_email: str) -> dict | None:
    """ENV-4: exact lowercased match against a signer email ON THIS envelope. No admin allowlist."""
    email_lc = (verified_email or "").strip().lower()
    if not email_lc:
        return None
    agr = esign.agreement_by_envelope(envelope_id)  # secrets stripped — we only need email/id
    if not agr:
        return None
    for s in agr.get("signers", []):
        if (s.get("email") or "").strip().lower() == email_lc:
            return s
    return None


def resolve_signer_by_email(envelope_id: str, email: str) -> dict | None:
    """Server-side resolve a signer on THIS envelope by email (used for OTP — the client
    supplies a hint but never the destination address). Returns the stripped signer dict."""
    return match_google_signer(envelope_id, email)


def otp_destination(envelope_id: str, signer_id: int, channel: str):
    """ENV-5: server picks the address from the signer row; client chooses channel only.
    channel 'sms' -> signer.phone (if present); else -> signer.email. Returns (channel, to) | None."""
    s = esign.signer_for_envelope(envelope_id, signer_id)
    if not s:
        return None
    ch = "sms" if channel == "sms" else "email"
    if ch == "sms":
        to = (s.get("phone") or "").strip()
        if not to:
            return None
    else:
        to = (s.get("email") or "").strip()
        if not to:
            return None
    return (ch, to)


def _mask(to: str, channel: str) -> str:
    """Display-only masking for the verify UI (CERT-4 parity). Never used for matching."""
    to = to or ""
    if channel == "sms":
        return ("•••• " + to[-4:]) if len(to) >= 4 else "••••"
    # email: a••••@domain.com
    if "@" in to:
        local, _, domain = to.partition("@")
        head = local[0] if local else ""
        return f"{head}••••@{domain}"
    return "••••"


def _otp_sent_key(signer_id: int, channel: str) -> str:
    return f"env_otp_sent:{int(signer_id)}:{'sms' if channel == 'sms' else 'email'}"


def _mark_otp_sent(signer_id: int, channel: str) -> None:
    db.set_setting(_otp_sent_key(signer_id, channel), time.time())


def _otp_send_fresh(signer_id: int, channel: str, ttl: int = 600) -> bool:
    """ENV-7 hardening (sec-review H2): a verify is only accepted if a code was actually
    SENT to this signer+channel within the last `ttl`s — blocks cold VerificationCheck
    abuse / griefing-lockouts against a destination that was never asked to send."""
    try:
        ts = float(db.get_setting(_otp_sent_key(signer_id, channel), 0) or 0)
    except Exception:
        ts = 0.0
    return (time.time() - ts) <= ttl


# --- self-issued EMAIL OTP (sent from our own MAIL_FROM alias, not Twilio) -------
# A 6-digit code is generated server-side and the recipient is given only an HMAC of it
# keyed by the SERVER secret (webauth._secret(), which lives in config, NOT the DB) — so a
# settings/DB leak can't brute-force the low-entropy code. 10-min TTL, single-use, and the
# same per-channel rate-limit/lockout as SMS applies in check_env_otp.
_EOTP_TTL = 600


def _eotp_key(signer_id: int) -> str:
    return f"env_eotp:{int(signer_id)}"


def _email_otp_from() -> str:
    from . import config

    return (config.local().get("esign", {}) or {}).get("otp_from") or config.MAIL_FROM


def _send_email_otp(signer_id: int, to: str) -> dict:
    from . import mailer, integrations

    code = "".join(secrets.choice("0123456789") for _ in range(6))
    salt = secrets.token_hex(8)
    h = hmac.new(webauth._secret(), (salt + code).encode("utf-8"), hashlib.sha256).hexdigest()
    db.set_setting(_eotp_key(signer_id), {"h": h, "salt": salt, "exp": time.time() + _EOTP_TTL})
    text = (
        f"Your LiftedSign verification code is {code}\n\n"
        "It expires in 10 minutes. If you didn't request this, you can ignore this email."
    )
    try:
        html = mailer.otp_html(code)
    except Exception:
        html = ""
    r = integrations.send_email(
        to,
        "Your LiftedSign verification code",
        text,
        html=html,
        from_addr=_email_otp_from(),
    )
    if not (r or {}).get("ok"):
        db.set_setting(_eotp_key(signer_id), 0)  # don't leave a live code if delivery failed
        return {"ok": False, "error": "Couldn't send the code right now."}
    _mark_otp_sent(signer_id, "email")
    return {"ok": True, "channel": "email", "to_masked": _mask(to, "email")}


def _verify_email_otp(signer_id: int, code: str) -> bool:
    code = (code or "").strip()
    if not (code.isdigit() and len(code) == 6):
        return False
    rec = db.get_setting(_eotp_key(signer_id), None)
    if not isinstance(rec, dict) or float(rec.get("exp", 0) or 0) < time.time():
        return False
    cand = hmac.new(
        webauth._secret(),
        (str(rec.get("salt", "")) + code).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if hmac.compare_digest(cand, str(rec.get("h", ""))):
        db.set_setting(_eotp_key(signer_id), 0)  # single-use: consume immediately
        return True
    return False


def send_env_otp(envelope_id: str, signer_id: int, channel: str, ip: str = "") -> dict:
    """ENV-5 / ENV-7 / RL-2: send an OTP to the on-record address. EMAIL = self-issued code from
    our MAIL_FROM alias. Rate-limited.

    L-29: the SMS (Twilio Verify) branch was removed — both call sites (routers) hardcode
    channel='email', so the SMS path was unreachable dead code. `channel` is kept in the
    signature for call-site compatibility but normalizes to email."""
    if not db.auth_rate_allowed(f"env:otpsend:{signer_id}", 5, 3600):
        return {"ok": False, "error": "Too many codes requested. Try again later."}
    dest = otp_destination(envelope_id, signer_id, channel)
    if not dest:
        return {"ok": False, "error": "No verification address on file."}
    ch, to = dest
    if db.auth_limit_locked(f"env:otp:{int(signer_id)}:{ch}"):
        return {"ok": False, "error": "Too many attempts. Try again later."}
    return _send_email_otp(signer_id, to)  # our own code, from the configured MAIL_FROM alias


def check_env_otp(envelope_id: str, signer_id: int, code: str, channel: str) -> bool:
    """ENV-5 / ENV-7: verify a self-issued email OTP sent to the on-record address. Hard-locked.
    Channel-bound lockout key (sec-review H2) + requires that a code was actually SENT to this
    signer+channel recently, so a verify can't be issued 'cold' (abuse/griefing-lockout).

    L-29: the SMS (Twilio Verify) branch was removed as unreachable — both call sites hardcode
    channel='email'. `channel` stays in the signature for compatibility but normalizes to email."""
    ch = "sms" if channel == "sms" else "email"
    key = f"env:otp:{int(signer_id)}:{ch}"
    if db.auth_limit_locked(key) or not (code or "").strip().isdigit():
        db.auth_limit_record(key, False, 5, 900)
        return False
    # H2: no verify without a recent send to this exact channel — blocks cold-checks.
    if not _otp_send_fresh(signer_id, ch):
        return False
    ok = _verify_email_otp(signer_id, code)  # our self-issued code
    db.auth_limit_record(key, ok, 5, 900)  # ENV-7: 5 fails -> 15-min lock
    if ok:
        db.set_setting(_otp_sent_key(signer_id, ch), 0)  # single-use: consume the send marker
    return ok


def mask_email(email: str) -> str:
    """CERT-4 helper, exposed for callers that need consistent masking."""
    return _mask(email or "", "email")
