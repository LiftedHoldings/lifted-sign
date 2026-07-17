"""Sender-account authentication surface.

Covers the passwordless magic-link path (the zero-config self-host default), the SIGNUPS_OPEN
gate, forged/expired token rejection, the configured-methods probe, the TOTP enroll→confirm→login
handoff, one-click email verification, and session lifecycle (me / logout / revocation).
"""

from __future__ import annotations

import contextlib
import io
import time

from conftest import MAGIC_LINK_RE


def _magic_token(client, email, name=""):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = client.post("/api/sign-portal/auth/magic/start", json={"email": email, "name": name})
    assert r.status_code == 200 and r.json() == {"ok": True}, r.text
    m = MAGIC_LINK_RE.search(buf.getvalue())
    return m.group(1) if m else None


def _cookie_from(resp):
    sc = resp.headers.get("set-cookie", "")
    import re

    m = re.search(r"__Host-ls_sign=([^;]+)", sc)
    return m.group(1) if m else None


def test_methods_reports_magic_only_when_google_phone_unconfigured(client):
    r = client.get("/api/sign-portal/auth/methods")
    assert r.status_code == 200
    assert r.json() == {"magic": True, "google": False, "phone": False}


def test_magic_link_creates_account_session_and_me(client):
    email = "newbie@example.com"
    tok = _magic_token(client, email, "New Bie")
    assert tok
    v = client.get(f"/api/sign-portal/auth/magic/verify?token={tok}", follow_redirects=False)
    assert v.status_code in (302, 307)
    assert v.headers["location"] == "/app"
    cookie = _cookie_from(v)
    assert cookie
    me = client.get("/api/sign-portal/auth/me", headers={"cookie": f"__Host-ls_sign={cookie}"})
    assert me.status_code == 200
    acct = me.json()["account"]
    assert acct["email"] == email
    assert acct["email_verified"] is True  # a clicked link proves mailbox control


def test_magic_verify_rejects_forged_token(client):
    v = client.get(
        "/api/sign-portal/auth/magic/verify?token=not.a.real.token", follow_redirects=False
    )
    assert v.headers["location"] == "/app?sign_error=magic"


def test_magic_verify_rejects_expired_token(client, monkeypatch):
    """An expired (past-exp) but correctly-signed token must be rejected by the HMAC layer."""
    from sign import sign_portal_auth, webauth

    # forge a signmagic token that is already expired
    expired = webauth._sign(
        {"k": "signmagic", "em": "late@example.com", "nm": "", "jti": "x", "exp": time.time() - 5}
    )
    assert sign_portal_auth.read_magic_token(expired) is None
    v = client.get(f"/api/sign-portal/auth/magic/verify?token={expired}", follow_redirects=False)
    assert v.headers["location"] == "/app?sign_error=magic"


def test_signups_closed_blocks_new_but_allows_existing(client, monkeypatch):
    from sign import config, sign_accounts, sign_portal_auth

    monkeypatch.setattr(config, "SIGNUPS_OPEN", False)
    stranger = "closed-new@example.com"
    tok = sign_portal_auth.make_magic_token(stranger, "")
    v = client.get(f"/api/sign-portal/auth/magic/verify?token={tok}", follow_redirects=False)
    assert v.headers["location"] == "/app?sign_error=closed"
    assert sign_accounts.account_by_email(stranger) is None

    member = "closed-existing@example.com"
    sign_accounts.create_account(member, "Member", None)
    tok2 = sign_portal_auth.make_magic_token(member, "")
    v2 = client.get(f"/api/sign-portal/auth/magic/verify?token={tok2}", follow_redirects=False)
    assert v2.headers["location"] == "/app"
    assert "__Host-ls_sign=" in v2.headers.get("set-cookie", "")


def test_magic_start_rejects_bad_email(client):
    r = client.post("/api/sign-portal/auth/magic/start", json={"email": "nope"})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_email"


def test_me_requires_session(client):
    assert client.get("/api/sign-portal/auth/me").status_code == 401


def test_logout_revokes_session(client, account_factory):
    auth = account_factory()
    # session valid before logout
    assert client.get("/api/sign-portal/auth/me", headers=auth.headers).status_code == 200
    lo = client.post("/api/sign-portal/auth/logout", headers=auth.headers)
    assert lo.status_code == 200
    # bump_session_version invalidated the old signed token
    assert client.get("/api/sign-portal/auth/me", headers=auth.headers).status_code == 401


def test_phone_start_no_500_on_fresh_db_and_unconfigured_twilio(client):
    r = client.post("/api/sign-portal/auth/phone/start", json={"phone": "+15551234567"})
    assert r.status_code in (400, 429, 503), r.text
    assert r.status_code != 500


def test_phone_start_rejects_invalid_number(client):
    r = client.post("/api/sign-portal/auth/phone/start", json={"phone": "abc"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_phone"


def test_verify_email_link_marks_verified(client, account_factory):
    from sign import sign_accounts, sign_portal_auth

    auth = account_factory(verified=False)
    assert sign_accounts.is_email_verified(sign_accounts.account_by_id(auth.id)) is False
    tok = sign_portal_auth.make_verify_token(auth.id, auth.email)
    r = client.get(f"/api/sign-portal/verify-email?token={tok}", follow_redirects=False)
    assert r.headers["location"] == "/app?verified=1"
    assert sign_accounts.is_email_verified(sign_accounts.account_by_id(auth.id)) is True


def test_verify_email_rejects_bad_token(client):
    r = client.get("/api/sign-portal/verify-email?token=garbage", follow_redirects=False)
    assert r.headers["location"] == "/app?verify_error=1"


def test_totp_enroll_confirm_then_magic_requires_2fa(client, account_factory):
    """Enroll TOTP on a live session, then prove a fresh magic-link login hands off to the 2FA
    step instead of minting a full session (an armed authenticator is never bypassed)."""
    from sign import sign_accounts, webauth

    auth = account_factory()
    enroll = client.post("/api/sign-portal/auth/totp/enroll", headers=auth.headers)
    assert enroll.status_code == 200
    secret = enroll.json()["secret"]
    totp_cookie = _named_cookie(enroll, "__Host-ls_sign_totp")
    code = webauth._hotp(secret, int(time.time() // 30))
    confirm = client.post(
        "/api/sign-portal/auth/totp/confirm",
        json={"code": code},
        headers={"cookie": f"{auth.headers['cookie']}; __Host-ls_sign_totp={totp_cookie}"},
    )
    assert confirm.json() == {"ok": True}, confirm.text
    assert sign_accounts.account_by_id(auth.id)["totp_secret"]

    # A magic-link login now must NOT complete straight to /app — it hands off to 2FA.
    from sign import sign_portal_auth

    mtok = sign_portal_auth.make_magic_token(auth.email, "")
    v = client.get(f"/api/sign-portal/auth/magic/verify?token={mtok}", follow_redirects=False)
    assert v.headers["location"] == "/app?need_2fa=1"
    assert "__Host-ls_sign_2fa=" in v.headers.get("set-cookie", "")


def _named_cookie(resp, name):
    import re

    for part in (
        resp.headers.get_list("set-cookie")
        if hasattr(resp.headers, "get_list")
        else [resp.headers.get("set-cookie", "")]
    ):
        m = re.search(rf"{re.escape(name)}=([^;]+)", part or "")
        if m:
            return m.group(1)
    return None
