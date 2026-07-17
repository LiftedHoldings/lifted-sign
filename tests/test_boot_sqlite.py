"""Golden-path boot + auth-surface e2e on the zero-config SQLite default.

These guard the two blockers found in the extraction review:

  1. A fresh SQLite boot must create the shared infra tables (settings, auth_limits,
     auth_rate_limits) so the FIRST auth request does not 500 with
     ``sqlite3.OperationalError: no such table``. If ``sign.app._lifespan`` ever stops calling
     ``db.ensure_tables()``, ``test_phone_start_does_not_500_on_fresh_db`` fails.
  2. A self-hoster with only ``SIGN_SECRET`` set must be able to sign in. The email magic-link
     path prints its link to the console when SMTP is unset, so the whole create-account →
     session flow is exercised here with zero external services.
"""

from __future__ import annotations

import contextlib
import io
import re

from fastapi.testclient import TestClient

from sign.app import app

_LINK_RE = re.compile(r"/api/sign-portal/auth/magic/verify\?token=([\w.\-]+)")


def _request_magic_link(client: TestClient, email: str, name: str = "") -> str | None:
    """POST /auth/magic/start and return the token from the console-printed link (SMTP unset)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        r = client.post("/api/sign-portal/auth/magic/start", json={"email": email, "name": name})
    assert r.status_code == 200 and r.json() == {"ok": True}, r.text
    m = _LINK_RE.search(buf.getvalue())
    return m.group(1) if m else None


def test_phone_start_does_not_500_on_fresh_db():
    """The blocker: on a blank DB the first auth request hit a missing table and 500'd.
    With the infra tables created at boot it returns a clean 503 (Twilio unconfigured)."""
    with TestClient(app) as c:
        r = c.post("/api/sign-portal/auth/phone/start", json={"phone": "+15551234567"})
        assert r.status_code != 500, r.text
        assert r.status_code in (400, 429, 503), r.text


def test_methods_endpoint_reports_magic_on_google_phone_off():
    with TestClient(app) as c:
        r = c.get("/api/sign-portal/auth/methods")
        assert r.status_code == 200
        data = r.json()
        assert data == {"magic": True, "google": False, "phone": False}


def test_magic_link_creates_account_and_session():
    email = "boot-tester@example.com"
    with TestClient(app) as c:
        token = _request_magic_link(c, email, "Boot Tester")
        assert token, "a magic link must print to the console when SMTP is unset"
        v = c.get(f"/api/sign-portal/auth/magic/verify?token={token}", follow_redirects=False)
        assert v.status_code in (302, 307)
        assert v.headers["location"] == "/app"
        set_cookie = v.headers.get("set-cookie", "")
        assert "__Host-ls_sign=" in set_cookie
        # TestClient drops Secure cookies over http, so replay the session cookie explicitly.
        cookie_val = re.search(r"__Host-ls_sign=([^;]+)", set_cookie).group(1)
        me = c.get(
            "/api/sign-portal/auth/me",
            headers={"cookie": f"__Host-ls_sign={cookie_val}"},
        )
        assert me.status_code == 200
        acct = me.json()["account"]
        assert acct["email"] == email
        # The clicked link proves mailbox control → the account is email-verified.
        assert acct["email_verified"] is True


def test_magic_verify_rejects_forged_token():
    with TestClient(app) as c:
        v = c.get(
            "/api/sign-portal/auth/magic/verify?token=not.a.real.token",
            follow_redirects=False,
        )
        assert v.status_code in (302, 307)
        assert v.headers["location"] == "/app?sign_error=magic"


def test_signups_closed_blocks_new_account_but_allows_existing(monkeypatch):
    """SIGN_SIGNUPS_OPEN=false must stop account CREATION at every path while still letting an
    existing account sign in. Exercised through the magic-link verify branch."""
    from sign import config, sign_accounts, sign_portal_auth

    monkeypatch.setattr(config, "SIGNUPS_OPEN", False)
    with TestClient(app) as c:
        # New email on a closed install → refuse creation, no account written.
        stranger = "closed-stranger@example.com"
        tok = sign_portal_auth.make_magic_token(stranger, "")
        v = c.get(f"/api/sign-portal/auth/magic/verify?token={tok}", follow_redirects=False)
        assert v.headers["location"] == "/app?sign_error=closed"
        assert sign_accounts.account_by_email(stranger) is None

        # An account that already exists still signs in on a closed install.
        member = "closed-member@example.com"
        sign_accounts.create_account(member, "Member", None)
        tok2 = sign_portal_auth.make_magic_token(member, "")
        v2 = c.get(f"/api/sign-portal/auth/magic/verify?token={tok2}", follow_redirects=False)
        assert v2.headers["location"] == "/app"
        assert "__Host-ls_sign=" in v2.headers.get("set-cookie", "")
