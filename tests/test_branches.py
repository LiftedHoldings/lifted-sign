"""Targeted branch coverage across accounts, portal auth, the draft editor, and admin queries.

These fill in the error/edge branches the happy-path e2e tests don't reach: account mutators,
phone/2FA portal routes that degrade cleanly without Twilio, edit-text fail-closed validation, the
admin (non-owner) listing surface, and the multi-envelope inbox switch.
"""

from __future__ import annotations

from conftest import make_pdf, make_png_data_url


# --- sign_accounts mutators -------------------------------------------------
def test_account_google_link_and_lookup(client, account_factory):
    from sign import sign_accounts

    auth = account_factory()
    sign_accounts.link_google(auth.id, "google-sub-123")
    assert sign_accounts.account_by_google_sub("google-sub-123")["id"] == auth.id


def test_account_phone_2fa_and_disable(client, account_factory):
    from sign import sign_accounts

    auth = account_factory()
    sign_accounts.set_phone_2fa(auth.id, "+15551230000", True)
    acct = sign_accounts.account_by_id(auth.id)
    assert acct["sms_2fa"] == 1 and acct["phone"] == "+15551230000"
    assert sign_accounts.account_by_phone("+15551230000")["id"] == auth.id
    sign_accounts.disable_sms_2fa(auth.id)
    assert sign_accounts.account_by_id(auth.id)["sms_2fa"] == 0


def test_account_totp_set_and_clear(client, account_factory):
    from sign import crypto, sign_accounts

    auth = account_factory()
    sign_accounts.set_totp(auth.id, crypto.encrypt("SEEDSEEDSEED"))
    assert sign_accounts.totp_secret(auth.id) == "SEEDSEEDSEED"
    sign_accounts.clear_totp(auth.id)
    assert sign_accounts.account_by_id(auth.id)["totp_secret"] == ""


def test_create_account_rejects_duplicate_and_bad_email(client):
    from sign import sign_accounts

    assert sign_accounts.create_account("nope", "x", None) == {"error": "invalid_email"}
    email = "dupe@example.com"
    sign_accounts.create_account(email, "First", None)
    assert sign_accounts.create_account(email, "Second", None) == {"error": "exists"}


def test_activate_subscription_reaffirms_active(client, account_factory):
    from sign import sign_accounts

    auth = account_factory()
    res = sign_accounts.activate_subscription(auth.id)
    assert res["ok"] is True


def test_session_version_bump_revokes(client, account_factory):
    from sign import sign_accounts, sign_portal_auth

    auth = account_factory()
    tok = sign_portal_auth.make_session(auth.id)
    assert sign_portal_auth.session_account(tok) is not None
    sign_accounts.bump_session_version(auth.id)
    assert sign_portal_auth.session_account(tok) is None  # old token no longer valid


# --- portal auth routes that degrade without Twilio -------------------------
def test_phone_verify_expired_without_cookie(client):
    r = client.post("/api/sign-portal/auth/phone/verify", json={"code": "123456"})
    assert r.status_code == 401 and r.json()["error"] == "expired"


def test_2fa_route_expired_without_pending(client):
    r = client.post("/api/sign-portal/auth/2fa", json={"code": "123456"})
    assert r.status_code == 401 and r.json()["error"] == "expired"


def test_resend_verify_requires_session(client):
    assert client.post("/api/sign-portal/auth/resend-verify").status_code == 401


def test_resend_verify_ok_for_unverified(client, account_factory):
    auth = account_factory(verified=False)
    r = client.post("/api/sign-portal/auth/resend-verify", headers=auth.headers)
    assert r.json() == {"ok": True}


def test_totp_disable_without_enrollment_is_noop(client, account_factory):
    auth = account_factory()
    r = client.post(
        "/api/sign-portal/auth/totp/disable", json={"code": "000000"}, headers=auth.headers
    )
    assert r.json() == {"ok": True}


def test_google_login_redirects_to_hint_when_unconfigured(client):
    r = client.get("/api/sign-portal/auth/google", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert r.headers["location"] == "/app?sign_error=google_unconfigured"


def test_google_callback_bad_state(client):
    r = client.get(
        "/api/sign-portal/auth/google/callback?code=x&state=forged", follow_redirects=False
    )
    assert r.headers["location"] == "/app?sign_error=state"


# --- edit-text fail-closed validation --------------------------------------
def test_edit_text_rejects_bad_inputs(client, account_factory):
    auth = account_factory()
    aid = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "Edit"},
        headers=auth.headers,
    ).json()["id"]
    # empty items list → 400
    r0 = client.post(
        f"/api/mysign/agreements/{aid}/edit-text", json={"items": []}, headers=auth.headers
    )
    assert r0.status_code == 400
    # bad page index
    r1 = client.post(
        f"/api/mysign/agreements/{aid}/edit-text",
        json={
            "items": [{"page": 99, "bbox": {"x": 0.1, "y": 0.1, "w": 0.2, "h": 0.02}, "text": "x"}]
        },
        headers=auth.headers,
    )
    assert r1.status_code == 400 and r1.json()["error"] == "bad page"
    # bad bbox
    r2 = client.post(
        f"/api/mysign/agreements/{aid}/edit-text",
        json={
            "items": [{"page": 0, "bbox": {"x": 0.5, "y": 0.1, "w": -0.2, "h": 0.02}, "text": "x"}]
        },
        headers=auth.headers,
    )
    assert r2.status_code == 400 and r2.json()["error"] == "bad bbox"
    # empty text
    r3 = client.post(
        f"/api/mysign/agreements/{aid}/edit-text",
        json={
            "items": [{"page": 0, "bbox": {"x": 0.1, "y": 0.1, "w": 0.2, "h": 0.02}, "text": "   "}]
        },
        headers=auth.headers,
    )
    assert r3.status_code == 400 and r3.json()["error"] == "empty"


# --- admin (non-owner) list surface ----------------------------------------
def test_admin_list_and_count_agreements(client, account_factory):
    from sign import esign

    auth = account_factory()
    esign.create_agreement("Admin Doc", make_pdf(), owner_account_id=auth.id)
    # the admin/global surface (no owner scope) sees at least what exists
    total = esign.count_agreements()
    assert total >= 1
    rows = esign.list_agreements(limit=5, offset=0)
    assert isinstance(rows, list) and len(rows) >= 1


# --- envelope inbox switch --------------------------------------------------
def test_envelope_switch_between_two_envelopes(client, account_factory):
    """A signer verified on one envelope can switch to a second envelope addressed to the same
    email without a fresh identity check."""
    import contextlib
    import io
    import re

    from conftest import OTP_RE

    auth = account_factory()
    email = "switcher@example.com"

    def _complete(name):
        aid = client.post(
            "/api/mysign/agreements",
            files={"file": ("d.pdf", make_pdf(), "application/pdf")},
            data={"name": name},
            headers=auth.headers,
        ).json()["id"]
        client.post(
            f"/api/mysign/agreements/{aid}/signers",
            json={"signers": [{"name": "Switcher", "email": email}]},
            headers=auth.headers,
        )
        client.post(
            f"/api/mysign/agreements/{aid}/fields",
            json={"fields": [{"type": "signature", "anchor": "Signature:", "signer": email}]},
            headers=auth.headers,
        )
        tok = client.post(
            f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers
        ).json()["links"][0]["token"]
        pl = client.get(f"/api/sign/token/{tok}").json()
        client.post(
            f"/api/sign/token/{tok}/submit",
            json={"values": {str(pl["fields"][0]["id"]): make_png_data_url()}, "consent": True},
        )
        from sign import esign

        return esign.get_agreement(aid)["envelope_id"]

    env1 = _complete("First Env")
    env2 = _complete("Second Env")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        client.post(
            f"/api/envelope/{env1}/auth/start", json={"method": "otp", "signer_hint": email}
        )
    code = OTP_RE.search(buf.getvalue()).group(1)
    ver = client.post(
        f"/api/envelope/{env1}/auth/otp-verify", json={"signer_hint": email, "code": code}
    )
    cookie = None
    for part in ver.headers.get_list("set-cookie"):
        m = re.search(r"__Host-ls_env=([^;]+)", part)
        if m:
            cookie = m.group(1)
    hdr = {"cookie": f"__Host-ls_env={cookie}"}

    inbox = client.get(f"/api/envelope/{env1}/inbox", headers=hdr).json()
    assert inbox["count"] >= 2
    sw = client.post(f"/api/envelope/{env1}/switch", json={"target": env2}, headers=hdr)
    assert sw.json()["ok"] is True and sw.json()["env_id"] == env2
