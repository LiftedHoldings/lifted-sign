"""Small unit surfaces — single-seed TOTP, portal-auth helpers, the SMTP send path, config.

Fills the remaining branch gaps that the flow tests don't reach: webauth's single-seed TOTP
storage helpers, sign_portal_auth's phone/method/magic helpers, and the mailer's real SMTP path
(exercised against an unreachable relay so the failure contract — ``{"ok": False, ...}`` — is
covered without a live server).
"""

from __future__ import annotations


# --- webauth single-seed TOTP + lock helpers --------------------------------
def test_single_seed_totp_storage(client):
    from sign import webauth

    secret = webauth.gen_totp_secret()
    webauth.save_totp_secret(secret)
    assert webauth.totp_secret() == secret
    assert webauth.totp_enrolled() is True


def test_totp_login_lock_helpers(client):
    from sign import webauth

    key = "login-lock-test"
    assert webauth.totp_login_locked(key) is False
    for _ in range(5):
        webauth.totp_login_record(key, False)
    assert webauth.totp_login_locked(key) is True
    webauth.totp_login_record("", True)  # empty key is a no-op, never raises


def test_b32decode_roundtrip():
    from sign import webauth

    s = webauth.gen_totp_secret()
    assert isinstance(webauth._b32decode(s), bytes)


# --- sign_portal_auth helpers -----------------------------------------------
def test_valid_phone_and_e164():
    from sign import sign_portal_auth

    assert sign_portal_auth.valid_phone("+15551234567") is True
    assert sign_portal_auth.valid_phone("5551234567") is True  # bare 10-digit → +1
    assert sign_portal_auth.valid_phone("nope") is False
    assert sign_portal_auth._e164("(555) 123-4567") == "+15551234567"
    assert sign_portal_auth._e164("") == ""


def test_available_methods_shape(client):
    from sign import sign_portal_auth

    m = sign_portal_auth.available_methods()
    assert m["magic"] is True
    assert m["google"] is False and m["phone"] is False


def test_send_phone_code_false_without_twilio(client):
    from sign import sign_portal_auth

    assert sign_portal_auth.send_phone_code("+15551234567") is False


def test_send_magic_link_console_for_existing(client, account_factory, capsys):
    from sign import sign_portal_auth

    auth = account_factory()
    sign_portal_auth.send_magic_link(auth.email)  # existing account → link prints to console
    out = capsys.readouterr().out
    assert "/api/sign-portal/auth/magic/verify?token=" in out


def test_send_magic_link_skips_bad_email(client, capsys):
    from sign import sign_portal_auth

    sign_portal_auth.send_magic_link("not-an-email")  # no send, no raise
    assert "magic/verify" not in capsys.readouterr().out


def test_send_verify_email_console(client, account_factory, capsys):
    from sign import sign_accounts, sign_portal_auth

    auth = account_factory(verified=False)
    sign_portal_auth.send_verify_email(sign_accounts.account_by_id(auth.id))
    out = capsys.readouterr().out
    assert "verify-email?token=" in out


# --- mailer real SMTP path (unreachable relay → failure contract) -----------
def test_mailer_smtp_failure_contract(monkeypatch):
    from sign import config, mailer

    monkeypatch.setattr(config, "MAIL_FROM", "sender@brand.test")
    # point at a closed port so the SMTP attempt fails fast and returns the error contract
    monkeypatch.setenv("SMTP_HOST", "127.0.0.1")
    monkeypatch.setenv("SMTP_PORT", "1")  # nothing listens here
    res = mailer.send_html(
        "to@example.com", "subj", "<p>body</p>", attachments=[("a.pdf", b"%PDF-1.4")]
    )
    assert res["ok"] is False
    assert "error" in res


def test_mailer_build_message_has_attachment(monkeypatch):
    from sign import mailer

    msg = mailer._build_message(
        "to@x.com", "s", "<p>h</p>", "from@x.com", "From", [("doc.pdf", b"%PDF-1.4")], "", None
    )
    raw = msg.as_bytes()
    assert b"doc.pdf" in raw
    assert b"application/pdf" in raw


# --- config accessors -------------------------------------------------------
def test_config_page_tokens_and_public_host():
    from sign import config

    tokens = config.page_tokens()
    assert "{{OPERATOR_NAME}}" in tokens
    assert config.public_host()  # non-empty host derived from PUBLIC_BASE_URL
    block = config.local()
    assert "esign" in block and "esign_public_url" in block
