"""Mailer SMTP transmit path — the branch the console-mode tests never reach.

With ``SMTP_HOST`` + ``MAIL_FROM`` both set, ``mailer.send_html`` stops printing and actually opens
an ``smtplib`` connection. These tests monkeypatch ``smtplib.SMTP`` / ``smtplib.SMTP_SSL`` with a
recording fake so the real transport wiring is exercised without a live relay:

  * port 587 → plain ``SMTP`` + EHLO + STARTTLS + (optional) AUTH + sendmail,
  * port 465 → implicit-TLS ``SMTP_SSL`` (no STARTTLS) + AUTH + sendmail,
  * no ``SMTP_USER`` → the connection is used without ``login`` (open relay),
  * a transport exception is swallowed into ``{"ok": False, "error": ...}`` (never raises),
  * attachments + reply-to actually land in the transmitted MIME bytes.
"""

from __future__ import annotations

import smtplib

import pytest


class _FakeSMTP:
    """Records the ordered method calls + the bytes handed to sendmail. Doubles as its own
    context manager (``with smtplib.SMTP(...) as srv``)."""

    instances: list = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.calls: list[str] = []
        self.login_args = None
        self.sent = None
        self.raise_on = None
        _FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self, *a):
        self.calls.append("ehlo")

    def starttls(self, *a, **k):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append("login")
        self.login_args = (user, password)

    def sendmail(self, from_addr, to, msg_bytes):
        self.calls.append("sendmail")
        if self.raise_on == "sendmail":
            raise smtplib.SMTPException("relay refused")
        self.sent = {"from": from_addr, "to": to, "bytes": msg_bytes}


@pytest.fixture
def smtp_env(monkeypatch):
    """Put the mailer into transmit mode with a recording fake for BOTH SMTP and SMTP_SSL."""
    from sign import config, mailer

    _FakeSMTP.instances = []
    monkeypatch.setattr(config, "MAIL_FROM", "sender@brand.test")
    monkeypatch.setenv("SMTP_HOST", "smtp.brand.test")
    monkeypatch.setattr(mailer.smtplib, "SMTP", _FakeSMTP)
    monkeypatch.setattr(mailer.smtplib, "SMTP_SSL", _FakeSMTP)
    return monkeypatch


def test_starttls_path_587_with_auth(smtp_env):
    from sign import mailer

    smtp_env.setenv("SMTP_PORT", "587")
    smtp_env.setenv("SMTP_USER", "relayuser")
    smtp_env.setenv("SMTP_PASSWORD", "relaypass")
    res = mailer.send_html("rx@example.com", "Hello", "<p>hi</p>")
    assert res == {"ok": True, "from": "sender@brand.test"}
    srv = _FakeSMTP.instances[-1]
    assert srv.port == 587
    # STARTTLS must run BEFORE login (credentials never cross a cleartext channel).
    assert srv.calls.index("starttls") < srv.calls.index("login")
    assert srv.login_args == ("relayuser", "relaypass")
    assert srv.sent["from"] == "sender@brand.test" and srv.sent["to"] == ["rx@example.com"]


def test_implicit_tls_path_465(smtp_env):
    from sign import mailer

    smtp_env.setenv("SMTP_PORT", "465")
    smtp_env.setenv("SMTP_USER", "u")
    smtp_env.setenv("SMTP_PASSWORD", "p")
    res = mailer.send_html("rx@example.com", "Hello", "<p>hi</p>")
    assert res["ok"] is True
    srv = _FakeSMTP.instances[-1]
    assert srv.port == 465
    # SMTPS is encrypted from the first byte → STARTTLS must NOT be issued.
    assert "starttls" not in srv.calls
    assert "login" in srv.calls and "sendmail" in srv.calls


def test_no_user_skips_login(smtp_env):
    from sign import mailer

    smtp_env.setenv("SMTP_PORT", "587")
    smtp_env.delenv("SMTP_USER", raising=False)
    smtp_env.delenv("SMTP_PASSWORD", raising=False)
    res = mailer.send_html("rx@example.com", "Hi", "<p>x</p>")
    assert res["ok"] is True
    srv = _FakeSMTP.instances[-1]
    assert "login" not in srv.calls  # open relay: no credentials presented
    assert "sendmail" in srv.calls


def test_transport_failure_returns_error_not_raise(smtp_env):
    from sign import mailer

    smtp_env.setenv("SMTP_PORT", "587")

    def _boom(host, port, timeout=None):
        raise smtplib.SMTPConnectError(421, "cannot connect")

    smtp_env.setattr(mailer.smtplib, "SMTP", _boom)
    res = mailer.send_html("rx@example.com", "Hi", "<p>x</p>")
    assert res["ok"] is False and res["error"]  # swallowed into a result dict, never raised


def test_attachments_and_reply_to_in_transmitted_bytes(smtp_env):
    from sign import mailer

    smtp_env.setenv("SMTP_PORT", "587")
    res = mailer.send_html(
        "rx@example.com",
        "Your signed copy",
        "<p>done</p>",
        attachments=[("Contract-SIGNED.pdf", b"%PDF-1.4 signed bytes")],
        reply_to="support@brand.test",
    )
    assert res["ok"] is True
    raw = _FakeSMTP.instances[-1].sent["bytes"]
    assert b"Contract-SIGNED.pdf" in raw  # attachment filename made it into the MIME payload
    assert b"support@brand.test" in raw  # Reply-To header present
