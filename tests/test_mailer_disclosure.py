"""Mailer (console mode + templates) and the canonical ERSD disclosure.

With SMTP unset every send prints to stdout instead of transmitting — the console dump must carry
the recipient, subject, every link, and attachment names. The From address derives from
``config.MAIL_FROM`` (blank ⇒ console mode). The disclosure module is the single source of truth:
versioned text with a stable content hash, distinct consumer vs B2B forms.
"""

from __future__ import annotations

import contextlib
import io


def _dump(fn, *a, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        res = fn(*a, **kw)
    return res, buf.getvalue()


def test_console_mode_prints_recipient_subject_and_link():
    from sign import mailer

    html = mailer.invite_html("Sam", "Contract", "please sign", "http://x/sign/TOK123")
    res, out = _dump(mailer.send_html, "to@example.com", "Signature requested", html)
    assert res["ok"] is True and res.get("console") is True
    assert "to@example.com" in out
    assert "Signature requested" in out
    assert "http://x/sign/TOK123" in out


def test_console_mode_lists_attachments():
    from sign import mailer

    res, out = _dump(
        mailer.send_html,
        "to@example.com",
        "Completed",
        "<p>done</p>",
        attachments=[("Contract-SIGNED.pdf", b"%PDF-1.4 fake bytes")],
    )
    assert res["ok"] is True
    assert "Attachments:" in out
    assert "Contract-SIGNED.pdf" in out


def test_from_address_is_mail_from(monkeypatch):
    from sign import config, mailer

    # blank MAIL_FROM → console mode, from is blank
    monkeypatch.setattr(config, "MAIL_FROM", "")
    res, _ = _dump(mailer.send_html, "to@example.com", "s", "<p>h</p>")
    assert res["from"] == ""
    # set MAIL_FROM but no SMTP_HOST → still console (no send), but from reflects config
    monkeypatch.setattr(config, "MAIL_FROM", "sender@brand.test")
    res2, _ = _dump(mailer.send_html, "to@example.com", "s", "<p>h</p>")
    assert res2["from"] == "sender@brand.test"


def test_all_templates_render_to_html():
    from sign import mailer

    assert "<" in mailer.invite_html("A", "Doc", "msg", "http://x")
    assert "<" in mailer.reminder_html("A", "Doc", "msg", "http://x")
    assert "<" in mailer.completed_html("Doc", "LS-ENV", "http://x/envelope/LS-ENV")
    assert "<" in mailer.envelope_html("A", "Doc", "LS-ENV", "http://x")
    assert "123456" in mailer.otp_html("123456")
    assert "<" in mailer.declined_html("Doc", "Sam", "changed mind", "LS-ENV")
    assert "<" in mailer.expired_html("Doc", "LS-ENV")


def test_html_to_text_extracts_links():
    from sign import mailer

    txt = mailer._html_to_text('<p>Hi</p><a href="http://x/link">Sign</a>')
    assert "Hi" in txt


def test_integrations_send_email_contract(monkeypatch):
    from sign import integrations

    r = integrations.send_email("nobody@example.com", "hi", "body text")
    assert r["ok"] is True
    bad = integrations.send_email("not-an-email", "hi", "body")
    assert bad["ok"] is False


# --- disclosure -------------------------------------------------------------
def test_disclosure_versioned_with_stable_hash():
    from sign import esign_disclosure, pdf_edit

    d = esign_disclosure.disclosure(consumer=False)
    assert d["version"] == esign_disclosure.VERSION
    assert d["consumer"] is False
    assert d["text_hash"] == pdf_edit.sha256(d["text"].encode("utf-8"))
    # hash is stable across calls
    assert esign_disclosure.disclosure(False)["text_hash"] == d["text_hash"]


def test_consumer_disclosure_differs_and_has_five_elements():
    from sign import esign_disclosure

    b2b = esign_disclosure.text_for(consumer=False)
    consumer = esign_disclosure.text_for(consumer=True)
    assert b2b != consumer
    assert "CONSUMER" in consumer
    # the five ESIGN §7001(c) elements are numbered in the consumer form
    for marker in (
        "1. PAPER COPIES",
        "2. WITHDRAWING CONSENT",
        "3. SCOPE OF CONSENT",
        "4. UPDATING",
        "5. HARDWARE",
    ):
        assert marker in consumer
    # hashes differ between the two forms
    dc = esign_disclosure.disclosure(True)
    db2b = esign_disclosure.disclosure(False)
    assert dc["text_hash"] != db2b["text_hash"]
