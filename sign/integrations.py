"""Outbound email compatibility shim.

The signing engine (``esign_access``, ``sign_portal_auth``) sends verification
and reset codes through ``integrations.send_gmail_new(...)`` — a name inherited
from the host application, where it drove the Gmail API. In the standalone
product there is no Gmail dependency: this reimplements the same call as a thin
wrapper over the pluggable mailer layer (:func:`sign.mailer.send_html`), which
handles SMTP / console output and the From identity from config.

The signature is preserved so callers are unchanged. Parameters the mailer seam
does not model (``from_addr``, ``cc``, ``bcc``) are accepted for compatibility
and ignored — the mailer derives the From address from ``MAIL_FROM`` and the
product's OTP/reset emails are single-recipient.
"""

from __future__ import annotations

import html as _html
from typing import Any


def _text_to_html(text: str) -> str:
    """Wrap a plain-text body in minimal, safe HTML so the html-only mailer seam
    can still deliver a text message with its formatting preserved."""
    return (
        '<pre style="font-family:inherit;white-space:pre-wrap;margin:0">'
        + _html.escape(text or "")
        + "</pre>"
    )


def send_gmail_new(
    to_addr: str,
    subject: str,
    body_text: str = "",
    html: str = "",
    from_addr: str = "",
    reply_to: str = "",
    cc: str = "",
    bcc: str = "",
    attachments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Send a single email via the mailer layer.

    Returns ``{"ok": True, "to": ...}`` on success or ``{"ok": False, "error": ...}``
    on failure — the contract callers check (they clear any live OTP when delivery
    fails). ``html`` is used as the body when provided; otherwise ``body_text`` is
    wrapped in minimal HTML. ``from_addr``/``cc``/``bcc`` are accepted for
    source-compatibility and ignored (see module docstring)."""
    from . import mailer

    if not to_addr or "@" not in to_addr:
        return {"ok": False, "error": "invalid recipient"}
    body_html = html or _text_to_html(body_text)
    try:
        result = mailer.send_html(
            to_addr,
            subject or "(no subject)",
            body_html,
            attachments=attachments,
            reply_to=(reply_to or None),
            # Forward the caller's plain-text body so the multipart/alternative carries a REAL text
            # part (better inbox placement) AND, crucially, so console mode (SMTP unset) prints the
            # actual text — including magic-link / verification URLs that _html_to_text would drop.
            text=(body_text or None),
        )
    except Exception as e:  # map any mailer error to the {"ok": False} contract
        return {"ok": False, "status": "error", "error": str(e)[:160]}
    # Honor an explicit result contract if the mailer returns one; otherwise a
    # clean return means the message was handed off successfully.
    if isinstance(result, dict) and "ok" in result:
        return result
    return {"ok": True, "to": to_addr}


# The signing engine's OTP/reset call sites (``esign_access._send_email_otp``,
# ``sign_portal_auth``) call ``integrations.send_email(...)`` — the same positional
# contract as :func:`send_gmail_new` (to, subject, body_text, html=, from_addr=).
# Expose it as an alias so both names resolve to the one mailer-backed implementation.
send_email = send_gmail_new
