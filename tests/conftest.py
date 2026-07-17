"""Test bootstrap + shared fixtures for Lifted Sign.

``sign.config`` resolves ``SIGN_SECRET`` and ``SIGN_DATA_DIR`` at import time (and refuses to
boot without a real secret), so those env vars MUST be set before any ``sign`` module is imported.
The env block below runs at collection time — before any test module imports ``sign.app`` — and
points the suite at a throwaway secret and an empty temp data dir so every run exercises the
zero-config SQLite default on a genuinely blank database.

The fixtures below are the shared harness every focused test file builds on: an app-lifespan
``TestClient`` (so the infra tables + self-signed PAdES cert are provisioned exactly as in prod),
a per-test account factory that hands back a ready-to-use session-cookie header, and the two
document primitives (a real one-page PDF, a real signature PNG data-URL) the engine flow needs.
"""

from __future__ import annotations

import base64
import io
import os
import re
import secrets
import tempfile
from types import SimpleNamespace

# Set BEFORE `sign` is imported anywhere. setdefault so an outer runner can override.
os.environ.setdefault("SIGN_SECRET", secrets.token_urlsafe(48))
os.environ.setdefault("SIGN_DATA_DIR", tempfile.mkdtemp(prefix="signtest_"))
os.environ.setdefault("PUBLIC_BASE_URL", "http://localhost:8080")
# Webhook delivery tests use a monkeypatched transport with non-resolving example hostnames
# (and, for a self-hoster, loopback receivers), so opt out of the SSRF public-address guard for
# the suite. test_webhooks_ssrf exercises the guard directly by flipping this flag back off.
os.environ.setdefault("SIGN_WEBHOOK_ALLOW_INTERNAL", "true")
# Keep the optional add-ons OFF so tests assert the zero-config self-host surface.
for _k in (
    "SMTP_HOST",
    "MAIL_FROM",
    "GOOGLE_OAUTH_CLIENT_ID",
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "TWILIO_VERIFY_SERVICE_SID",
):
    os.environ.pop(_k, None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# The magic-link console line every auth flow prints when SMTP is unset.
MAGIC_LINK_RE = re.compile(r"/api/sign-portal/auth/magic/verify\?token=([\w.\-]+)")
# The self-issued email OTP the envelope flow prints in console mode.
OTP_RE = re.compile(r"verification code is (\d{6})")


# --- document primitives ----------------------------------------------------
def make_pdf(text: str = "Test Agreement", anchor: str = "Signature:") -> bytes:
    """A real one-page US-Letter PDF carrying an anchorable ``Signature:`` label, built with
    reportlab (a normal dependency) so anchor-based field placement and rasterized rendering
    both have genuine content to work against."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(72, 720, text)
    c.drawString(72, 690, "This agreement is entered into electronically.")
    c.drawString(72, 640, anchor)
    c.drawString(72, 600, "Date:")
    c.showPage()
    c.save()
    return buf.getvalue()


def make_png_data_url() -> str:
    """A genuine, non-blank signature PNG as a data-URL — a diagonal ink stroke on transparent,
    so ``pdf_edit.is_valid_image`` accepts it and it stamps as a real adopted signature."""
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (240, 80), (255, 255, 255, 0))
    d = ImageDraw.Draw(img)
    d.line((6, 70, 234, 10), fill=(18, 24, 120, 255), width=5)
    d.line((6, 40, 234, 40), fill=(18, 24, 120, 180), width=2)
    b = io.BytesIO()
    img.save(b, "PNG")
    return "data:image/png;base64," + base64.b64encode(b.getvalue()).decode()


# --- fixtures ---------------------------------------------------------------
@pytest.fixture(scope="session")
def client():
    """App-lifespan TestClient. Entering the context runs ``_lifespan`` — ``db.ensure_tables()``
    (infra tables) and ``esign.ensure_signing_material()`` (self-signed PAdES cert) — exactly as a
    real boot does, so completed documents seal with a genuine certification signature."""
    from sign.app import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def account_factory():
    """Create isolated sender accounts and hand back a ready session-cookie header.

    Returns a ``make(...)`` callable → a namespace with ``id``, ``email``, ``acct`` (the row),
    ``token`` (a real signed session), and ``headers`` (the ``cookie:`` header to attach to any
    ``/api/mysign/*`` request — TestClient drops ``Secure`` cookies over http, so the header is the
    reliable way to authenticate). Accounts are email-verified by default so they can send."""
    from sign import sign_accounts, sign_portal_auth

    def make(email: str | None = None, name: str = "Test User", verified: bool = True):
        email = (email or f"acct-{secrets.token_hex(6)}@example.com").lower()
        res = sign_accounts.create_account(email, name, None)
        assert "id" in res, res
        aid = res["id"]
        if verified:
            sign_accounts.set_email_verified(aid)
        acct = sign_accounts.account_by_id(aid)
        token = sign_portal_auth.make_session(aid)
        return SimpleNamespace(
            id=aid,
            email=email,
            acct=acct,
            token=token,
            headers={"cookie": f"{sign_portal_auth.COOKIE}={token}"},
        )

    return make
