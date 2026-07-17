"""Test bootstrap for Lifted Sign.

``sign.config`` resolves ``SIGN_SECRET`` and ``SIGN_DATA_DIR`` at import time (and refuses to
boot without a real secret), so those env vars MUST be set before any ``sign`` module is imported.
This conftest runs at collection time — before test modules import ``sign.app`` — and points the
suite at a throwaway secret and an empty temp data dir so every run exercises the zero-config
SQLite default on a genuinely blank database.
"""

from __future__ import annotations

import os
import secrets
import tempfile

# Set BEFORE `sign` is imported anywhere. setdefault so an outer runner can override.
os.environ.setdefault("SIGN_SECRET", secrets.token_urlsafe(48))
os.environ.setdefault("SIGN_DATA_DIR", tempfile.mkdtemp(prefix="signtest_"))
os.environ.setdefault("PUBLIC_BASE_URL", "http://localhost:8080")
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
