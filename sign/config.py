"""Standalone configuration for Lifted Sign.

Everything is read from the process environment (a ``.env`` file, real env
vars, or your orchestrator's secret store). There is no ``config.local.json``
and no dependency on any host application — a self-hoster sets a handful of
variables and runs the server.

The module intentionally preserves the two accessors the signing engine was
written against — :func:`local` (a nested settings dict with an ``"esign"``
block) and :data:`REPO_ROOT` — so the engine can be lifted across with a
minimal diff. The difference from the original is that every value now comes
from the environment and every hosted-service default is **blank**, never a
hardcoded address or domain.

Required:
    SIGN_SECRET   A long random string. All session tokens, envelope-access
                  cookies, and OTP HMACs are keyed off it. The server refuses
                  to boot without a real value — a weak/placeholder secret is a
                  silent account-takeover risk, so we fail closed and loud.

Common:
    PUBLIC_BASE_URL       External URL of this install (e.g. https://sign.example.com).
                          Used to build signer links and email content. Default
                          http://localhost:8080 for local development.
    SIGN_DATA_DIR         Directory for the SQLite database and sealed PDFs.
                          Default ./data (created on boot).
    DATABASE_URL          Optional Postgres DSN. Unset ⇒ SQLite (the zero-config
                          default). Set ⇒ Postgres via psycopg.
    PORT                  HTTP port. Default 8080.

Email (see sign.mail): SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD,
    SMTP_STARTTLS, MAIL_FROM, MAIL_FROM_NAME, MAIL_REPLY_TO. With SMTP_HOST
    unset, mail is printed to the console (great for local dev, never for prod).

Signing material (optional; PAdES sealing): SIGN_PADES_CERT_PEM / _CERT_PATH,
    SIGN_PADES_KEY_PEM / _KEY_PATH, SIGN_PADES_KEY_PASSPHRASE. Absent ⇒ the
    engine self-signs / falls back to an AES-integrity seal (documents are still
    tamper-evident; self-signed certs simply won't chain to Adobe's trust store).

Legal identity (appears in disclosures / certificate / email footer): all blank
    by default — LEGAL_ENTITY, LEGAL_ADDRESS, SUPPORT_EMAIL. Shipping a real
    company name here for a third-party install would be a compliance hazard, so
    the default is empty and the operator fills in their own.

Optional auth add-ons: GOOGLE_OAUTH_CLIENT_ID/_SECRET/_REDIRECT (Google login),
    TWILIO_ACCOUNT_SID/_AUTH_TOKEN/_VERIFY_SERVICE_SID (SMS phone-OTP + 2FA).
    Any unset group simply disables that sign-in method.

Deployment mode: SIGN_HOSTED_MODE (default false), SIGN_SIGNUPS_OPEN
    (default true), ADMIN_EMAILS (comma list; enables the operator console).
    Hosted-only billing (Stripe) reads STRIPE_SECRET_KEY / STRIPE_PRICE_ID /
    STRIPE_WEBHOOK_SECRET and SIGN_PLAN_FREE_MONTHLY_LIMIT — imported lazily and
    only when SIGN_HOSTED_MODE=true, so the self-host build has zero payment code
    on its import path.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# --- placeholder secrets we refuse to boot with ----------------------------
# A self-hoster who copies .env.example verbatim and forgets to set SIGN_SECRET
# must get a hard, obvious failure — not a server that boots and then silently
# rejects every login because the HMAC key is a known constant.
_PLACEHOLDER_SECRETS = {
    "",
    "change-me",
    "changeme",
    "replace-me",
    "dev",
    "development",
    "secret",
    "your-secret-here",
    "please-change-this-in-production",
}


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    """Positive int from the env, falling back to ``default`` on missing/unparsable/non-positive —
    never raises, so a typo'd value can't crash boot (the limiter applies the same fallback)."""
    try:
        val = int(_env(name) or default)
    except (TypeError, ValueError):
        return default
    return val if val > 0 else default


def _require_secret() -> str:
    secret = os.environ.get("SIGN_SECRET", "").strip()
    if secret in _PLACEHOLDER_SECRETS or len(secret) < 16:
        sys.stderr.write(
            "\nFATAL: SIGN_SECRET is missing, too short, or a placeholder.\n"
            "Lifted Sign keys every login session, signer-access cookie, and\n"
            "one-time code off this value; booting without a real one would make\n"
            "authentication insecure and, under the old default, silently broken.\n\n"
            "Set it to a long random string, e.g.:\n"
            '    SIGN_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")\n\n'
        )
        raise SystemExit(78)  # EX_CONFIG
    return secret


# --- resolved configuration -------------------------------------------------

# REPO_ROOT anchors any relative path a config value points at (e.g. a signing
# key given as a repo-relative path). It is the install root, not a source repo.
REPO_ROOT: Path = Path(_env("SIGN_HOME", str(Path(__file__).resolve().parent.parent)))

SECRET: str = _require_secret()

PUBLIC_BASE_URL: str = _env("PUBLIC_BASE_URL", "http://localhost:8080").rstrip("/")
PORT: int = int(_env("PORT", "8080") or "8080")

DATA_DIR: Path = Path(_env("SIGN_DATA_DIR", str(REPO_ROOT / "data")))
DATABASE_URL: str = _env("DATABASE_URL")  # blank ⇒ SQLite

# PAdES auto-provisioning — when no signing cert/key is configured, generate a self-signed
# pair on first boot into the (gitignored) data dir so a zero-config install still produces
# REAL PKCS#7/PAdES certification signatures that pdf_sign.validate() confirms as
# valid+certified+not-tampered — instead of an AES-only seal that validate() can't attest to.
# A self-signed cert secures integrity + certification; it simply won't chain to Adobe's trust
# store without a CA-issued cert. Set SIGN_PADES_AUTOCERT=false to force the AES fallback, or
# supply your own SIGN_PADES_CERT_/KEY_ material to override.
PADES_AUTOCERT: bool = _bool("SIGN_PADES_AUTOCERT", True)
AUTOCERT_DIR: Path = DATA_DIR / "signing"
AUTOCERT_CERT: Path = AUTOCERT_DIR / "self-signed-cert.pem"
AUTOCERT_KEY: Path = AUTOCERT_DIR / "self-signed-key.pem"

# Email identity — all default blank; sign.mail falls back to console output
# when SMTP_HOST is unset and to MAIL_FROM for every from-address.
MAIL_FROM: str = _env("MAIL_FROM")
MAIL_FROM_NAME: str = _env("MAIL_FROM_NAME", "Lifted Sign")

# Legal identity — blank by default (operator fills in their own entity).
LEGAL_ENTITY: str = _env("LEGAL_ENTITY")
LEGAL_ADDRESS: str = _env("LEGAL_ADDRESS")
SUPPORT_EMAIL: str = _env("SUPPORT_EMAIL")

# Public-page identity — the operator name + website shown on the marketing landing (head
# metadata, footer, hero mockup). Neutral defaults keep a fresh OSS build from shipping a
# placeholder like "[Operator Name]" or "example.com": OPERATOR_NAME falls back to the legal
# entity then the mail-from display name; OPERATOR_URL falls back to this install's own URL.
OPERATOR_NAME: str = _env("OPERATOR_NAME") or LEGAL_ENTITY or MAIL_FROM_NAME
OPERATOR_URL: str = _env("OPERATOR_URL") or PUBLIC_BASE_URL


def public_host() -> str:
    """Host[:port] of PUBLIC_BASE_URL — the bare domain shown in the hero mockup + footer
    (e.g. 'sign.example.com'), never a hardcoded value."""
    from urllib.parse import urlsplit

    return urlsplit(PUBLIC_BASE_URL).netloc or "localhost:8080"


def page_tokens() -> dict[str, str]:
    """The {{token}} substitutions applied to served HTML page shells (see app._page). Every
    value is env-derived — no hardcoded domain or entity ever reaches the browser."""
    return {
        "{{PUBLIC_BASE_URL}}": PUBLIC_BASE_URL,
        "{{PUBLIC_HOST}}": public_host(),
        "{{OPERATOR_NAME}}": OPERATOR_NAME,
        "{{OPERATOR_URL}}": OPERATOR_URL,
        # Legal operator entity for the binding ToS/Privacy pages. Resolves to the configured
        # LEGAL_ENTITY when set (so the hosted deploy reads as a finished document), and falls
        # back to the visible "[Operator Name]" placeholder otherwise — an honest signal that a
        # self-hoster must set LEGAL_ENTITY to their own entity before publishing.
        "{{LEGAL_ENTITY}}": LEGAL_ENTITY or "[Operator Name]",
    }


# Per-account API rate limit (sign.ratelimit). Sustained requests allowed per account/API key
# per 60s window for the authenticated /api/mysign/* surface. The limiter reads SIGN_API_RATE_LIMIT
# from os.environ itself on each call (so it is tunable without a restart); this entry surfaces the
# knob alongside the rest of the env config. Non-positive/unparsable ⇒ the generous default.
API_RATE_LIMIT: int = _int("SIGN_API_RATE_LIMIT", 120)

# Webhook delivery SSRF guard. By default, webhook delivery refuses to POST to private,
# loopback, link-local, or otherwise non-public addresses (incl. cloud metadata at
# 169.254.169.254) so a tenant-supplied URL can't be used to reach internal services — this
# matters most on the multi-tenant hosted tier where subscription URLs are untrusted. A single-
# tenant self-hoster who legitimately needs to deliver to a loopback/internal receiver can set
# SIGN_WEBHOOK_ALLOW_INTERNAL=true to opt out of the guard.
WEBHOOK_ALLOW_INTERNAL: bool = _bool("SIGN_WEBHOOK_ALLOW_INTERNAL", False)

# Deployment mode / feature flags.
HOSTED_MODE: bool = _bool("SIGN_HOSTED_MODE", False)
SIGNUPS_OPEN: bool = _bool("SIGN_SIGNUPS_OPEN", True)
ADMIN_EMAILS: list[str] = [e.strip().lower() for e in _env("ADMIN_EMAILS").split(",") if e.strip()]


def _esign_block() -> dict:
    """The nested settings the signing engine reads via ``local()["esign"]``.

    Every from-address defaults to MAIL_FROM (or blank), and the public base to
    PUBLIC_BASE_URL — no hardcoded liftedholdings.com anywhere. Signing material
    is surfaced under the same keys ``_load_signing_material`` already expects.

    Signing material precedence: explicit SIGN_PADES_* env (inline PEM or path) wins;
    otherwise, when auto-provisioning is on and the self-signed pair exists on disk (written
    at boot by ensure_signing_material), fall back to it so the engine seals with PAdES.
    """
    cert_path = _env("SIGN_PADES_CERT_PATH")
    key_path = _env("SIGN_PADES_KEY_PATH")
    cert_pem = _env("SIGN_PADES_CERT_PEM")
    key_pem = _env("SIGN_PADES_KEY_PEM")
    if not (cert_pem or cert_path or key_pem or key_path) and PADES_AUTOCERT:
        if AUTOCERT_CERT.exists() and AUTOCERT_KEY.exists():
            cert_path, key_path = str(AUTOCERT_CERT), str(AUTOCERT_KEY)
    return {
        "sender_email": _env("MAIL_FROM"),
        "notify_email": _env("MAIL_FROM"),
        "otp_from": _env("MAIL_FROM"),
        "public_base": PUBLIC_BASE_URL,
        "signing_cert_pem": cert_pem,
        "signing_cert_path": cert_path,
        "signing_key_pem": key_pem,
        "signing_key_path": key_path,
        "signing_key_passphrase": _env("SIGN_PADES_KEY_PASSPHRASE"),
    }


def local() -> dict:
    """Return the settings dict the engine was written against.

    Kept for source-compatibility with the extracted modules. Values are
    env-derived; the shape mirrors the original ``config.local()`` so the
    signing engine needs only its import repointed, not a rewrite.
    """
    return {
        "esign": _esign_block(),
        "esign_public_url": PUBLIC_BASE_URL,
    }
