"""Symmetric encryption for secrets at rest (TOTP seeds, etc.).

Keyed off :data:`sign.config.SECRET` (the required ``SIGN_SECRET``) so there is
no separate key to manage: the 32-byte Fernet key is derived as
``base64.urlsafe_b64encode(sha256(SECRET))``. Fernet gives AES-128-CBC + HMAC
authentication.

Design / backward-compat:
  * :func:`encrypt` always returns a string with a recognizable version prefix
    so readers can tell ciphertext from a LEGACY plaintext value and pass the
    latter through unchanged (``enc:v1:`` = real ciphertext, ``enc:v0:`` = a
    passthrough marker used only when ``cryptography`` is unavailable).
  * If ``cryptography`` is not importable we degrade to a clearly-labeled
    identity passthrough (``enc:v0:``) so nothing breaks — the value is NOT
    encrypted in that case (only marked). ``cryptography`` is a normal
    dependency of this package, so that path is a last-resort safety net.
  * The key is derived lazily at call time. Rotating ``SIGN_SECRET`` re-derives
    the key; ciphertext written under the old secret will no longer decrypt and
    :func:`decrypt` fails soft (returns the token unchanged) rather than raising
    — a secret rotation is an intentional break.
"""

from __future__ import annotations

import base64
import hashlib

from . import config

# v1 = real Fernet ciphertext; v0 = passthrough marker (cryptography unavailable).
_PREFIX_V1 = "enc:v1:"
_PREFIX_V0 = "enc:v0:"
_PREFIXES = (_PREFIX_V1, _PREFIX_V0)

try:  # optional dependency — degrade gracefully if missing
    from cryptography.fernet import Fernet

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - only hit when cryptography is absent
    Fernet = None  # type: ignore
    _HAVE_CRYPTO = False


def available() -> bool:
    """True when real (Fernet) encryption is in effect; False = passthrough only."""
    return _HAVE_CRYPTO


def _key() -> bytes:
    """Derive the 32-byte urlsafe-base64 Fernet key from ``config.SECRET``."""
    digest = hashlib.sha256(config.SECRET.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _fernet() -> "Fernet | None":
    if not _HAVE_CRYPTO:
        return None
    return Fernet(_key())


def looks_encrypted(s: str | None) -> bool:
    """True if the value carries one of our version prefixes (v1 ciphertext or
    v0 passthrough marker). LEGACY plaintext has no prefix -> False."""
    return bool(s) and str(s).startswith(_PREFIXES)


def encrypt(plaintext: str, *, allow_plaintext: bool = False) -> str:
    """Return a prefixed token. ``enc:v1:`` is real ciphertext; ``enc:v0:`` is a
    passthrough marker used only when ``cryptography`` is unavailable.

    ``allow_plaintext`` is accepted for source-compatibility with callers that
    passed it; it has no effect here because the encryption key is always
    derivable from the required ``SIGN_SECRET``.
    """
    if plaintext is None:
        plaintext = ""
    f = _fernet()
    if f is None:
        # No crypto lib: store behind a marker so reads still round-trip. The
        # value is NOT encrypted — install the 'cryptography' package to fix.
        return _PREFIX_V0 + plaintext
    token = f.encrypt(plaintext.encode()).decode()
    return _PREFIX_V1 + token


def decrypt(token: str) -> str:
    """Reverse :func:`encrypt`. Unprefixed (LEGACY plaintext) values and values
    we can't decrypt are returned as-is so a config change never hard-locks a
    login."""
    if token is None:
        return ""
    s = str(token)
    if s.startswith(_PREFIX_V0):
        return s[len(_PREFIX_V0) :]
    if s.startswith(_PREFIX_V1):
        f = _fernet()
        if f is None:
            return s  # can't open without the crypto lib — fail soft
        try:
            return f.decrypt(s[len(_PREFIX_V1) :].encode()).decode()
        except Exception:
            return s  # wrong key / corrupt token — fail soft
    # LEGACY plaintext — pass through unchanged.
    return s
