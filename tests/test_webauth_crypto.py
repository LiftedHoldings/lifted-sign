"""Auth primitives — HMAC token signing, TOTP (RFC 6238), and Fernet-at-rest crypto.

Every session/OTP/state token in the product is an HMAC-SHA256 signed JSON blob with an ``exp``
claim; a wrong secret, a tamper, or an elapsed exp must all fail closed. TOTP enroll/verify with
single-use replay protection. crypto round-trips secrets with a version prefix and fails soft.
"""

from __future__ import annotations

import time


def test_sign_unsign_round_trip():
    from sign import webauth

    tok = webauth._sign({"k": "unit", "v": 7, "exp": time.time() + 60})
    d = webauth._unsign(tok)
    assert d and d["k"] == "unit" and d["v"] == 7


def test_unsign_rejects_tamper_and_expiry():
    from sign import webauth

    tok = webauth._sign({"k": "unit", "exp": time.time() + 60})
    body, sig = tok.split(".", 1)
    assert webauth._unsign(f"{body}.deadbeef" + sig[8:]) is None  # bad signature
    assert webauth._unsign("garbage-no-dot") is None
    expired = webauth._sign({"k": "unit", "exp": time.time() - 1})
    assert webauth._unsign(expired) is None


def test_totp_generate_verify_and_replay_guard():
    from sign import db, webauth

    secret = webauth.gen_totp_secret()
    step = int(time.time() // 30)
    code = webauth._hotp(secret, step)
    # reset the global replay marker so this test is order-independent
    db.set_setting(webauth._TOTP_LAST_STEP_KEY, 0)
    assert webauth.totp_verify(secret, code, window=1) is True
    # same code again is rejected (single-use replay guard)
    assert webauth.totp_verify(secret, code, window=1) is False
    # a wrong code fails
    assert webauth.totp_verify(secret, "000000", window=1) is False


def test_totp_uri_and_match_step():
    from sign import webauth

    secret = webauth.gen_totp_secret()
    uri = webauth.totp_uri(secret, account="a@b.com", issuer="LiftedSign")
    assert uri.startswith("otpauth://totp/") and "secret=" in uri
    step = webauth._totp_match_step(secret, webauth._hotp(secret, int(time.time() // 30)), 1)
    assert step is not None
    assert webauth._totp_match_step(secret, "not-digits", 1) is None


def test_phone_login_not_ready_without_twilio():
    from sign import webauth

    assert webauth.phone_login_ready() is False


def test_crypto_round_trip_and_prefix():
    from sign import crypto

    ct = crypto.encrypt("super-secret-seed")
    assert crypto.looks_encrypted(ct) is True
    assert ct.startswith("enc:v1:")  # cryptography is installed → real ciphertext
    assert crypto.decrypt(ct) == "super-secret-seed"


def test_crypto_passthrough_for_legacy_plaintext():
    from sign import crypto

    # unprefixed legacy value passes through unchanged, never raises
    assert crypto.decrypt("legacy-plaintext") == "legacy-plaintext"
    assert crypto.looks_encrypted("legacy-plaintext") is False
    assert crypto.decrypt(None) == ""


def test_crypto_fails_soft_on_wrong_key():
    from sign import crypto

    ct = crypto.encrypt("x")
    # corrupt ciphertext body → decrypt returns the token unchanged (fail soft), no raise
    corrupted = ct[:-4] + "AAAA"
    assert crypto.decrypt(corrupted) == corrupted
