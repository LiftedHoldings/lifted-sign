"""Regression tests for the hardening fixes from the adversarial review:

* submit_signature must reject a malformed public ``values`` map with a clean error, never a 500;
* the email magic-link must be single-use (a replayed token cannot open a second session);
* TOTP enrollment-confirm uses a per-account replay marker (one account's confirm can't reject
  another account's valid code in the same 30-second step);
* the auto-provisioned PAdES private key is created with 0600 permissions.
"""

from __future__ import annotations


from sign import db, esign, sign_portal_auth, webauth


def _pdf() -> bytes:
    import io

    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    cv = canvas.Canvas(buf)
    cv.drawString(72, 720, "Master Services Agreement")
    cv.drawString(72, 690, "Signature:")
    cv.showPage()
    cv.save()
    return buf.getvalue()


def _sig_png() -> str:
    import base64
    import io

    from PIL import Image, ImageDraw

    im = Image.new("RGBA", (240, 70), (255, 255, 255, 0))
    ImageDraw.Draw(im).line([(10, 50), (220, 48)], fill=(10, 20, 60, 255), width=2)
    bb = io.BytesIO()
    im.save(bb, "PNG")
    return "data:image/png;base64," + base64.b64encode(bb.getvalue()).decode()


def _make_agreement_with_signer(pdf: bytes):
    aid = esign.create_agreement("MSA", pdf, "", "owner@example.com", None, 1)
    esign.set_signers(aid, [{"name": "Riley", "email": "riley@example.com"}])
    agr = esign.get_agreement(aid)
    sid = agr["signers"][0]["id"]
    esign.place_fields(
        aid,
        [
            {
                "page": 0,
                "x": 0.15,
                "y": 0.12,
                "w": 0.3,
                "h": 0.06,
                "type": "signature",
                "signer_id": sid,
                "required": True,
            }
        ],
    )
    esign.send(aid, "http://localhost:8080")
    ag = esign.get_agreement(aid)
    tok = ag["signers"][0]["token"]
    fid = ag["fields"][0]["id"]
    return aid, tok, fid


def test_submit_rejects_non_integer_field_key(client):
    """A valid signature plus a stray non-integer key → clean error, not an int()/DB crash (500)."""
    _, tok, fid = _make_agreement_with_signer(_pdf())
    esign.record_consent(tok, {"agreed": True}, "1.2.3.4", "ua")
    res = esign.submit_signature(
        tok, {str(fid): _sig_png(), "not-an-int": "x"}, True, "1.2.3.4", "ua"
    )
    assert res["ok"] is False
    assert res["error"] == "malformed submission"


def test_submit_rejects_non_string_value(client):
    """A valid signature plus a non-string value → clean error, not a SQLite binding crash."""
    _, tok, fid = _make_agreement_with_signer(_pdf())
    esign.record_consent(tok, {"agreed": True}, "1.2.3.4", "ua")
    res = esign.submit_signature(
        tok, {str(fid): _sig_png(), "999": {"nested": 1}}, True, "1.2.3.4", "ua"
    )
    assert res["ok"] is False
    assert res["error"] == "malformed submission"


def test_submit_route_returns_400_not_500(client):
    """The public HTTP route surfaces a malformed submission as a clean response, never a 500."""
    _, tok, fid = _make_agreement_with_signer(_pdf())
    client.post(f"/api/sign/token/{tok}/consent", json={"agreed": True})
    r = client.post(
        f"/api/sign/token/{tok}/submit",
        json={"values": {str(fid): _sig_png(), "abc": "x"}, "consent": True},
    )
    assert r.status_code == 200  # handler returns {ok:false,...}, not an unhandled 500
    assert r.json()["ok"] is False


def test_magic_link_is_single_use(client):
    """Verifying a magic-link token twice must not mint a second session."""
    email = "single-use@example.com"
    tok = sign_portal_auth.make_magic_token(email)
    first = client.get(f"/api/sign-portal/auth/magic/verify?token={tok}", follow_redirects=False)
    assert first.status_code == 307 and first.headers["location"] == "/app"
    assert any(c.startswith("__Host-ls_sign=") for c in first.headers.get_list("set-cookie"))
    # Replay the same token: rejected, no session cookie.
    second = client.get(f"/api/sign-portal/auth/magic/verify?token={tok}", follow_redirects=False)
    assert second.status_code == 307
    assert "sign_error=magic" in second.headers["location"]
    assert not any(
        c.startswith("__Host-ls_sign=") and "=;" not in c
        for c in second.headers.get_list("set-cookie")
    )


def test_magic_jti_claim_is_atomic_once(client):
    """db.claim_once returns True exactly once for a given key."""
    key = f"magic_used:{db.now()}"
    assert db.claim_once(key, {"exp": 1}) is True
    assert db.claim_once(key, {"exp": 1}) is False


def _totp_now(secret_b32: str) -> str:
    """Compute the current 6-digit TOTP for a base32 secret (RFC 6238, SHA-1, 30s)."""
    import base64
    import hmac
    import struct
    import time

    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    counter = int(time.time() // 30)
    mac = hmac.new(key, struct.pack(">Q", counter), "sha1").digest()
    off = mac[-1] & 0x0F
    val = struct.unpack(">I", mac[off : off + 4])[0] & 0x7FFFFFFF
    return f"{val % 1_000_000:06d}"


def test_totp_confirm_is_per_account(client, account_factory):
    """Two accounts confirming TOTP in the same 30s step must both succeed — the confirm path uses
    a per-account replay marker, not the single global one."""
    a = account_factory()
    b = account_factory()
    secret_a = webauth.gen_totp_secret()
    secret_b = webauth.gen_totp_secret()
    ok_a = sign_portal_auth.verify_totp_for_pending(a.id, secret_a, _totp_now(secret_a))
    ok_b = sign_portal_auth.verify_totp_for_pending(b.id, secret_b, _totp_now(secret_b))
    # Before the fix, A's accepted step bumped the GLOBAL marker and rejected B in the same step.
    assert ok_a and ok_b


def test_autoprovisioned_key_is_locked_down(client, tmp_path, monkeypatch):
    """The self-signed PAdES key is written 0600 (POSIX). On Windows the mode check is skipped."""
    import os
    import stat

    from sign import config

    monkeypatch.setattr(config, "AUTOCERT_DIR", tmp_path / "signing")
    monkeypatch.setattr(config, "AUTOCERT_CERT", tmp_path / "signing" / "cert.pem")
    monkeypatch.setattr(config, "AUTOCERT_KEY", tmp_path / "signing" / "key.pem")
    monkeypatch.setattr(config, "PADES_AUTOCERT", True)
    esign.ensure_signing_material()
    assert config.AUTOCERT_KEY.exists()
    if os.name == "posix":
        mode = stat.S_IMODE(config.AUTOCERT_KEY.stat().st_mode)
        assert mode == 0o600, oct(mode)
