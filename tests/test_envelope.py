"""Envelope return-view — proven-identity signer sessions + the access-lock challenge.

Drives the whole returning-signer surface end to end: a completed envelope, self-issued email OTP
identity (console-captured code), the scoped ``__Host-ls_env`` session, the sender access-lock
challenge (wrong value rejected, correct value unlocks), the multi-envelope inbox, and the gated
executed-copy + certificate downloads. Also unit-tests the ``esign_access`` core (challenge
hashing/verify with lockout, session mint/verify, identity match, DOB normalization).
"""

from __future__ import annotations

import contextlib
import io
import re

from conftest import OTP_RE, make_png_data_url, make_pdf


def _env_cookie(resp):
    for part in resp.headers.get_list("set-cookie"):
        m = re.search(r"__Host-ls_env=([^;]+)", part)
        if m:
            return m.group(1)
    return None


def _complete_envelope(client, auth, signer_email="returner@example.com"):
    """Create → sign → complete an agreement; return (aid, env_id, signer_id)."""
    r = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "Envelope Doc"},
        headers=auth.headers,
    )
    aid = r.json()["id"]
    client.post(
        f"/api/mysign/agreements/{aid}/signers",
        json={"signers": [{"name": "Rita Returner", "email": signer_email}]},
        headers=auth.headers,
    )
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={"fields": [{"type": "signature", "anchor": "Signature:", "signer": signer_email}]},
        headers=auth.headers,
    )
    token = client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers).json()[
        "links"
    ][0]["token"]
    payload = client.get(f"/api/sign/token/{token}").json()
    fid = payload["fields"][0]["id"]
    client.post(
        f"/api/sign/token/{token}/submit",
        json={"values": {str(fid): make_png_data_url()}, "consent": True},
    )
    from sign import esign

    agr = esign.get_agreement(aid)
    signer_id = agr["signers"][0]["id"]
    return aid, agr["envelope_id"], signer_id


def _otp_login(client, env_id, hint):
    """Drive OTP identity: capture the console-printed code, verify, return the env cookie."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        start = client.post(
            f"/api/envelope/{env_id}/auth/start", json={"method": "otp", "signer_hint": hint}
        )
    assert start.json()["ok"] is True
    code = OTP_RE.search(buf.getvalue())
    assert code, "an OTP code must print to the console in SMTP-off mode"
    ver = client.post(
        f"/api/envelope/{env_id}/auth/otp-verify", json={"signer_hint": hint, "code": code.group(1)}
    )
    assert ver.json()["ok"] is True, ver.text
    cookie = _env_cookie(ver)
    assert cookie
    return {"cookie": f"__Host-ls_env={cookie}"}


def test_envelope_otp_flow_data_inbox_download(client, account_factory):
    auth = account_factory()
    email = "returner@example.com"
    aid, env_id, _sid = _complete_envelope(client, auth, email)
    hdr = _otp_login(client, env_id, email)

    data = client.get(f"/api/envelope/{env_id}", headers=hdr).json()
    assert data["ok"] is True
    assert data["envelope"]["status"] == "completed"
    assert data["me"]["email_masked"].endswith("@example.com")
    assert data["download"]["available"] is True

    inbox = client.get(f"/api/envelope/{env_id}/inbox", headers=hdr).json()
    assert inbox["ok"] is True and inbox["count"] >= 1
    assert any(e["current"] for e in inbox["envelopes"])

    dl = client.get(f"/api/envelope/{env_id}/download", headers=hdr)
    assert dl.status_code == 200 and dl.content[:5] == b"%PDF-"
    cert = client.get(f"/api/envelope/{env_id}/certificate", headers=hdr)
    assert cert.status_code == 200 and cert.content[:5] == b"%PDF-"


def test_envelope_requires_auth(client, account_factory):
    auth = account_factory()
    _aid, env_id, _sid = _complete_envelope(client, auth, "noauth@example.com")
    r = client.get(f"/api/envelope/{env_id}")
    assert r.status_code == 401
    assert r.json()["need_auth"] is True
    # download without a session is 401 too
    assert client.get(f"/api/envelope/{env_id}/download").status_code == 401


def test_envelope_access_challenge_gate(client, account_factory):
    """A sender access-lock (code challenge) withholds the envelope until the correct value is
    supplied; a wrong value is rejected, the right value unlocks download."""
    from sign import esign, esign_access

    auth = account_factory()
    email = "gated@example.com"
    aid, env_id, sid = _complete_envelope(client, auth, email)
    salt, wrapped, iters = esign_access.hash_challenge("Rosebud42", "code")
    assert esign.set_signer_challenge(aid, sid, "code", "Passphrase?", salt, wrapped, iters)

    hdr = _otp_login(client, env_id, email)
    gated = client.get(f"/api/envelope/{env_id}", headers=hdr).json()
    assert gated["ok"] is False and gated["challenge_required"] is True
    # download blocked while challenge unmet
    assert client.get(f"/api/envelope/{env_id}/download", headers=hdr).status_code == 401

    wrong = client.post(f"/api/envelope/{env_id}/challenge", json={"value": "wrong"}, headers=hdr)
    assert wrong.json()["ok"] is False

    ok = client.post(
        f"/api/envelope/{env_id}/challenge", json={"value": "rosebud42"}, headers=hdr
    )  # normalized casefold
    assert ok.json()["ok"] is True
    hdr2 = {"cookie": f"__Host-ls_env={_env_cookie(ok)}"}
    data = client.get(f"/api/envelope/{env_id}", headers=hdr2).json()
    assert data["ok"] is True
    assert client.get(f"/api/envelope/{env_id}/download", headers=hdr2).status_code == 200


def test_envelope_google_start_and_bad_state_callback(client, account_factory):
    auth = account_factory()
    _aid, env_id, _sid = _complete_envelope(client, auth, "g@example.com")
    # Google unconfigured → redirect URL is empty but the route still returns ok w/ redirect key
    start = client.post(f"/api/envelope/{env_id}/auth/start", json={"method": "google"})
    assert start.json()["ok"] is True
    # callback with a bogus state renders the friendly error page (200 HTML), never a 500
    cb = client.get("/api/envelope/auth/callback?code=x&state=forged", follow_redirects=False)
    assert cb.status_code == 200
    assert "Lifted Sign" in cb.text


def test_envelope_page_shell_served(client):
    r = client.get("/envelope/LS-ANYTHING")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]


def test_envelope_unsupported_auth_method(client, account_factory):
    auth = account_factory()
    _aid, env_id, _sid = _complete_envelope(client, auth, "u@example.com")
    r = client.post(f"/api/envelope/{env_id}/auth/start", json={"method": "carrier-pigeon"})
    assert r.json() == {"ok": False, "error": "unsupported method"}


# --- esign_access unit surface ---------------------------------------------
def test_challenge_hash_and_verify_roundtrip(client, account_factory):
    from sign import esign, esign_access

    auth = account_factory()
    aid, _env, sid = _complete_envelope(client, auth, "chal@example.com")
    salt, wrapped, iters = esign_access.hash_challenge("2001-05-09", "dob")
    esign.set_signer_challenge(aid, sid, "dob", "DOB?", salt, wrapped, iters)
    env_id = esign.get_agreement(aid)["envelope_id"]
    # correct (accepts MM/DD/YYYY normalization to the stored ISO date)
    assert esign_access.verify_challenge(env_id, sid, "05/09/2001", "9.9.9.9")["ok"] is True


def test_challenge_wrong_value_then_lockout(client, account_factory):
    from sign import esign, esign_access

    auth = account_factory()
    aid, _env, sid = _complete_envelope(client, auth, "lock@example.com")
    salt, wrapped, iters = esign_access.hash_challenge("secret-code", "code")
    esign.set_signer_challenge(aid, sid, "code", "?", salt, wrapped, iters)
    env_id = esign.get_agreement(aid)["envelope_id"]
    ip = "5.5.5.5"
    last = None
    for _ in range(6):
        last = esign_access.verify_challenge(env_id, sid, "nope", ip)
    # after 5 wrong tries the per-IP lock engages
    assert last.get("locked") is True and last.get("retry_after") == 900


def test_normalize_and_iso_date():
    from sign import esign_access

    assert esign_access.normalize_challenge("  Hello World  ", "text") == "hello world"
    assert esign_access.normalize_challenge("123-45-6789", "ssn") == "123456789"
    assert esign_access._to_iso_date("12/31/1999") == "1999-12-31"
    assert esign_access._to_iso_date("2001-05-09") == "2001-05-09"
    assert esign_access.mask_email("someone@example.com") == "s••••@example.com"


def test_env_session_mint_read_require(client, account_factory):
    from sign import esign, esign_access

    auth = account_factory()
    aid, env_id, sid = _complete_envelope(client, auth, "sess@example.com")
    epoch = int(esign.get_agreement(aid).get("env_session_epoch", 0) or 0)
    tok = esign_access.mint_env_session(env_id, sid, "sess@example.com", "otp:email", True, epoch)
    d = esign_access.read_env_session(tok)
    assert d and d["env_id"] == env_id and d["chal_ok"] is True
    # require_env_session authorizes for the matching path, denies a path mismatch
    guard = esign_access.require_env_session(env_id, tok)
    assert guard is not None and len(guard) == 3
    assert esign_access.require_env_session("LS-OTHER", tok) is None
    assert esign_access.require_env_session(env_id, None) is None


def test_match_google_signer(client, account_factory):
    from sign import esign_access

    auth = account_factory()
    aid, env_id, _sid = _complete_envelope(client, auth, "Match@Example.com")
    assert esign_access.match_google_signer(env_id, "match@example.com") is not None
    assert esign_access.match_google_signer(env_id, "stranger@example.com") is None
