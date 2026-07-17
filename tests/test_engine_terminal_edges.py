"""Signing-engine terminal-state edges — the guards that keep a legal envelope consistent under
re-POSTs, out-of-band voids/expiry, and stranded finalizes.

The golden path and the basic void/decline/expire transitions are covered in ``test_engine_flow`` /
``test_engine_extra`` / ``test_sequential_and_placement``. These pin the harder invariants:

  * a re-POST by an already-signed signer is idempotent (``already: True``) and never double-signs,
  * a finalize that failed transiently (all signers signed, envelope un-sealed) self-heals on the
    next idempotent re-POST rather than stranding the document forever,
  * malformed ``values`` from an untrusted signer browser yield a clean rejection, not a 500,
  * signing / declining / consenting are refused once the envelope is voided, expired, or complete,
  * ``sweep_expired`` only touches ``out_for_signature`` rows and is idempotent.
"""

from __future__ import annotations

import pytest
from conftest import make_pdf, make_png_data_url

from sign import db, esign


def _ready(auth, signer_specs, order_mode="parallel"):
    """Build → place required signature fields → send. Returns (aid, signers, email→token)."""
    aid = esign.create_agreement(
        "Edge", make_pdf(), owner_account_id=auth.id, created_by=auth.email
    )
    signers = esign.set_signers(aid, signer_specs)
    esign.set_fields(
        aid,
        [
            {
                "type": "signature",
                "signer_id": s["id"],
                "page": 0,
                "x": 0.2,
                "y": 0.3 + 0.12 * i,
                "w": 0.3,
                "h": 0.06,
            }
            for i, s in enumerate(signers)
        ],
    )
    if order_mode == "sequential":
        esign.set_order_mode_owned(aid, auth.id, "sequential")
    send = esign.send(aid, base_url="http://localhost")
    assert send["ok"] is True, send
    tokens = {link["email"]: link["token"] for link in send["links"]}
    return aid, signers, tokens


def _fid_for(aid, signer_id):
    agr = esign.get_agreement(aid, full=True)
    return next(f["id"] for f in agr["fields"] if f["signer_id"] == signer_id)


def _sign(aid, signer, token, consent=True):
    fid = _fid_for(aid, signer["id"])
    return esign.submit_signature(
        token, {str(fid): make_png_data_url()}, consent=consent, ip="9.9.9.9", ua="pytest"
    )


def test_resubmit_after_completion_is_idempotent(client, account_factory):
    auth = account_factory()
    aid, signers, toks = _ready(auth, [{"name": "Sam", "email": "sam@example.com"}])
    tok = toks["sam@example.com"]
    assert _sign(aid, signers[0], tok) == {"ok": True, "completed": True}
    # A re-POST of the same token does not re-sign or reseal — it reports the prior signature.
    again = _sign(aid, signers[0], tok)
    assert again["ok"] is True and again.get("already") is True and again["completed"] is False
    assert esign.get_agreement(aid)["status"] == "completed"


def test_finalize_retry_redrives_stranded_envelope(client, account_factory, monkeypatch):
    """If finalize() dies after the last signer is durably marked signed, the envelope is left
    all-signed-but-unsealed. The next idempotent re-POST must re-drive finalize and complete it."""
    auth = account_factory()
    aid, signers, toks = _ready(auth, [{"name": "Sam", "email": "sam@example.com"}])
    tok = toks["sam@example.com"]

    real_finalize = esign.finalize
    state = {"first": True}

    def flaky(agreement_id):
        if state["first"]:
            state["first"] = False
            raise RuntimeError("transient seal failure")
        return real_finalize(agreement_id)

    monkeypatch.setattr(esign, "finalize", flaky)
    with pytest.raises(RuntimeError):
        _sign(aid, signers[0], tok)  # signer committed 'signed', finalize blew up → stranded
    stranded = esign.get_agreement(aid)
    assert stranded["status"] != "completed"
    assert stranded["signers"][0]["status"] == "signed"

    monkeypatch.setattr(esign, "finalize", real_finalize)
    healed = _sign(aid, signers[0], tok)  # idempotent re-POST self-heals the seal
    assert healed["ok"] is True and healed["completed"] is True
    assert esign.get_agreement(aid)["status"] == "completed"


def test_submit_malformed_values_rejected_cleanly(client, account_factory):
    auth = account_factory()
    aid, signers, toks = _ready(auth, [{"name": "Sam", "email": "sam@example.com"}])
    tok = toks["sam@example.com"]
    fid = _fid_for(aid, signers[0]["id"])
    good = make_png_data_url()

    # Non-integer field-id key → clean rejection, signer NOT marked signed (no int()/bind crash).
    r1 = esign.submit_signature(
        tok, {str(fid): good, "not-an-int": "x"}, consent=True, ip="1.1.1.1", ua="pytest"
    )
    assert r1 == {"ok": False, "error": "malformed submission"}
    # Non-string value → same clean rejection.
    r2 = esign.submit_signature(
        tok, {str(fid): good, "77": 123}, consent=True, ip="1.1.1.1", ua="pytest"
    )
    assert r2 == {"ok": False, "error": "malformed submission"}
    # The envelope is untouched — still out for signature, signer still unsigned.
    agr = esign.get_agreement(aid)
    assert agr["status"] == "out_for_signature"
    assert agr["signers"][0]["status"] != "signed"


def test_submit_on_voided_envelope_refused(client, account_factory):
    auth = account_factory()
    aid, signers, toks = _ready(auth, [{"name": "Sam", "email": "sam@example.com"}])
    esign.void(aid, reason="mistake")
    r = _sign(aid, signers[0], toks["sam@example.com"])
    assert r["ok"] is False and "no longer available" in r["error"]
    assert esign.get_agreement(aid)["status"] == "voided"


def test_submit_on_expired_envelope_refused(client, account_factory):
    auth = account_factory()
    aid, signers, toks = _ready(auth, [{"name": "Sam", "email": "sam@example.com"}])
    conn = db.connect()
    try:
        conn.execute("UPDATE agreements SET expires_at=? WHERE id=?", (1.0, aid))
        conn.commit()
    finally:
        conn.close()
    assert esign.sweep_expired() >= 1
    r = _sign(aid, signers[0], toks["sam@example.com"])
    assert r["ok"] is False and "expired" in r["error"].lower()


def test_decline_after_signed_refused(client, account_factory):
    auth = account_factory()
    aid, signers, toks = _ready(auth, [{"name": "Sam", "email": "sam@example.com"}])
    tok = toks["sam@example.com"]
    assert _sign(aid, signers[0], tok)["completed"] is True
    # A signer who already signed cannot retroactively decline a completed envelope.
    assert esign.decline(tok, reason="regret") == {"ok": False, "error": "already signed"}


def test_decline_on_voided_document_refused(client, account_factory):
    auth = account_factory()
    aid, signers, toks = _ready(
        auth,
        [
            {"name": "A", "email": "a@example.com"},
            {"name": "B", "email": "b@example.com"},
        ],
    )
    esign.void(aid, reason="withdrawn")
    # An UNSIGNED signer on a voided doc hits the agreement-status guard (not the signed guard).
    r = esign.decline(toks["a@example.com"], reason="no")
    assert r["ok"] is False and "voided" in r["error"]


def test_void_midflow_blocks_remaining_signer(client, account_factory):
    auth = account_factory()
    aid, signers, toks = _ready(
        auth,
        [
            {"name": "A", "email": "a@example.com"},
            {"name": "B", "email": "b@example.com"},
        ],
    )
    first = _sign(aid, signers[0], toks["a@example.com"])
    assert first["ok"] is True and first["completed"] is False  # one signer still outstanding
    esign.void(aid, reason="changed plans")
    second = _sign(aid, signers[1], toks["b@example.com"])
    assert second["ok"] is False and "no longer available" in second["error"]
    assert esign.get_agreement(aid)["status"] == "voided"


def test_record_consent_idempotent_then_refused_when_voided(client, account_factory):
    auth = account_factory()
    aid, signers, toks = _ready(
        auth, [{"name": "Connie", "email": "connie@example.com", "is_consumer": True}]
    )
    tok = toks["connie@example.com"]
    first = esign.record_consent(tok, {"agreed": True, "access_demonstrated": True})
    assert first["ok"] is True and "consent_at" in first
    second = esign.record_consent(tok, {"agreed": True})
    assert second["ok"] is True and second.get("already") is True
    assert second["consent_at"] == first["consent_at"]  # not re-written

    # A fresh consumer envelope, voided before consent, refuses consent capture.
    aid2, s2, toks2 = _ready(
        auth, [{"name": "Dana", "email": "dana@example.com", "is_consumer": True}]
    )
    esign.void(aid2, reason="pulled")
    r = esign.record_consent(toks2["dana@example.com"], {"agreed": True})
    assert r["ok"] is False and "voided" in r["error"]


def test_sweep_expired_idempotent_and_scoped(client, account_factory):
    auth = account_factory()
    aid, signers, toks = _ready(auth, [{"name": "Sam", "email": "sam@example.com"}])
    conn = db.connect()
    try:
        conn.execute("UPDATE agreements SET expires_at=? WHERE id=?", (1.0, aid))
        conn.commit()
    finally:
        conn.close()
    now = 1000.0
    assert esign.sweep_expired(now=now) >= 1
    assert esign.get_agreement(aid)["status"] == "expired"
    # Re-running the sweep does not re-expire an already-expired row (status guard) — this one
    # contributes 0 to the count and its status is unchanged.
    before = esign.get_agreement(aid)["status"]
    esign.sweep_expired(now=now)
    assert esign.get_agreement(aid)["status"] == before == "expired"


def test_self_sign_link_after_signed_refused(client, account_factory):
    auth = account_factory()
    aid, signers, toks = _ready(auth, [{"name": "Sam", "email": "sam@example.com"}])
    assert _sign(aid, signers[0], toks["sam@example.com"])["completed"] is True
    res = esign.self_sign_link(aid, signers[0]["id"], base_url="http://localhost")
    assert res == {"ok": False, "error": "already signed"}
