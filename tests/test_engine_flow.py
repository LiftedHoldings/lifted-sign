"""End-to-end signing-engine lifecycle over the real HTTP surface.

Drives the whole product path a sender + signer actually walk — create an agreement, add a
signer, place a signature field by anchor text, send it, render the signer payload, submit a real
PNG signature, and finalize — then proves the sealed artifact:

  * status flips to ``completed`` and the sealed PDF is a genuine, growing document,
  * ``pdf_sign.validate`` reports it ``valid + certified + not-tampered`` (the auto-provisioned
    self-signed PAdES certification signature),
  * mutating one sealed byte is DETECTED as tampering (``tampered=True``, ``valid=False``),
  * the Certificate of Completion is retrievable and the audit trail is complete.
"""

from __future__ import annotations

from conftest import make_pdf, make_png_data_url


def _create(client, auth, name="Golden Doc"):
    r = client.post(
        "/api/mysign/agreements",
        files={"file": ("doc.pdf", make_pdf(), "application/pdf")},
        data={"name": name},
        headers=auth.headers,
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _drive_to_completed(client, auth, consumer=False):
    """create → signer → anchor field → send → view → submit → completed. Returns (aid, token)."""
    aid = _create(client, auth)
    rs = client.post(
        f"/api/mysign/agreements/{aid}/signers",
        json={
            "signers": [{"name": "Sam Signer", "email": "sam@example.com", "is_consumer": consumer}]
        },
        headers=auth.headers,
    )
    assert rs.status_code == 200, rs.text
    rf = client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [{"type": "signature", "anchor": "Signature:", "signer": "sam@example.com"}]
        },
        headers=auth.headers,
    )
    assert rf.json().get("ok") is True, rf.text
    rsend = client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers)
    assert rsend.status_code == 200 and rsend.json().get("ok"), rsend.text
    token = rsend.json()["links"][0]["token"]

    payload = client.get(f"/api/sign/token/{token}").json()
    assert payload["ok"] is True, payload
    fid = payload["fields"][0]["id"]

    # A consumer signer must record ESIGN consent before signing (server-side gate).
    if consumer:
        rc = client.post(
            f"/api/sign/token/{token}/consent",
            json={
                "agreed": True,
                "disclosure_version": payload["disclosure"]["version"],
                "disclosure_text_hash": payload["disclosure"]["text_hash"],
                "access_demonstrated": True,
                "access_method": "viewed",
            },
        )
        assert rc.json().get("ok") is True, rc.text

    rsub = client.post(
        f"/api/sign/token/{token}/submit",
        json={
            "values": {str(fid): make_png_data_url()},
            "consent": True,
            "field_meta": {str(fid): {"method": "draw", "adopted_at": 1}},
        },
    )
    assert rsub.json() == {"ok": True, "completed": True}, rsub.text
    return aid, token


def test_full_lifecycle_seals_valid_certified_pdf(client, account_factory):
    from sign import pdf_sign

    auth = account_factory()
    aid, token = _drive_to_completed(client, auth)

    agr = client.get(f"/api/mysign/agreements/{aid}", headers=auth.headers).json()
    assert agr["status"] == "completed"
    assert agr["seal_method"] == "pades"
    assert agr["sealed_hash"] and agr["preseal_hash"]

    dl = client.get(f"/api/mysign/agreements/{aid}/download", headers=auth.headers)
    assert dl.status_code == 200
    assert dl.headers["content-type"] == "application/pdf"
    sealed = dl.content
    assert sealed[:5] == b"%PDF-"
    # sealed doc carries the stamped signature + appended certificate → materially bigger source
    assert len(sealed) > len(make_pdf())

    v = pdf_sign.validate(sealed)
    assert v["valid"] is True, v
    assert v["certified"] is True, v
    assert v["tampered"] is False, v
    assert v["docmdp_ok"] is True, v


def test_tamper_of_sealed_bytes_is_detected(client, account_factory):
    from sign import esign, pdf_sign

    auth = account_factory()
    aid, _ = _drive_to_completed(client, auth)
    sealed = esign.executed_bytes(aid)
    assert sealed

    mutated = bytearray(sealed)
    mutated[len(mutated) // 2] ^= 0xFF  # flip a byte inside the covered range
    v = pdf_sign.validate(bytes(mutated))
    assert v["tampered"] is True, v
    assert v["valid"] is False, v

    # A truncated / non-PDF "signed" file is a detected tamper, not a crash.
    junk = pdf_sign.validate(b"not a pdf at all")
    assert junk["valid"] is False and junk["tampered"] is True


def test_certificate_of_completion_downloadable(client, account_factory):
    auth = account_factory()
    aid, _ = _drive_to_completed(client, auth)
    cert = client.get(f"/api/mysign/agreements/{aid}/certificate", headers=auth.headers)
    assert cert.status_code == 200
    assert cert.content[:5] == b"%PDF-"


def test_consumer_flow_embeds_consumer_disclosure(client, account_factory):
    """A consumer signer walks the consent gate; the sealed doc still validates + certifies."""
    from sign import pdf_sign

    auth = account_factory()
    aid, _ = _drive_to_completed(client, auth, consumer=True)
    v = pdf_sign.validate(
        client.get(f"/api/mysign/agreements/{aid}/download", headers=auth.headers).content
    )
    assert v["valid"] and v["certified"] and not v["tampered"]


def test_audit_trail_records_every_stage(client, account_factory):
    from sign import esign

    auth = account_factory()
    aid, _ = _drive_to_completed(client, auth)
    agr = esign.get_agreement(aid, full=True)
    types = {e["type"] for e in agr["events"]}
    for expected in ("created", "sent", "DOC_FROZEN", "signed", "DOC_SEALED", "completed"):
        assert expected in types, (expected, sorted(types))


def test_required_field_gate_blocks_blank_signature(client, account_factory):
    """A raw POST that omits the required signature must NOT mark the signer signed."""
    auth = account_factory()
    aid = _create(client, auth)
    client.post(
        f"/api/mysign/agreements/{aid}/signers",
        json={"signers": [{"name": "Sam", "email": "sam@example.com"}]},
        headers=auth.headers,
    )
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [{"type": "signature", "anchor": "Signature:", "signer": "sam@example.com"}]
        },
        headers=auth.headers,
    )
    token = client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers).json()[
        "links"
    ][0]["token"]
    client.get(f"/api/sign/token/{token}")
    # empty values → required-field gate rejects, agreement stays out_for_signature
    r = client.post(f"/api/sign/token/{token}/submit", json={"values": {}, "consent": True})
    assert r.json()["ok"] is False
    agr = client.get(f"/api/mysign/agreements/{aid}", headers=auth.headers).json()
    assert agr["status"] == "out_for_signature"


def test_submit_requires_consent(client, account_factory):
    auth = account_factory()
    aid = _create(client, auth)
    client.post(
        f"/api/mysign/agreements/{aid}/signers",
        json={"signers": [{"name": "Sam", "email": "sam@example.com"}]},
        headers=auth.headers,
    )
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [{"type": "signature", "anchor": "Signature:", "signer": "sam@example.com"}]
        },
        headers=auth.headers,
    )
    token = client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers).json()[
        "links"
    ][0]["token"]
    r = client.post(f"/api/sign/token/{token}/submit", json={"values": {}, "consent": False})
    assert r.json() == {"ok": False, "error": "consent required"}
