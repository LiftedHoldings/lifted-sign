"""Seal a document carrying every field type — exercises the stamping + font-embedding engine.

The golden flow stamps a single signature; this one fills a signature, initials, date, text, name,
and checkbox so ``pdf_stamp`` (image + text + checkbox paths) and ``fontmap`` (font metrics /
embedding) are driven broadly, then confirms the multi-field sealed PDF still validates + certifies.
"""

from __future__ import annotations

from conftest import make_png_data_url, make_pdf


def test_all_field_types_stamp_and_seal(client, account_factory):
    from sign import esign, pdf_sign

    auth = account_factory()
    aid = esign.create_agreement(
        "Multi Field", make_pdf(), owner_account_id=auth.id, created_by=auth.email
    )
    signers = esign.set_signers(aid, [{"name": "Multi Signer", "email": "multi@example.com"}])
    sid = signers[0]["id"]
    fields = [
        {
            "type": "signature",
            "signer_id": sid,
            "page": 0,
            "x": 0.2,
            "y": 0.30,
            "w": 0.3,
            "h": 0.06,
        },
        {"type": "initials", "signer_id": sid, "page": 0, "x": 0.6, "y": 0.30, "w": 0.1, "h": 0.06},
        {"type": "date", "signer_id": sid, "page": 0, "x": 0.2, "y": 0.42, "w": 0.2, "h": 0.03},
        {"type": "text", "signer_id": sid, "page": 0, "x": 0.2, "y": 0.50, "w": 0.3, "h": 0.03},
        {"type": "name", "signer_id": sid, "page": 0, "x": 0.2, "y": 0.58, "w": 0.3, "h": 0.03},
        {
            "type": "checkbox",
            "signer_id": sid,
            "page": 0,
            "x": 0.2,
            "y": 0.66,
            "w": 0.03,
            "h": 0.03,
        },
    ]
    assert esign.set_fields(aid, fields) == 6

    send = esign.send(aid, base_url="http://localhost")
    assert send["ok"] is True
    token = send["links"][0]["token"]
    esign.signing_payload(token, ip="1.1.1.1", ua="pytest")
    agr = esign.get_agreement(aid, full=True)
    ids = {f["type"]: f["id"] for f in agr["fields"]}
    values = {
        str(ids["signature"]): make_png_data_url(),
        str(ids["initials"]): make_png_data_url(),
        str(ids["date"]): "2026-07-17",
        str(ids["text"]): "Free-text answer",
        str(ids["name"]): "Multi Signer",
        str(ids["checkbox"]): "true",
    }
    res = esign.submit_signature(token, values, consent=True, ip="1.1.1.1", ua="pytest")
    assert res == {"ok": True, "completed": True}, res

    sealed = esign.executed_bytes(aid)
    v = pdf_sign.validate(sealed)
    assert v["valid"] and v["certified"] and not v["tampered"]
