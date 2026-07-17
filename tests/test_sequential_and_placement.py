"""Sequential signing, token download, field-placement variants, templates-from-layout, edits.

Covers the multi-signer sequential cascade (only the current order-group is notified; the next is
emailed as each completes), the signer-facing token download, the point/normalized branches of
``place_fields``, template creation from an explicit layout, and ``apply_edits``.
"""

from __future__ import annotations

from conftest import make_pdf, make_png_data_url


def test_sequential_two_signer_cascade(client, account_factory):
    from sign import esign

    auth = account_factory()
    aid = esign.create_agreement(
        "Sequential", make_pdf(), owner_account_id=auth.id, created_by=auth.email
    )
    signers = esign.set_signers(
        aid,
        [
            {"name": "First", "email": "first@example.com", "order": 1},
            {"name": "Second", "email": "second@example.com", "order": 2},
        ],
    )
    for s in signers:
        esign.set_fields(aid, [])  # reset between
    # place a signature field for each signer
    esign.set_fields(
        aid,
        [
            {
                "type": "signature",
                "signer_id": signers[0]["id"],
                "page": 0,
                "x": 0.2,
                "y": 0.3,
                "w": 0.3,
                "h": 0.06,
            },
            {
                "type": "signature",
                "signer_id": signers[1]["id"],
                "page": 0,
                "x": 0.2,
                "y": 0.5,
                "w": 0.3,
                "h": 0.06,
            },
        ],
    )
    esign.set_order_mode_owned(aid, auth.id, "sequential")

    send = esign.send(aid, base_url="http://localhost")
    assert send["ok"] is True
    # sequential: only the first order-group is emailed on send
    assert send["emailed"] == 1
    tok1 = next(link["token"] for link in send["links"] if link["email"] == "first@example.com")
    tok2 = next(link["token"] for link in send["links"] if link["email"] == "second@example.com")

    # second cannot sign before first (order gate)
    esign.signing_payload(tok2, ip="2.2.2.2", ua="pytest")
    agr = esign.get_agreement(aid, full=True)
    f2 = next(f for f in agr["fields"] if f["signer_id"] == signers[1]["id"])
    blocked = esign.submit_signature(
        tok2, {str(f2["id"]): make_png_data_url()}, consent=True, ip="2.2.2.2", ua="pytest"
    )
    assert blocked["ok"] is False  # "not your turn yet"

    # first signs → cascade notifies the second
    esign.signing_payload(tok1, ip="1.1.1.1", ua="pytest")
    f1 = next(f for f in agr["fields"] if f["signer_id"] == signers[0]["id"])
    r1 = esign.submit_signature(
        tok1, {str(f1["id"]): make_png_data_url()}, consent=True, ip="1.1.1.1", ua="pytest"
    )
    assert r1["ok"] is True and r1["completed"] is False  # one signer left

    # now the second can sign → envelope completes
    r2 = esign.submit_signature(
        tok2, {str(f2["id"]): make_png_data_url()}, consent=True, ip="2.2.2.2", ua="pytest"
    )
    assert r2 == {"ok": True, "completed": True}
    assert esign.get_agreement(aid)["status"] == "completed"


def test_signer_token_download_after_completion(client, account_factory):
    auth = account_factory()
    aid = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "TokenDl"},
        headers=auth.headers,
    ).json()["id"]
    client.post(
        f"/api/mysign/agreements/{aid}/signers",
        json={"signers": [{"name": "S", "email": "s@example.com"}]},
        headers=auth.headers,
    )
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={"fields": [{"type": "signature", "anchor": "Signature:", "signer": "s@example.com"}]},
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
    # signer-facing token download now serves the executed PDF
    dl = client.get(f"/api/sign/token/{token}/download")
    assert dl.status_code == 200 and dl.content[:5] == b"%PDF-"


def test_place_fields_points_and_normalized(client, account_factory):
    auth = account_factory()
    aid = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "Placement"},
        headers=auth.headers,
    ).json()["id"]
    client.post(
        f"/api/mysign/agreements/{aid}/signers",
        json={"signers": [{"name": "P", "email": "p@example.com"}]},
        headers=auth.headers,
    )
    # normalized (0..1) placement + an absolute-points placement in one batch
    res = client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [
                {
                    "type": "signature",
                    "signer": "p@example.com",
                    "page": 0,
                    "x": 0.2,
                    "y": 0.3,
                    "w": 0.3,
                    "h": 0.06,
                },
                {
                    "type": "date",
                    "signer": "p@example.com",
                    "page": 0,
                    "x": 120,
                    "y": 400,
                    "w": 110,
                    "h": 26,
                    "unit": "pt",
                },
            ]
        },
        headers=auth.headers,
    )
    assert res.json()["ok"] is True and res.json()["count"] == 2


def test_place_fields_anchor_not_found(client, account_factory):
    auth = account_factory()
    aid = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "NoAnchor"},
        headers=auth.headers,
    ).json()["id"]
    client.post(
        f"/api/mysign/agreements/{aid}/signers",
        json={"signers": [{"name": "P", "email": "p@example.com"}]},
        headers=auth.headers,
    )
    res = client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [
                {"type": "signature", "anchor": "NoSuchAnchorXYZ", "signer": "p@example.com"}
            ]
        },
        headers=auth.headers,
    )
    body = res.json()
    assert body["ok"] is False and body["error"] == "anchor_not_found"


def test_create_template_from_layout(client, account_factory):
    from sign import esign

    auth = account_factory()
    aid = esign.create_agreement("Layout Source", make_pdf(), owner_account_id=auth.id)
    res = esign.create_template(
        name="Layout Template",
        source_agreement_id=aid,
        created_by=auth.email,
        owner_account_id=auth.id,
    )
    assert res.get("ok") is True
    tid = res["id"]
    tpl = esign.get_template_owned(tid, auth.id)
    assert tpl and tpl["name"] == "Layout Template"


def test_apply_edits_on_draft(client, account_factory):
    from sign import esign

    auth = account_factory()
    aid = esign.create_agreement("ApplyEdits", make_pdf(), owner_account_id=auth.id)
    ok = esign.apply_edits(
        aid, [{"kind": "add_text", "page": 0, "x": 0.1, "y": 0.1, "text": "Added"}]
    )
    assert ok is True
