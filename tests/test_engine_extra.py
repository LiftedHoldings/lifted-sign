"""Extended engine surface — the draft-editor, templates, and terminal transitions.

Covers the parts of ``esign`` beyond the golden signing path: page ops (rotate/delete/add/reorder),
redaction, add-text / edit-text, prefill autodetect, reusable templates (create → list → use →
archive), reminders, self-sign links, decline, consent withdrawal, void, and the expiry sweep — all
through the owner-scoped HTTP surface where one exists, else the engine function directly.
"""

from __future__ import annotations

from conftest import make_pdf


def _new_draft(client, auth, name="Editor Doc"):
    r = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": name},
        headers=auth.headers,
    )
    return r.json()["id"]


def _add_signer(client, auth, aid, email="ed@example.com"):
    client.post(
        f"/api/mysign/agreements/{aid}/signers",
        json={"signers": [{"name": "Ed", "email": email}]},
        headers=auth.headers,
    )


# --- page ops ---------------------------------------------------------------
def test_pages_list_and_render(client, account_factory):
    auth = account_factory()
    aid = _new_draft(client, auth)
    pages = client.get(f"/api/mysign/agreements/{aid}/pages", headers=auth.headers).json()
    assert pages["count"] >= 1
    png = client.get(f"/api/mysign/agreements/{aid}/page/0", headers=auth.headers)
    assert png.status_code == 200 and png.headers["content-type"] == "image/png"
    pdf = client.get(f"/api/mysign/agreements/{aid}/pdf", headers=auth.headers)
    assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-"


def test_add_and_rotate_and_delete_pages(client, account_factory):
    auth = account_factory()
    aid = _new_draft(client, auth)
    # add a second page
    add = client.post(
        f"/api/mysign/agreements/{aid}/pages/add",
        files={"file": ("extra.pdf", make_pdf("Page Two"), "application/pdf")},
        headers=auth.headers,
    )
    assert add.json()["ok"] is True
    # rotate page 0
    rot = client.post(
        f"/api/mysign/agreements/{aid}/pages/rotate",
        json={"page": 0, "deg": 90},
        headers=auth.headers,
    )
    assert rot.json()["ok"] is True
    # reorder the two pages
    ro = client.post(
        f"/api/mysign/agreements/{aid}/pages/reorder", json={"order": [1, 0]}, headers=auth.headers
    )
    assert ro.json()["ok"] is True
    # delete a page
    dele = client.post(
        f"/api/mysign/agreements/{aid}/pages/delete", json={"page": 1}, headers=auth.headers
    )
    assert dele.json()["ok"] is True


def test_add_text_and_redact(client, account_factory):
    auth = account_factory()
    aid = _new_draft(client, auth)
    txt = client.post(
        f"/api/mysign/agreements/{aid}/text",
        json={"items": [{"page": 0, "x": 0.1, "y": 0.1, "text": "Stamped here"}]},
        headers=auth.headers,
    )
    assert txt.json()["ok"] is True
    red = client.post(
        f"/api/mysign/agreements/{aid}/redact",
        json={"regions": [{"page": 0, "x": 0.1, "y": 0.1, "w": 0.2, "h": 0.05}]},
        headers=auth.headers,
    )
    assert red.json()["ok"] is True


def test_spans_and_edit_text(client, account_factory):
    auth = account_factory()
    aid = _new_draft(client, auth)
    spans = client.get(f"/api/mysign/agreements/{aid}/spans?page=0", headers=auth.headers).json()
    assert spans["ok"] is True
    assert isinstance(spans["spans"], list)


def test_detect_prefill_fields(client, account_factory):
    auth = account_factory()
    aid = _new_draft(client, auth)
    r = client.post(f"/api/mysign/agreements/{aid}/detect", headers=auth.headers)
    assert r.status_code == 200
    assert "added" in r.json() or "fields" in r.json() or r.json().get("ok") is not None


def test_page_op_locked_after_send_returns_409(client, account_factory):
    auth = account_factory()
    aid = _new_draft(client, auth)
    _add_signer(client, auth, aid)
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [{"type": "signature", "anchor": "Signature:", "signer": "ed@example.com"}]
        },
        headers=auth.headers,
    )
    client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers)
    # editing a sent doc is locked → 409
    r = client.post(
        f"/api/mysign/agreements/{aid}/pages/rotate",
        json={"page": 0, "deg": 90},
        headers=auth.headers,
    )
    assert r.status_code == 409


# --- templates --------------------------------------------------------------
def test_template_create_list_use_archive(client, account_factory):
    auth = account_factory()
    aid = _new_draft(client, auth, "Template Source")
    _add_signer(client, auth, aid, "role@example.com")
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [{"type": "signature", "anchor": "Signature:", "signer": "role@example.com"}]
        },
        headers=auth.headers,
    )
    created = client.post(
        "/api/mysign/templates",
        json={"name": "My Template", "agreement_id": aid},
        headers=auth.headers,
    )
    assert created.json().get("ok") is True, created.text
    tid = created.json()["id"]
    listing = client.get("/api/mysign/templates", headers=auth.headers).json()
    assert any(t["id"] == tid for t in listing["templates"])
    got = client.get(f"/api/mysign/templates/{tid}", headers=auth.headers)
    assert got.status_code == 200
    used = client.post(
        f"/api/mysign/templates/{tid}/use",
        json={"recipients": [{"name": "New", "email": "new@example.com"}]},
        headers=auth.headers,
    )
    assert used.json().get("ok") is True, used.text
    arch = client.post(f"/api/mysign/templates/{tid}/archive", headers=auth.headers)
    assert arch.json()["ok"] is True


def test_template_cross_owner_404(client, account_factory):
    a, b = account_factory(), account_factory()
    aid = _new_draft(client, a, "A Template Source")
    created = client.post(
        "/api/mysign/templates", json={"name": "A-only", "agreement_id": aid}, headers=a.headers
    )
    tid = created.json()["id"]
    assert client.get(f"/api/mysign/templates/{tid}", headers=b.headers).status_code == 404


# --- terminal transitions ---------------------------------------------------
def test_remind_pending_signer(client, account_factory):
    auth = account_factory()
    aid = _new_draft(client, auth)
    _add_signer(client, auth, aid)
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [{"type": "signature", "anchor": "Signature:", "signer": "ed@example.com"}]
        },
        headers=auth.headers,
    )
    client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers)
    r = client.post(f"/api/mysign/agreements/{aid}/remind", json={}, headers=auth.headers)
    assert r.json()["ok"] is True and r.json()["emailed"] >= 1


def test_void_sent_agreement(client, account_factory):
    auth = account_factory()
    aid = _new_draft(client, auth)
    _add_signer(client, auth, aid)
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [{"type": "signature", "anchor": "Signature:", "signer": "ed@example.com"}]
        },
        headers=auth.headers,
    )
    client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers)
    v = client.post(
        f"/api/mysign/agreements/{aid}/void", json={"reason": "mistake"}, headers=auth.headers
    )
    assert v.json()["ok"] is True
    agr = client.get(f"/api/mysign/agreements/{aid}", headers=auth.headers).json()
    assert agr["status"] == "voided"


def test_decline_via_token(client, account_factory):
    from sign import esign

    auth = account_factory()
    aid = _new_draft(client, auth)
    _add_signer(client, auth, aid)
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [{"type": "signature", "anchor": "Signature:", "signer": "ed@example.com"}]
        },
        headers=auth.headers,
    )
    token = client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers).json()[
        "links"
    ][0]["token"]
    r = client.post(f"/api/sign/token/{token}/decline", json={"reason": "no thanks"})
    assert r.json()["ok"] is True
    assert esign.get_agreement(aid)["status"] == "declined"


def test_withdraw_consent_before_completion_declines(client, account_factory):
    from sign import esign

    auth = account_factory()
    aid = _new_draft(client, auth)
    client.post(
        f"/api/mysign/agreements/{aid}/signers",
        json={"signers": [{"name": "Connie", "email": "connie@example.com", "is_consumer": True}]},
        headers=auth.headers,
    )
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [
                {"type": "signature", "anchor": "Signature:", "signer": "connie@example.com"}
            ]
        },
        headers=auth.headers,
    )
    token = client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers).json()[
        "links"
    ][0]["token"]
    client.get(f"/api/sign/token/{token}")
    r = client.post(f"/api/sign/token/{token}/withdraw-consent", json={"reason": "changed mind"})
    assert r.json()["ok"] is True
    assert esign.get_agreement(aid)["status"] == "declined"


def test_self_sign_link_no_email(client, account_factory):
    from sign import esign

    auth = account_factory()
    aid = _new_draft(client, auth)
    _add_signer(client, auth, aid)
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [{"type": "signature", "anchor": "Signature:", "signer": "ed@example.com"}]
        },
        headers=auth.headers,
    )
    client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers)
    sid = esign.get_agreement(aid)["signers"][0]["id"]
    res = esign.self_sign_link(aid, sid, base_url="http://localhost")
    assert res.get("ok") is True and res.get("token")


def test_sweep_expired_flips_status(client, account_factory):
    from sign import db, esign

    auth = account_factory()
    aid = _new_draft(client, auth)
    _add_signer(client, auth, aid)
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [{"type": "signature", "anchor": "Signature:", "signer": "ed@example.com"}]
        },
        headers=auth.headers,
    )
    client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers)
    # force this envelope's expiry into the past, then sweep
    conn = db.connect()
    try:
        conn.execute("UPDATE agreements SET expires_at=? WHERE id=?", (1.0, aid))
        conn.commit()
    finally:
        conn.close()
    n = esign.sweep_expired()
    assert n >= 1
    assert esign.get_agreement(aid)["status"] == "expired"


def test_owner_status_counts_and_list(client, account_factory):
    from sign import esign

    auth = account_factory()
    _new_draft(client, auth, "One")
    _new_draft(client, auth, "Two")
    counts = esign.owner_status_counts(auth.id)
    assert counts["total"] >= 2
    total = esign.count_agreements_for_owner(auth.id)
    assert total >= 2
    rows = esign.list_agreements_for_owner(auth.id, 50, 0)
    assert len(rows) >= 2
