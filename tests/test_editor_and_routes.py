"""Higher-fidelity editor + auth branch coverage.

Drives the in-place edit-text engine (which also triggers the send-time page flatten), the signer
access-lock challenge over the public token routes, draft delete / order-mode / tenant purge, and
the phone-OTP + Google login success branches with their external verifiers monkeypatched (no live
Twilio / Google needed).
"""

from __future__ import annotations

from conftest import make_pdf


# --- in-place edit-text success (+ send-time flatten) -----------------------
def test_edit_text_success_then_send_flattens(client, account_factory):
    from sign import esign

    auth = account_factory()
    aid = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "Editable"},
        headers=auth.headers,
    ).json()["id"]
    spans = client.get(f"/api/mysign/agreements/{aid}/spans?page=0", headers=auth.headers).json()[
        "spans"
    ]
    target = next(s for s in spans if s["text"] == "Test Agreement")
    item = {
        "page": 0,
        "bbox": {"x": target["x"], "y": target["y"], "w": target["w"], "h": target["h"]},
        "text": "Edited Agreement",
    }
    r = client.post(
        f"/api/mysign/agreements/{aid}/edit-text", json={"items": [item]}, headers=auth.headers
    )
    assert r.status_code == 200 and r.json()["ok"] is True, r.text

    # an edited page must be flattened into the frozen snapshot at send time (remanence closure)
    esign.set_signers(aid, [{"name": "S", "email": "s@example.com"}])
    esign.set_fields(
        aid,
        [
            {
                "type": "signature",
                "signer_id": esign.get_agreement(aid)["signers"][0]["id"],
                "page": 0,
                "x": 0.2,
                "y": 0.3,
                "w": 0.3,
                "h": 0.06,
            }
        ],
    )
    sent = esign.send(aid, base_url="http://localhost")
    assert sent["ok"] is True
    agr = esign.get_agreement(aid)
    assert agr.get("frozen_path")  # snapshot written


# --- draft lifecycle helpers -----------------------------------------------
def test_delete_draft_and_order_mode(client, account_factory):
    auth = account_factory()
    aid = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "Draft"},
        headers=auth.headers,
    ).json()["id"]
    om = client.post(
        f"/api/mysign/agreements/{aid}/order-mode",
        json={"mode": "sequential"},
        headers=auth.headers,
    )
    assert om.json().get("ok") is True
    dele = client.request("DELETE", f"/api/mysign/agreements/{aid}", headers=auth.headers)
    assert dele.json()["ok"] is True
    # gone now → 404
    assert client.get(f"/api/mysign/agreements/{aid}", headers=auth.headers).status_code == 404


def test_delete_agreements_for_owner(client, account_factory):
    from sign import esign

    auth = account_factory()
    esign.create_agreement("D1", make_pdf(), owner_account_id=auth.id)
    esign.create_agreement("D2", make_pdf(), owner_account_id=auth.id)
    n = esign.delete_agreements_for_owner(auth.id)
    assert n >= 2
    assert esign.count_agreements_for_owner(auth.id) == 0


def test_cannot_delete_sent_agreement(client, account_factory):
    auth = account_factory()
    aid = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "Sent"},
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
    client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers)
    r = client.request("DELETE", f"/api/mysign/agreements/{aid}", headers=auth.headers)
    assert r.status_code == 409  # legal record → void only


# --- signer access-lock challenge over the public token routes --------------
def test_signer_challenge_gates_document(client, account_factory):
    from sign import esign, esign_access

    auth = account_factory()
    aid = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "Gated"},
        headers=auth.headers,
    ).json()["id"]
    client.post(
        f"/api/mysign/agreements/{aid}/signers",
        json={"signers": [{"name": "Gia", "email": "gia@example.com"}]},
        headers=auth.headers,
    )
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={
            "fields": [{"type": "signature", "anchor": "Signature:", "signer": "gia@example.com"}]
        },
        headers=auth.headers,
    )
    token = client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers).json()[
        "links"
    ][0]["token"]
    # set an access-lock AFTER send (bumps epoch; challenge persists on the signer row)
    sid = esign.get_agreement(aid)["signers"][0]["id"]
    salt, wrapped, iters = esign_access.hash_challenge("opensesame", "code")
    esign.set_signer_challenge(aid, sid, "code", "Passcode?", salt, wrapped, iters)

    # payload route now reports challenge_required and the page image is blocked
    pl = client.get(f"/api/sign/token/{token}").json()
    assert pl.get("challenge_required") is True
    page = client.get(f"/api/sign/token/{token}/page/0")
    assert page.status_code == 403

    # wrong then correct challenge value over the public route
    wrong = client.post(f"/api/sign/token/{token}/challenge", json={"value": "nope"})
    assert wrong.json()["ok"] is False
    ok = client.post(f"/api/sign/token/{token}/challenge", json={"value": "opensesame"})
    assert ok.json()["ok"] is True
    # unlocked → page renders
    assert client.get(f"/api/sign/token/{token}/page/0").status_code == 200


def test_mark_challenge_passed_helper(client, account_factory):
    from sign import esign, esign_access

    auth = account_factory()
    aid = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "H"},
        headers=auth.headers,
    ).json()["id"]
    client.post(
        f"/api/mysign/agreements/{aid}/signers",
        json={"signers": [{"name": "H", "email": "h@example.com"}]},
        headers=auth.headers,
    )
    client.post(
        f"/api/mysign/agreements/{aid}/fields",
        json={"fields": [{"type": "signature", "anchor": "Signature:", "signer": "h@example.com"}]},
        headers=auth.headers,
    )
    token = client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers).json()[
        "links"
    ][0]["token"]
    sid = esign.get_agreement(aid)["signers"][0]["id"]
    salt, wrapped, iters = esign_access.hash_challenge("x", "code")
    esign.set_signer_challenge(aid, sid, "code", "?", salt, wrapped, iters)
    assert esign.mark_challenge_passed(token) is True


# --- phone-OTP login success (Twilio verifier monkeypatched) ----------------
def test_phone_verify_creates_account(client, account_factory, monkeypatch):
    from sign import sign_accounts, sign_portal_auth

    monkeypatch.setattr(sign_portal_auth, "check_phone_code", lambda phone, code: True)
    phone = "+15557778888"
    email = "phoneuser@example.com"
    pend = sign_portal_auth.make_phone_pending(phone, email, "Phone User")
    r = client.post(
        "/api/sign-portal/auth/phone/verify",
        json={"code": "123456"},
        headers={"cookie": f"{sign_portal_auth.COOKIE_PHONE}={pend}"},
    )
    assert r.json()["ok"] is True
    assert "account" in r.json()
    assert sign_accounts.account_by_phone(phone) is not None


# --- Google login success (OIDC exchange monkeypatched) ---------------------
def test_google_callback_success(client, account_factory, monkeypatch):
    from sign import sign_accounts, sign_portal_auth

    email = "googler@example.com"
    monkeypatch.setattr(sign_portal_auth, "google_exchange", lambda code, nonce=None: email)
    state = "state-abc"
    cookies = f"{sign_portal_auth.STATE_COOKIE}={state}; {sign_portal_auth.NONCE_COOKIE}=nonce-xyz"
    r = client.get(
        f"/api/sign-portal/auth/google/callback?code=authcode&state={state}",
        headers={"cookie": cookies},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/app"
    assert "__Host-ls_sign=" in r.headers.get("set-cookie", "")
    assert sign_accounts.account_by_email(email) is not None
