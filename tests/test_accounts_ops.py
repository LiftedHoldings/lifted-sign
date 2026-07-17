"""Sender-account model + the operator console (``/api/sign-ops/*``).

``sign_accounts`` public projection (never leaks pw_hash / totp_secret), subscription status +
``can_send`` gating, session-version revocation, and the operator console — closed by default
(empty ADMIN_EMAILS), open only to a signed-in account whose email is allow-listed.
"""

from __future__ import annotations


def test_public_view_hides_secrets(client, account_factory):
    from sign import sign_accounts

    auth = account_factory()
    view = sign_accounts.public_view(sign_accounts.account_by_id(auth.id))
    assert view["email"] == auth.email
    assert "pw_hash" not in view
    assert "totp_secret" not in view


def test_can_send_gate_by_sub_status(client, account_factory):
    from sign import sign_accounts

    auth = account_factory()
    assert sign_accounts.can_send(auth.id) is True
    sign_accounts.set_sub_status(auth.id, "canceled")
    assert sign_accounts.can_send(auth.id) is False
    # reactivate an already-known account
    sign_accounts.set_sub_status(auth.id, "active")
    assert sign_accounts.can_send(auth.id) is True


def test_send_blocked_when_subscription_inactive(client, account_factory):
    from conftest import make_pdf
    from sign import sign_accounts

    auth = account_factory()
    r = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "Doc"},
        headers=auth.headers,
    )
    aid = r.json()["id"]
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
    sign_accounts.set_sub_status(auth.id, "canceled")
    send = client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers)
    assert send.status_code == 403
    assert send.json()["error"] == "subscription_inactive"


def test_send_blocked_when_email_unverified(client, account_factory):
    from conftest import make_pdf

    auth = account_factory(verified=False)
    r = client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "Doc"},
        headers=auth.headers,
    )
    aid = r.json()["id"]
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
    send = client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=auth.headers)
    assert send.status_code == 403 and send.json()["error"] == "email_unverified"


def test_account_endpoint_reports_doc_count(client, account_factory):
    from conftest import make_pdf

    auth = account_factory()
    client.post(
        "/api/mysign/agreements",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"name": "Doc"},
        headers=auth.headers,
    )
    acct = client.get("/api/mysign/account", headers=auth.headers).json()["account"]
    assert acct["email"] == auth.email
    assert acct["agreement_count"] >= 1


def test_api_key_lifecycle_over_http(client, account_factory):
    auth = account_factory()
    created = client.post(
        "/api/mysign/api-keys", json={"label": "ci", "mode": "test"}, headers=auth.headers
    )
    assert created.json()["ok"] is True
    raw = created.json()["key"]
    assert raw.startswith("sk_test_")
    kid = created.json()["meta"]["id"]
    listing = client.get("/api/mysign/api-keys", headers=auth.headers).json()
    assert any(k["id"] == kid for k in listing["keys"])
    rev = client.post(f"/api/mysign/api-keys/{kid}/revoke", headers=auth.headers)
    assert rev.json()["ok"] is True
    # a revoked key no longer authenticates
    assert (
        client.get("/api/mysign/agreements", headers={"authorization": f"Bearer {raw}"}).status_code
        == 401
    )


# --- operator console -------------------------------------------------------
def test_ops_console_open_only_to_admin_emails(client, account_factory, monkeypatch):
    from sign import config

    admin = account_factory()
    monkeypatch.setattr(config, "ADMIN_EMAILS", [admin.email])

    accounts = client.get("/api/sign-ops/accounts", headers=admin.headers)
    assert accounts.status_code == 200
    assert isinstance(accounts.json()["accounts"], list)

    summary = client.get("/api/sign-ops/summary", headers=admin.headers).json()
    assert summary["total"] >= 1 and "mrr" in summary

    # a non-admin account is still forbidden even while the console is enabled
    other = account_factory()
    assert client.get("/api/sign-ops/accounts", headers=other.headers).status_code == 403


def test_ops_suspend_and_reinstate(client, account_factory, monkeypatch):
    from sign import config, sign_accounts

    admin = account_factory()
    monkeypatch.setattr(config, "ADMIN_EMAILS", [admin.email])
    target = account_factory()

    susp = client.post(
        f"/api/sign-ops/accounts/{target.id}/status",
        json={"suspended": True},
        headers=admin.headers,
    )
    assert susp.json()["status"] == "suspended"
    assert sign_accounts.account_by_id(target.id)["status"] == "suspended"

    reinstate = client.post(
        f"/api/sign-ops/accounts/{target.id}/status",
        json={"suspended": False},
        headers=admin.headers,
    )
    assert reinstate.json()["status"] == "active"

    # unknown account id → 404
    missing = client.post(
        "/api/sign-ops/accounts/99999999/status", json={"suspended": True}, headers=admin.headers
    )
    assert missing.status_code == 404


def test_sign_ops_purge_only_test_tenants(client, account_factory, monkeypatch):
    from sign import config, sign_accounts, sign_ops

    admin = account_factory()
    monkeypatch.setattr(config, "ADMIN_EMAILS", [admin.email])
    # a throwaway test-tenant (isotest- prefix) is purgeable; a real account is not
    sign_accounts.create_account("isotest-purgeme@example.com", "T", None)
    res = client.post("/api/sign-ops/purge-test", headers=admin.headers).json()
    assert res["ok"] is True
    assert sign_accounts.account_by_email("isotest-purgeme@example.com") is None
    # the admin's own real account survives
    assert sign_accounts.account_by_id(admin.id) is not None
    # direct summary/list layer
    assert sign_ops.summary()["total"] >= 1
