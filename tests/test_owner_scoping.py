"""Tenant isolation — the IDOR choke-point (``_require_owned`` → 404, never 403/oracle).

Account A must never read, download, mutate, or even confirm the existence of account B's
agreement. Every cross-owner attempt returns 404 (existence is not an oracle), and an unauthed
request to a protected route is 401.
"""

from __future__ import annotations

from conftest import make_pdf


def _create(client, auth, name="Owned Doc"):
    r = client.post(
        "/api/mysign/agreements",
        files={"file": ("doc.pdf", make_pdf(), "application/pdf")},
        data={"name": name},
        headers=auth.headers,
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_cross_owner_get_is_404(client, account_factory):
    a, b = account_factory(), account_factory()
    aid = _create(client, a)
    # owner sees it
    assert client.get(f"/api/mysign/agreements/{aid}", headers=a.headers).status_code == 200
    # stranger gets 404, not 403 (no existence oracle)
    r = client.get(f"/api/mysign/agreements/{aid}", headers=b.headers)
    assert r.status_code == 404
    assert r.json() == {"error": "not found"}


def test_cross_owner_download_is_404(client, account_factory):
    a, b = account_factory(), account_factory()
    aid = _create(client, a)
    assert (
        client.get(f"/api/mysign/agreements/{aid}/download", headers=b.headers).status_code == 404
    )


def test_cross_owner_mutation_is_404(client, account_factory):
    a, b = account_factory(), account_factory()
    aid = _create(client, a)
    r = client.post(
        f"/api/mysign/agreements/{aid}/signers",
        json={"signers": [{"name": "X", "email": "x@example.com"}]},
        headers=b.headers,
    )
    assert r.status_code == 404


def test_cross_owner_send_is_404(client, account_factory):
    a, b = account_factory(), account_factory()
    aid = _create(client, a)
    r = client.post(f"/api/mysign/agreements/{aid}/send", json={}, headers=b.headers)
    assert r.status_code == 404


def test_list_only_returns_own_agreements(client, account_factory):
    a, b = account_factory(), account_factory()
    aid_a = _create(client, a, "A-only")
    _create(client, b, "B-only")
    listing = client.get("/api/mysign/agreements", headers=a.headers).json()
    ids = {x["id"] for x in listing["agreements"]}
    assert aid_a in ids
    assert all(x["created_by"] == a.email for x in listing["agreements"])


def test_unauth_mysign_is_401(client):
    # middleware allowlist: no cookie + no bearer → 401 before the handler
    assert client.get("/api/mysign/agreements").status_code == 401
    assert client.get("/api/mysign/account").status_code == 401


def test_bearer_api_key_scoped_to_owner(client, account_factory):
    """A developer Bearer key resolves to exactly its account and flows through the same owner
    choke-point — it can read its own agreement but 404s on another account's."""
    from sign import sign_api_keys

    a, b = account_factory(), account_factory()
    aid_a = _create(client, a)
    aid_b = _create(client, b)
    raw, _meta = sign_api_keys.issue(a.id, "test-key", "live")
    hdr = {"authorization": f"Bearer {raw}"}
    assert client.get(f"/api/mysign/agreements/{aid_a}", headers=hdr).status_code == 200
    assert client.get(f"/api/mysign/agreements/{aid_b}", headers=hdr).status_code == 404
    # a bogus bearer is unauthorized
    assert (
        client.get(
            "/api/mysign/agreements", headers={"authorization": "Bearer sk_live_bogus"}
        ).status_code
        == 401
    )
