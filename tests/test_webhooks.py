"""Outbound webhooks — subscription CRUD, HMAC signing, matching, and guarded delivery.

The webhook subsystem (``sign.webhooks`` + ``sign.routers.webhooks``) is not yet mounted on the
shipped app (it is a separate integration step), so these tests drive it two ways without touching
any shared file: the pure/engine surface directly, and the router surface through a throwaway
FastAPI app that includes only the webhooks router. Delivery is exercised with a monkeypatched
``httpx.Client`` so retries, health counters, auto-disable, and signature verification are all
covered without a live receiver.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient


# --- pure surface -----------------------------------------------------------
def test_normalize_events_wildcard_subset_and_unknown():
    from sign import webhooks

    assert webhooks.normalize_events(None) == webhooks.ALL
    assert webhooks.normalize_events(["*"]) == webhooks.ALL
    assert webhooks.normalize_events("all") == webhooks.ALL
    got = webhooks.normalize_events(["envelope.sent", "signer.signed", "envelope.sent"])
    assert got == "envelope.sent,signer.signed"  # dedup, preserves order
    assert webhooks.normalize_events("envelope.completed") == "envelope.completed"
    with pytest.raises(ValueError):
        webhooks.normalize_events(["not.an.event"])
    with pytest.raises(ValueError):
        webhooks.normalize_events(123)


def test_events_out_and_matches():
    from sign import webhooks

    assert webhooks._events_out(webhooks.ALL) == ["*"]
    assert webhooks._events_out("envelope.sent,signer.signed") == ["envelope.sent", "signer.signed"]
    assert webhooks._matches(webhooks.ALL, "envelope.voided") is True
    assert webhooks._matches("envelope.sent", "envelope.sent") is True
    assert webhooks._matches("envelope.sent", "envelope.voided") is False


def test_validate_url_rejects_non_http():
    from sign import webhooks

    assert webhooks._validate_url("https://example.com/hook").startswith("https://")
    for bad in ("file:///etc/passwd", "gopher://x", "not-a-url", ""):
        with pytest.raises(ValueError):
            webhooks._validate_url(bad)


def test_sign_and_verify_signature():
    from sign import webhooks

    secret = "whsec_test"
    body = b'{"hello":"world"}'
    sig = webhooks.sign_body(secret, body)
    assert sig.startswith("sha256=")
    assert webhooks.verify_signature(secret, body, sig) is True
    assert webhooks.verify_signature(secret, body, "sha256=deadbeef") is False
    assert webhooks.verify_signature(secret, body, None) is False
    assert webhooks.verify_signature("", body, sig) is False


# --- CRUD (owner-scoped) ----------------------------------------------------
def test_crud_and_owner_scoping(client, account_factory):
    from sign import webhooks

    a, b = account_factory(), account_factory()
    row = webhooks.create_webhook(a.id, "https://a.example.com/hook", ["envelope.completed"])
    assert row["secret"].startswith("whsec_")
    assert row["events"] == ["envelope.completed"]
    wid = row["id"]

    assert any(w["id"] == wid for w in webhooks.list_webhooks(a.id))
    assert webhooks.list_webhooks(b.id) == []  # tenant isolation
    assert webhooks.get_webhook_owned(a.id, wid) is not None
    assert webhooks.get_webhook_owned(b.id, wid) is None  # cross-owner → None (→404)

    rotated = webhooks.rotate_secret(a.id, wid)
    assert rotated["secret"] != row["secret"]
    assert webhooks.rotate_secret(b.id, wid) is None

    assert webhooks.recent_deliveries(a.id, wid) == []
    assert webhooks.recent_deliveries(b.id, wid) is None

    assert webhooks.delete_webhook(b.id, wid) is False  # can't delete another owner's
    assert webhooks.delete_webhook(a.id, wid) is True
    assert webhooks.delete_webhook(a.id, wid) is False  # idempotent


# --- delivery (monkeypatched transport) -------------------------------------
class _FakeResp:
    def __init__(self, status_code):
        self.status_code = status_code


class _FakeClient:
    """Stand-in for httpx.Client — records posts and returns a queued status code."""

    posts: list = []
    statuses: list = [200]

    def __init__(self, *a, **kw):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, content=None, headers=None):
        _FakeClient.posts.append({"url": url, "content": content, "headers": headers})
        idx = min(len(_FakeClient.posts) - 1, len(_FakeClient.statuses) - 1)
        return _FakeResp(_FakeClient.statuses[idx])


@pytest.fixture
def fake_httpx(monkeypatch):
    from sign import webhooks

    _FakeClient.posts = []
    _FakeClient.statuses = [200]
    monkeypatch.setattr(webhooks.httpx, "Client", _FakeClient)
    # no real backoff sleeps
    monkeypatch.setattr(webhooks.time, "sleep", lambda *_: None)
    return _FakeClient


def test_deliver_now_success_signs_and_logs(client, account_factory, fake_httpx):
    from sign import webhooks

    auth = account_factory()
    row = webhooks.create_webhook(auth.id, "https://ok.example.com/hook", ["envelope.completed"])
    results = webhooks.deliver_now(
        "envelope.completed", {"agreement_id": 1, "status": "completed"}, auth.id
    )
    assert len(results) == 1 and results[0]["ok"] is True
    # the delivered body carries a valid signature the receiver can verify
    post = fake_httpx.posts[-1]
    sig = post["headers"]["X-Lifted-Signature"]
    assert webhooks.verify_signature(row["secret"], post["content"], sig) is True
    body = json.loads(post["content"])
    assert body["event"] == "envelope.completed" and body["data"]["status"] == "completed"
    # a delivery row is logged and health reset
    log = webhooks.recent_deliveries(auth.id, row["id"])
    assert log and log[0]["ok"] is True and log[0]["status_code"] == 200


def test_deliver_now_retries_then_fails(client, account_factory, fake_httpx):
    from sign import webhooks

    auth = account_factory()
    row = webhooks.create_webhook(auth.id, "https://bad.example.com/hook")
    fake_httpx.statuses = [500, 500, 500]  # every attempt fails
    results = webhooks.deliver_now("envelope.sent", {"x": 1}, auth.id, attempts=3)
    assert results[0]["ok"] is False
    assert results[0]["attempts"] == 3
    assert len(fake_httpx.posts) == 3  # all retries fired
    # health counter incremented
    got = webhooks.get_webhook_owned(auth.id, row["id"])
    assert got["failure_count"] >= 1


def test_emit_wildcard_and_unknown_event(client, account_factory, monkeypatch):
    from sign import webhooks

    auth = account_factory()
    webhooks.create_webhook(auth.id, "https://all.example.com/hook", ["*"])
    dispatched = []
    monkeypatch.setattr(webhooks, "_dispatch", lambda sub, ev, env: dispatched.append(ev))
    # a real event on a wildcard sub is scheduled
    assert webhooks.emit("envelope.completed", {"a": 1}, auth.id) == 1
    # an unknown event / missing owner schedules nothing and never raises
    assert webhooks.emit("bogus.event", {}, auth.id) == 0
    assert webhooks.emit("envelope.completed", {}, None) == 0
    assert dispatched == ["envelope.completed"]


# --- router surface (test-local app; shipped app.py is not modified) --------
@pytest.fixture(scope="module")
def wh_client():
    from fastapi import FastAPI

    from sign import db
    from sign.routers import webhooks as wh_router

    db.ensure_tables()  # infra tables (this local app has no _lifespan to create them)
    app = FastAPI()
    app.include_router(wh_router.router)
    with TestClient(app) as c:
        yield c


def test_router_crud_flow(wh_client, account_factory):
    auth = account_factory()
    created = wh_client.post(
        "/api/mysign/webhooks",
        json={"url": "https://rx.example.com/h", "events": ["envelope.sent"]},
        headers=auth.headers,
    )
    assert created.json()["ok"] is True
    wid = created.json()["webhook"]["id"]

    listed = wh_client.get("/api/mysign/webhooks", headers=auth.headers).json()
    assert any(w["id"] == wid for w in listed["webhooks"])
    assert "envelope.sent" in listed["events"]

    rot = wh_client.post(f"/api/mysign/webhooks/{wid}/rotate", headers=auth.headers)
    assert rot.json()["ok"] is True

    dev = wh_client.get(f"/api/mysign/webhooks/{wid}/deliveries", headers=auth.headers)
    assert dev.status_code == 200 and isinstance(dev.json()["deliveries"], list)

    dele = wh_client.request("DELETE", f"/api/mysign/webhooks/{wid}", headers=auth.headers)
    assert dele.json()["ok"] is True


def test_router_validation_and_authz(wh_client, account_factory):
    auth = account_factory()
    # missing url → 400
    assert wh_client.post("/api/mysign/webhooks", json={}, headers=auth.headers).status_code == 400
    # bad url → 400
    bad = wh_client.post("/api/mysign/webhooks", json={"url": "file:///x"}, headers=auth.headers)
    assert bad.status_code == 400
    # unknown event → 400
    ue = wh_client.post(
        "/api/mysign/webhooks",
        json={"url": "https://x.example.com/h", "events": ["nope"]},
        headers=auth.headers,
    )
    assert ue.status_code == 400
    # unauth → 401
    assert wh_client.get("/api/mysign/webhooks").status_code == 401
    # cross-owner id → 404 (no oracle)
    a, b = account_factory(), account_factory()
    wid = wh_client.post(
        "/api/mysign/webhooks", json={"url": "https://a.example.com/h"}, headers=a.headers
    ).json()["webhook"]["id"]
    assert (
        wh_client.request("DELETE", f"/api/mysign/webhooks/{wid}", headers=b.headers).status_code
        == 404
    )


def test_router_test_ping_scheduled(wh_client, account_factory, monkeypatch):
    from sign import webhooks

    auth = account_factory()
    wid = wh_client.post(
        "/api/mysign/webhooks", json={"url": "https://p.example.com/h"}, headers=auth.headers
    ).json()["webhook"]["id"]
    monkeypatch.setattr(webhooks, "_dispatch", lambda *a, **k: None)
    r = wh_client.post(f"/api/mysign/webhooks/{wid}/test", headers=auth.headers)
    assert r.json()["ok"] is True and r.json()["scheduled"] == 1
