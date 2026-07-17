"""Webhook health bookkeeping — auto-disable, failure-count reset, transport faults, and the
delivery-time (DNS-rebinding) SSRF re-check.

The CRUD + happy-path delivery live in ``test_webhooks``. These cover the reliability machinery a
production webhook fleet depends on:

  * a subscription that fails ``_DISABLE_AFTER`` consecutive deliveries is deactivated
    (``active=0``) and then stops matching — ``deliver_now`` / ``emit`` schedule nothing for it,
  * a single success resets the failure counter to zero (a flaky endpoint recovers cleanly),
  * a transport-layer exception (not an HTTP status) is retried, logged, and folded into the health
    counter without ever escaping ``_deliver_sync``,
  * a URL that was public at registration but resolves internal at delivery time is refused by the
    pre-POST ``_assert_public_host`` re-check — no POST is issued.
"""

from __future__ import annotations

import pytest

from sign import db, webhooks


class _Resp:
    def __init__(self, status_code):
        self.status_code = status_code


class _Client:
    """Recording stand-in for httpx.Client. ``mode`` picks the behavior of ``post``."""

    posts: list = []
    mode = "500"  # "500" → HTTP 500; "200" → HTTP 200; "raise" → transport error

    def __init__(self, *a, **kw):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, content=None, headers=None):
        _Client.posts.append(url)
        if _Client.mode == "raise":
            raise webhooks.httpx.HTTPError("connection reset")
        return _Resp(200 if _Client.mode == "200" else 500)


@pytest.fixture
def fake_transport(monkeypatch):
    _Client.posts = []
    _Client.mode = "500"
    monkeypatch.setattr(webhooks.httpx, "Client", _Client)
    monkeypatch.setattr(webhooks.time, "sleep", lambda *_: None)  # no real backoff
    return _Client


def _set_failure_count(webhook_id: int, n: int) -> None:
    conn = db.connect()
    try:
        conn.execute("UPDATE sign_webhooks SET failure_count=? WHERE id=?", (n, webhook_id))
        conn.commit()
    finally:
        conn.close()


def test_auto_disable_after_threshold_then_stops_matching(client, account_factory, fake_transport):
    auth = account_factory()
    row = webhooks.create_webhook(auth.id, "https://dead.example.com/hook", ["envelope.completed"])
    wid = row["id"]
    # Park the counter one below the threshold, then one more failed delivery trips auto-disable.
    _set_failure_count(wid, webhooks._DISABLE_AFTER - 1)
    res = webhooks.deliver_now("envelope.completed", {"x": 1}, auth.id, attempts=1)
    assert res and res[0]["ok"] is False
    got = webhooks.get_webhook_owned(auth.id, wid)
    assert got["active"] is False  # deactivated
    assert got["failure_count"] >= webhooks._DISABLE_AFTER
    # A deactivated subscription no longer matches: nothing is scheduled/delivered for it.
    assert webhooks.deliver_now("envelope.completed", {"x": 2}, auth.id, attempts=1) == []
    assert webhooks.emit("envelope.completed", {"x": 3}, auth.id) == 0


def test_success_resets_failure_count(client, account_factory, fake_transport):
    auth = account_factory()
    row = webhooks.create_webhook(auth.id, "https://flaky.example.com/hook", ["envelope.sent"])
    wid = row["id"]
    _set_failure_count(wid, 7)  # a history of failures, but below the disable threshold
    _Client.mode = "200"
    res = webhooks.deliver_now("envelope.sent", {"x": 1}, auth.id, attempts=1)
    assert res[0]["ok"] is True
    got = webhooks.get_webhook_owned(auth.id, wid)
    assert got["failure_count"] == 0 and got["active"] is True  # recovered cleanly


def test_transport_exception_retried_and_counted(client, account_factory, fake_transport):
    auth = account_factory()
    row = webhooks.create_webhook(auth.id, "https://gone.example.com/hook", ["envelope.sent"])
    _Client.mode = "raise"  # every POST raises a transport error (not an HTTP status)
    res = webhooks.deliver_now("envelope.sent", {"x": 1}, auth.id, attempts=3)
    assert res[0]["ok"] is False
    assert res[0]["attempts"] == 3  # all retries attempted
    assert len(_Client.posts) == 3  # each attempt actually fired a POST
    assert res[0]["error"]  # transport error captured, not swallowed silently
    assert webhooks.get_webhook_owned(auth.id, row["id"])["failure_count"] >= 1


def test_delivery_time_ssrf_recheck_blocks_rebind(
    client, account_factory, fake_transport, monkeypatch
):
    """A loopback URL accepted while the guard was off (suite default) must be refused at DELIVERY
    time once the guard is on — the DNS-rebinding defense — and no POST may be issued."""
    auth = account_factory()
    row = webhooks.create_webhook(auth.id, "http://127.0.0.1:9000/hook", ["envelope.sent"])
    monkeypatch.setattr(webhooks.config, "WEBHOOK_ALLOW_INTERNAL", False)  # guard ON for delivery
    res = webhooks.deliver_now("envelope.sent", {"x": 1}, auth.id, attempts=3)
    assert res[0]["ok"] is False
    assert "non-public" in res[0]["error"]  # refused by the pre-POST host re-check
    assert _Client.posts == []  # crucially: nothing was ever sent to the internal address
    # Health still folds the failure in (isolation boundary marked the result).
    assert webhooks.get_webhook_owned(auth.id, row["id"])["failure_count"] >= 1
