"""Operational probes (``sign.routers.meta``) — liveness / readiness / version.

Not yet mounted on the shipped app, so driven through a throwaway app that includes only the meta
router (no shared-file edit). Liveness must never touch the DB; readiness must reflect DB
reachability and fail closed to 503 without leaking error detail; version reports build facts only.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def meta_client():
    from sign import db
    from sign.routers import meta

    db.ensure_tables()
    app = FastAPI()
    app.include_router(meta.router)
    with TestClient(app) as c:
        yield c


def test_healthz_liveness(meta_client):
    r = meta_client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_readyz_ok_when_db_reachable(meta_client):
    r = meta_client.get("/readyz")
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "checks": {"db": True}}


def test_readyz_503_when_db_down(meta_client, monkeypatch):
    from sign.routers import meta

    def _boom():
        raise RuntimeError("db is down")

    monkeypatch.setattr(meta, "db_connect", _boom)
    r = meta_client.get("/readyz")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "unavailable" and body["checks"]["db"] is False
    # the underlying error text is never leaked
    assert "db is down" not in r.text


def test_version_reports_build_facts(meta_client):
    from sign import __version__

    r = meta_client.get("/version")
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "lifted-sign"
    assert body["version"] == __version__
    assert body["hosted"] is False
