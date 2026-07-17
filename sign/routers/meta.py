"""``/healthz``, ``/readyz``, ``/version`` — operational probes for orchestrators.

These are the endpoints a Fortune-500 deployment (Kubernetes, ECS, a load
balancer, an uptime monitor, a Docker ``HEALTHCHECK``) polls to decide whether
the process should receive traffic. They are public and unauthenticated by
design — a probe must not carry a credential — so each one is written to reveal
*only* a boolean-grade signal and never a secret, DSN, filesystem path, or stack
trace.

**Liveness vs. readiness** — the distinction is what the orchestrator *does*
with the answer, and getting it wrong causes outages:

* **Liveness** (``/healthz``) answers "is this process alive and its event loop
  responsive?" It touches nothing external and always returns fast. A liveness
  failure means the orchestrator should *restart* the container. Critically, it
  must **not** depend on the database: if it did, a brief DB blip would fail
  liveness everywhere at once and trigger a restart storm that takes the whole
  fleet down instead of letting it ride out the blip.

* **Readiness** (``/readyz``) answers "can this instance serve a real request
  right now?" — which for this server means the database is reachable. A
  readiness failure means the orchestrator should pull the instance *out of the
  load-balancer rotation* (but keep it running) until its dependencies recover.
  Because it does real I/O it can be slow or fail, so it is never wired to the
  liveness probe.

``/version`` reports build identity (package name, version, and whether this is
a hosted install) for support and deploy-verification — no secrets, just facts a
release engineer needs to confirm *what* is running.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from .. import config

router = APIRouter()


@router.get("/healthz")  # liveness — never touches the DB, always fast
async def healthz() -> dict[str, str]:
    """Liveness probe: proof the process is up and the event loop is turning.

    Deliberately does no I/O so a database or network hiccup can never fail
    liveness and provoke a restart loop. Restarting the process cannot fix a
    down dependency; that is readiness's job.
    """
    return {"status": "ok"}


def _db_ok() -> bool:
    """Open a connection and run a trivial ``SELECT 1`` on whichever backend is
    configured. Runs in a worker thread (the drivers are blocking); the caller
    treats any exception as "not ready" and never surfaces its text."""
    conn = db_connect()
    try:
        row = conn.execute("SELECT 1").fetchone()
        return row is not None and tuple(row)[0] == 1
    finally:
        conn.close()


def db_connect():
    """Indirection so the DB module is imported lazily (keeps this router's
    import path free of DB-driver side effects)."""
    from .. import db

    return db.connect()


@router.get("/readyz")  # readiness — verifies DB connectivity
async def readyz() -> Any:
    """Readiness probe: 200 only when the database answers.

    On success returns ``{"status": "ready", "checks": {"db": true}}``. On
    failure returns HTTP 503 with the failing check flagged
    (``{"status": "unavailable", "checks": {"db": false}}``) so the orchestrator
    pulls this instance from rotation. The underlying error is intentionally
    *not* included — a public probe must not leak a DSN, host, or stack trace.
    """
    try:
        ok = await asyncio.to_thread(_db_ok)
    except Exception:
        ok = False
    if ok:
        return {"status": "ready", "checks": {"db": True}}
    return JSONResponse(
        {"status": "unavailable", "checks": {"db": False}},
        status_code=503,
    )


@router.get("/version")  # build identity — no secrets, just facts
async def version() -> dict[str, Any]:
    """Report package name, version, and hosted/self-host mode.

    Everything here is public build metadata a release engineer uses to confirm
    what is deployed. No secret, path, or environment value is exposed.
    """
    from .. import __version__

    return {
        "name": "lifted-sign",
        "version": __version__,
        "hosted": config.HOSTED_MODE,
    }
