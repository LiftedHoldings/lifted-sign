"""Outbound webhooks for Lifted Sign — signed, retried, audited event delivery.

A **subscription** (``sign_webhooks``) is an owner-scoped HTTPS endpoint that wants to be
notified when something happens to one of that owner's envelopes: an envelope is sent, a
signer signs, an envelope completes, is voided, declined, or expires. When the signing
engine reaches one of those transitions it calls :func:`emit`, which fans the event out to
every active matching subscription for that owner.

Delivery contract (stable, documented in the developer guide + SDK):

* **Body** — a compact JSON object ``{"id", "event", "created", "data": <payload>}``.
  ``id`` is a unique event id, ``created`` a Unix timestamp, ``data`` the event-specific
  payload (e.g. ``{"agreement_id", "status", ...}``).
* **Headers** —
    * ``X-Lifted-Event``     the event name (e.g. ``envelope.completed``);
    * ``X-Lifted-Delivery``  a per-delivery UUID (stable across retries, so a receiver can
      dedupe);
    * ``X-Lifted-Signature`` ``sha256=<hex>`` where ``<hex>`` is the HMAC-SHA256 of the
      **exact raw request body** keyed by the subscription's ``whsec_`` secret. A receiver
      recomputes it with :func:`verify_signature` to authenticate the call.
* **Retries** — up to :data:`_MAX_ATTEMPTS` attempts with exponential backoff on any
  non-2xx / transport error. Every attempt is written to ``sign_webhook_deliveries`` for
  the audit/delivery log.
* **Auto-disable** — a subscription that fails :data:`_DISABLE_AFTER` consecutive deliveries
  is deactivated (``active=0``) so a dead endpoint stops consuming worker time; the owner
  re-enables it by rotating/recreating.

**Isolation is absolute.** :func:`emit` never blocks the signing request and a webhook error
can never surface into the signing flow: delivery runs in a background task (or a daemon
thread when ``emit`` is called from a worker thread with no running event loop), and every
delivery path is fully guarded. A broken customer endpoint has zero effect on sealing a
document.

Persistence lives in this module (``ensure_tables`` self-runs at import, mirroring
``sign_api_keys``); everything is scoped to ``owner_account_id`` — the same tenant identity
the ``/api/mysign/*`` API authorizes on.

Security note (SSRF): a webhook URL is operator/tenant supplied and delivery POSTs to it
from the server. Redirects are not followed. Restricting delivery to public IP ranges (to
prevent access to internal metadata endpoints) is deployment policy and left to the operator
via network egress rules; this module deliberately does not block loopback so local
development and self-hosted receivers on the same host keep working.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import threading
import time
import uuid
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import config, db

log = logging.getLogger(__name__)

# --- canonical event names --------------------------------------------------
# The complete, stable set of events a subscription can receive. A subscription's ``events``
# is either the wildcard sentinel ``ALL`` or a comma-separated subset of these.
EVENT_ENVELOPE_SENT = "envelope.sent"
EVENT_ENVELOPE_VIEWED = "envelope.viewed"
EVENT_SIGNER_SIGNED = "signer.signed"
EVENT_ENVELOPE_COMPLETED = "envelope.completed"
EVENT_ENVELOPE_DECLINED = "envelope.declined"
EVENT_ENVELOPE_VOIDED = "envelope.voided"
EVENT_ENVELOPE_EXPIRED = "envelope.expired"

EVENTS: tuple[str, ...] = (
    EVENT_ENVELOPE_SENT,
    EVENT_ENVELOPE_VIEWED,
    EVENT_SIGNER_SIGNED,
    EVENT_ENVELOPE_COMPLETED,
    EVENT_ENVELOPE_DECLINED,
    EVENT_ENVELOPE_VOIDED,
    EVENT_ENVELOPE_EXPIRED,
)

# Sentinel stored in ``sign_webhooks.events`` meaning "every event". Surfaced to the API as
# the ``["*"]`` wildcard (mirrors the common webhook-config convention).
ALL = "all"

# --- delivery tuning --------------------------------------------------------
_MAX_ATTEMPTS = 3  # total POST attempts per subscription before a delivery is failed
_TIMEOUT = 5.0  # seconds — short; a webhook receiver must ack fast, not do work inline
_BACKOFF_BASE = 0.5  # seconds; attempt n waits _BACKOFF_BASE * 2**(n-1)
_BACKOFF_CAP = 8.0  # seconds — ceiling on a single backoff sleep
_DISABLE_AFTER = 15  # consecutive failed deliveries → auto-disable the subscription
_SECRET_BYTES = 32  # entropy of a generated signing secret
_USER_AGENT = "Lifted-Sign-Webhooks/1"


# ---------------------------------------------------------------------------
# Schema — owned by this module; ensure_tables() self-runs at import.
# ---------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS sign_webhooks (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_account_id INTEGER NOT NULL,
  url              TEXT NOT NULL,
  secret           TEXT NOT NULL,
  events           TEXT NOT NULL DEFAULT 'all',
  active           INTEGER NOT NULL DEFAULT 1,
  created_at       REAL,
  last_status      INTEGER,
  last_delivery_at REAL,
  failure_count    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sign_webhooks_owner ON sign_webhooks(owner_account_id);
CREATE TABLE IF NOT EXISTS sign_webhook_deliveries (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  webhook_id  INTEGER NOT NULL,
  event       TEXT,
  status_code INTEGER,
  ok          INTEGER NOT NULL DEFAULT 0,
  attempt     INTEGER,
  created_at  REAL,
  response_ms INTEGER,
  error       TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sign_wh_deliveries_wh ON sign_webhook_deliveries(webhook_id);
"""


def ensure_tables() -> None:
    """Create the webhook tables on a blank database (idempotent). Additive migrations use
    ``db._columns`` — never a raw PRAGMA — so a future column can be added without a
    destructive rebuild, exactly like the esign/account modules."""
    conn = db.connect()
    try:
        conn.executescript(_SCHEMA)
        # Additive-migration choke-point: newly-introduced columns are appended here guarded
        # by db._columns so existing installs upgrade in place. (No deltas yet — the create
        # DDL above is current — but the pattern is wired so the next column is a one-liner.)
        for table, cols in (("sign_webhooks", ()), ("sign_webhook_deliveries", ())):
            have = set(db._columns(conn, table))
            for col, ddl in cols:  # pragma: no cover - no pending migrations yet
                if col not in have:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# events (de)serialization
# ---------------------------------------------------------------------------


def normalize_events(events: Any) -> str:
    """Normalize a caller-supplied event selector to the stored form.

    Accepts a list/tuple of event names, a comma-separated string, ``None``/empty, or a
    wildcard (``"*"`` / ``"all"`` as a value or list element). Returns the ``ALL`` sentinel
    for a wildcard, else a comma-joined subset of :data:`EVENTS`. Raises ``ValueError`` naming
    the first unknown event so the route can answer a clean 400.
    """
    if events is None:
        return ALL
    if isinstance(events, str):
        items = [e.strip() for e in events.split(",")]
    elif isinstance(events, (list, tuple)):
        items = [str(e).strip() for e in events]
    else:
        raise ValueError("events must be a list or comma-separated string")
    items = [e for e in items if e]
    if not items or any(e in ("*", ALL) for e in items):
        return ALL
    valid = set(EVENTS)
    picked: list[str] = []
    for e in items:
        if e not in valid:
            raise ValueError(f"unknown event: {e}")
        if e not in picked:
            picked.append(e)
    return ",".join(picked)


def _events_out(stored: str) -> list[str]:
    """Render the stored ``events`` string for the API: ``["*"]`` for the wildcard, else the
    explicit list."""
    if (stored or ALL) == ALL:
        return ["*"]
    return [e for e in stored.split(",") if e]


def _matches(stored: str, event: str) -> bool:
    """True if a subscription whose stored selector is ``stored`` should receive ``event``."""
    if (stored or ALL) == ALL:
        return True
    return event in {e for e in stored.split(",") if e}


def _blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True if an address is one delivery must never reach: loopback, private (RFC 1918 /
    ULA), link-local (incl. the 169.254.169.254 cloud-metadata endpoint), unspecified, or
    otherwise reserved/non-global. This is the SSRF choke point."""
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_multicast
        or not ip.is_global
    )


def _assert_public_host(host: str) -> None:
    """Resolve ``host`` and raise ``ValueError`` if it maps to any non-public address — an
    SSRF guard so a tenant-supplied webhook URL can't reach internal services (databases,
    admin panels, cloud metadata). Called at subscription create time AND again immediately
    before each delivery POST, which blunts DNS-rebinding (a name that resolves public at
    registration but private at delivery time is caught on the pre-POST check). A self-hoster
    who needs loopback/internal delivery opts out via SIGN_WEBHOOK_ALLOW_INTERNAL.

    Residual limitation: httpx re-resolves the name for the actual connection, so a name that
    flips between this check and the socket connect could still slip through in theory; combined
    with follow_redirects=False and the pre-POST timing this is a narrow window, and pinning the
    connection to the vetted IP is a documented future hardening.
    """
    if config.WEBHOOK_ALLOW_INTERNAL:
        return
    # A bare IP literal is checked directly; a hostname is resolved to every A/AAAA record.
    try:
        literal = ipaddress.ip_address(host)
        candidates = [literal]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError as e:
            raise ValueError(f"webhook host does not resolve: {host}") from e
        candidates = [ipaddress.ip_address(info[4][0]) for info in infos]
    for ip in candidates:
        if _blocked_ip(ip):
            raise ValueError("webhook url resolves to a non-public address")


def _validate_url(url: str) -> str:
    """Return the trimmed URL if it is a syntactically valid http(s) endpoint that resolves to a
    public address, else raise ``ValueError``. Scheme is restricted to http/https so a
    subscription can never point the delivery worker at a ``file://`` / ``gopher://`` target,
    and the host is checked against the SSRF guard (see ``_assert_public_host``)."""
    u = (url or "").strip()
    parts = urlsplit(u)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("url must be an absolute http(s) URL")
    if parts.hostname:
        _assert_public_host(parts.hostname)
    return u


def _public(row: dict) -> dict:
    """Owner-facing view of a subscription. Includes ``secret`` deliberately — the endpoint is
    owner-scoped and the owner needs the signing secret to verify deliveries (mirrors how
    dashboard webhook UIs let the owner reveal their signing secret)."""
    return {
        "id": row["id"],
        "url": row.get("url") or "",
        "secret": row.get("secret") or "",
        "events": _events_out(row.get("events") or ALL),
        "active": bool(row.get("active", 1)),
        "created_at": row.get("created_at"),
        "last_status": row.get("last_status"),
        "last_delivery_at": row.get("last_delivery_at"),
        "failure_count": int(row.get("failure_count") or 0),
    }


def _new_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(_SECRET_BYTES)


def _as_dict(row) -> dict | None:
    if row is None:
        return None
    return dict(row) if not isinstance(row, dict) else row


# ---------------------------------------------------------------------------
# CRUD (owner-scoped)
# ---------------------------------------------------------------------------


def create_webhook(owner_id: int, url: str, events: Any = None) -> dict:
    """Create a subscription for ``owner_id``. Generates a ``whsec_`` signing secret. ``events``
    is normalized via :func:`normalize_events` (default = all). Returns the public row (incl.
    the secret, shown to the owner). Raises ``ValueError`` on a bad URL / unknown event."""
    u = _validate_url(url)
    ev = normalize_events(events)
    secret = _new_secret()
    now = time.time()
    conn = db.connect()
    try:
        wid = db.insert_returning(
            conn,
            "INSERT INTO sign_webhooks(owner_account_id,url,secret,events,active,created_at,failure_count)"
            " VALUES(?,?,?,?,1,?,0)",
            (int(owner_id), u, secret, ev, now),
        )
        conn.commit()
    finally:
        conn.close()
    return _public(
        {
            "id": wid,
            "url": u,
            "secret": secret,
            "events": ev,
            "active": 1,
            "created_at": now,
            "last_status": None,
            "last_delivery_at": None,
            "failure_count": 0,
        }
    )


def list_webhooks(owner_id: int) -> list[dict]:
    """Every subscription owned by ``owner_id`` (newest first)."""
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT * FROM sign_webhooks WHERE owner_account_id=? ORDER BY created_at DESC, id DESC",
            (int(owner_id),),
        ).fetchall()
        return [_public(_as_dict(r)) for r in rows]
    finally:
        conn.close()


def get_webhook_owned(owner_id: int, webhook_id: int) -> dict | None:
    """A single subscription IFF it belongs to ``owner_id`` (else ``None`` → the route answers
    404, never 403 — a wrong id is not an existence oracle)."""
    conn = db.connect()
    try:
        row = conn.execute(
            "SELECT * FROM sign_webhooks WHERE id=? AND owner_account_id=?",
            (int(webhook_id), int(owner_id)),
        ).fetchone()
        r = _as_dict(row)
        return _public(r) if r else None
    finally:
        conn.close()


def delete_webhook(owner_id: int, webhook_id: int) -> bool:
    """Owner-scoped delete (the ``owner_account_id`` filter is the IDOR guard). Idempotent —
    returns True only when a row was actually removed."""
    conn = db.connect()
    try:
        cur = conn.execute(
            "DELETE FROM sign_webhooks WHERE id=? AND owner_account_id=?",
            (int(webhook_id), int(owner_id)),
        )
        conn.commit()
        return (cur.rowcount or 0) > 0
    finally:
        conn.close()


def rotate_secret(owner_id: int, webhook_id: int) -> dict | None:
    """Mint a new signing secret for an owned subscription (invalidates the old one). Returns
    the refreshed public row, or ``None`` when the id isn't owned by ``owner_id``."""
    secret = _new_secret()
    conn = db.connect()
    try:
        cur = conn.execute(
            "UPDATE sign_webhooks SET secret=? WHERE id=? AND owner_account_id=?",
            (secret, int(webhook_id), int(owner_id)),
        )
        conn.commit()
        if not (cur.rowcount or 0):
            return None
        row = conn.execute(
            "SELECT * FROM sign_webhooks WHERE id=? AND owner_account_id=?",
            (int(webhook_id), int(owner_id)),
        ).fetchone()
        return _public(_as_dict(row))
    finally:
        conn.close()


def recent_deliveries(owner_id: int, webhook_id: int, limit: int = 50) -> list[dict] | None:
    """The recent delivery/audit log for an OWNED subscription (newest first), or ``None`` when
    the id isn't owned by ``owner_id`` (→ 404 at the route). Ownership is verified first so the
    delivery log can't be read cross-tenant."""
    if get_webhook_owned(owner_id, webhook_id) is None:
        return None
    limit = max(1, min(int(limit), 200))
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT id,webhook_id,event,status_code,ok,attempt,created_at,response_ms,error"
            " FROM sign_webhook_deliveries WHERE webhook_id=? ORDER BY id DESC LIMIT ?",
            (int(webhook_id), limit),
        ).fetchall()
        out = []
        for r in rows:
            d = _as_dict(r)
            d["ok"] = bool(d.get("ok"))
            out.append(d)
        return out
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# signing / verification
# ---------------------------------------------------------------------------


def _to_bytes(v: str | bytes) -> bytes:
    return v if isinstance(v, bytes) else str(v).encode("utf-8")


def sign_body(secret: str | bytes, raw_body: str | bytes) -> str:
    """The ``X-Lifted-Signature`` header value for ``raw_body`` under ``secret``:
    ``"sha256=" + hex(HMAC-SHA256(secret, raw_body))``."""
    digest = hmac.new(_to_bytes(secret), _to_bytes(raw_body), hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_signature(secret: str | bytes, raw_body: str | bytes, header: str | None) -> bool:
    """Constant-time verify an ``X-Lifted-Signature`` header against ``raw_body``. Used by the
    SDK/docs example and by receivers to authenticate a delivery. A missing header or secret
    fails closed."""
    if not header or not secret:
        return False
    expected = sign_body(secret, raw_body)
    return hmac.compare_digest(expected, str(header).strip())


# ---------------------------------------------------------------------------
# delivery
# ---------------------------------------------------------------------------


def _build_envelope(event: str, payload: dict) -> dict:
    """The delivery body: ``{id, event, created, data}``. ``id`` is a unique event id shared by
    every subscription for this emit; ``created`` a Unix timestamp."""
    return {
        "id": "evt_" + uuid.uuid4().hex,
        "event": event,
        "created": int(time.time()),
        "data": payload or {},
    }


def _matching_subscriptions(owner_id: int, event: str) -> list[dict]:
    """Active subscriptions for ``owner_id`` that want ``event`` (matching resolved in Python so
    the wildcard/subset logic lives in exactly one place, :func:`_matches`)."""
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT * FROM sign_webhooks WHERE owner_account_id=? AND active=1",
            (int(owner_id),),
        ).fetchall()
    finally:
        conn.close()
    return [d for r in rows if _matches((d := _as_dict(r)).get("events") or ALL, event)]


def _record_delivery(
    webhook_id: int,
    event: str,
    status_code: int | None,
    ok: bool,
    attempt: int,
    response_ms: int | None,
    error: str,
) -> None:
    """Append one attempt to the delivery/audit log. Best-effort: a logging failure must never
    break delivery (which is itself best-effort)."""
    try:
        conn = db.connect()
        try:
            conn.execute(
                "INSERT INTO sign_webhook_deliveries"
                "(webhook_id,event,status_code,ok,attempt,created_at,response_ms,error)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (
                    int(webhook_id),
                    event,
                    status_code,
                    1 if ok else 0,
                    int(attempt),
                    time.time(),
                    response_ms,
                    (error or "")[:500],
                ),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 — the delivery log is telemetry; never fail delivery on it
        log.exception("webhook delivery-log write failed (webhook_id=%s)", webhook_id)


def _mark_result(webhook_id: int, ok: bool, status_code: int | None) -> None:
    """Fold a completed delivery into the subscription's health counters. On success: reset
    ``failure_count`` and stamp ``last_status``/``last_delivery_at``. On failure: increment
    ``failure_count`` and auto-disable once it reaches :data:`_DISABLE_AFTER`."""
    try:
        conn = db.connect()
        try:
            now = time.time()
            if ok:
                conn.execute(
                    "UPDATE sign_webhooks SET last_status=?, last_delivery_at=?, failure_count=0"
                    " WHERE id=?",
                    (status_code, now, int(webhook_id)),
                )
            else:
                cur = conn.execute(
                    "UPDATE sign_webhooks SET last_status=?, last_delivery_at=?,"
                    " failure_count=failure_count+1 WHERE id=? RETURNING failure_count",
                    (status_code, now, int(webhook_id)),
                )
                row = cur.fetchone()
                fails = int((_as_dict(row) or {}).get("failure_count") or 0) if row else 0
                if fails >= _DISABLE_AFTER:
                    conn.execute("UPDATE sign_webhooks SET active=0 WHERE id=?", (int(webhook_id),))
            conn.commit()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 — health bookkeeping must never break the signing flow
        log.exception("webhook health update failed (webhook_id=%s)", webhook_id)


def _deliver_sync(sub: dict, event: str, envelope: dict, attempts: int = _MAX_ATTEMPTS) -> dict:
    """POST ``envelope`` to one subscription with retry + backoff, logging every attempt and
    folding the outcome into the subscription's health counters. Fully self-contained and
    exception-safe: it returns a result dict and never raises, so a delivery failure can never
    propagate into a caller (the signing flow). Returns
    ``{webhook_id, ok, status_code, attempts, delivery_id, error}``.
    """
    webhook_id = int(sub["id"])
    result = {
        "webhook_id": webhook_id,
        "ok": False,
        "status_code": None,
        "attempts": 0,
        "delivery_id": "",
        "error": "",
    }
    try:
        raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        delivery_id = uuid.uuid4().hex
        result["delivery_id"] = delivery_id
        headers = {
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT,
            "X-Lifted-Event": event,
            "X-Lifted-Delivery": delivery_id,
            "X-Lifted-Signature": sign_body(sub["secret"], raw),
        }
        url = sub["url"]
        # SSRF guard: re-resolve + re-check the host immediately before delivery so a name that
        # was public at registration but now points at an internal address (DNS rebinding) is
        # refused. Raises ValueError → handled by the isolation boundary below; never signs.
        _assert_public_host(urlsplit(url).hostname or "")
        last_status: int | None = None
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False) as client:
            for attempt in range(1, max(1, attempts) + 1):
                result["attempts"] = attempt
                t0 = time.monotonic()
                try:
                    resp = client.post(url, content=raw, headers=headers)
                    ms = int((time.monotonic() - t0) * 1000)
                    last_status = resp.status_code
                    ok = 200 <= resp.status_code < 300
                    err = "" if ok else f"HTTP {resp.status_code}"
                    _record_delivery(webhook_id, event, resp.status_code, ok, attempt, ms, err)
                    if ok:
                        result.update(ok=True, status_code=resp.status_code, error="")
                        _mark_result(webhook_id, True, resp.status_code)
                        return result
                    result.update(status_code=resp.status_code, error=err)
                except httpx.HTTPError as e:
                    ms = int((time.monotonic() - t0) * 1000)
                    err = f"{type(e).__name__}: {e}"[:300]
                    _record_delivery(webhook_id, event, None, False, attempt, ms, err)
                    result["error"] = err
                if attempt < attempts:
                    time.sleep(min(_BACKOFF_BASE * (2 ** (attempt - 1)), _BACKOFF_CAP))
        _mark_result(webhook_id, False, last_status)
        return result
    except Exception as e:  # noqa: BLE001 — isolation boundary: a webhook error never escapes
        log.exception("webhook delivery crashed (webhook_id=%s)", webhook_id)
        result["error"] = f"{type(e).__name__}: {e}"[:300]
        try:
            _mark_result(webhook_id, False, result.get("status_code"))
        except Exception:  # noqa: BLE001
            pass
        return result


async def _deliver_async(sub: dict, event: str, envelope: dict) -> None:
    """Event-loop delivery: run the blocking :func:`_deliver_sync` in a worker thread so the
    loop is never blocked. Guarded — a delivery exception is logged, never surfaced."""
    try:
        await asyncio.to_thread(_deliver_sync, sub, event, envelope)
    except Exception:  # noqa: BLE001 — belt-and-suspenders; _deliver_sync already never raises
        log.exception("webhook async delivery failed (webhook_id=%s)", sub.get("id"))


def _dispatch(sub: dict, event: str, envelope: dict) -> None:
    """Fire-and-forget one subscription's delivery without blocking the caller.

    Uses ``asyncio.create_task`` when called on a running event loop; otherwise (the common
    case — :func:`emit` is invoked from an ``asyncio.to_thread`` worker inside the signing
    engine, where there is no running loop) it starts a daemon thread. Either way the caller
    returns immediately and a delivery error can never reach it.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None:
        loop.create_task(_deliver_async(sub, event, envelope))
    else:
        threading.Thread(
            target=_deliver_sync,
            args=(sub, event, envelope),
            name=f"webhook-{sub.get('id')}",
            daemon=True,
        ).start()


def emit(event: str, payload: dict, owner_account_id: int | None) -> int:
    """Fan ``event`` out to every active matching subscription for ``owner_account_id``.

    Called by the signing engine at each envelope transition. Returns the number of
    subscriptions scheduled (0 when the owner is unknown/None or has no matching
    subscription). **Never blocks and never raises** — deliveries run in the background and
    the whole body is guarded, so a webhook subsystem fault has zero effect on signing. Use
    :func:`deliver_now` for a synchronous, awaitable-free variant in tests.
    """
    try:
        if not owner_account_id or event not in EVENTS:
            return 0
        subs = _matching_subscriptions(int(owner_account_id), event)
        if not subs:
            return 0
        envelope = _build_envelope(event, payload)
        for sub in subs:
            _dispatch(sub, event, envelope)
        return len(subs)
    except Exception:  # noqa: BLE001 — isolation: emit must never perturb the signing flow
        log.exception("webhook emit failed (event=%s owner=%s)", event, owner_account_id)
        return 0


def deliver_now(
    event: str,
    payload: dict,
    owner_account_id: int,
    *,
    attempts: int = _MAX_ATTEMPTS,
) -> list[dict]:
    """Synchronous sibling of :func:`emit` for tests: deliver ``event`` to every active
    matching subscription in the calling thread and return the per-subscription result dicts
    (``_deliver_sync``'s output). Blocks until delivery completes — do not call on the request
    path; that's what :func:`emit` is for."""
    if not owner_account_id or event not in EVENTS:
        return []
    subs = _matching_subscriptions(int(owner_account_id), event)
    if not subs:
        return []
    envelope = _build_envelope(event, payload)
    return [_deliver_sync(sub, event, envelope, attempts=attempts) for sub in subs]


ensure_tables()
