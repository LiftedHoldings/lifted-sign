"""``/api/mysign/webhooks/*`` — owner-scoped management of outbound webhook subscriptions.

Every route authenticates with the shared ``_require_sign_acct`` gate (cookie session OR
developer Bearer key) and scopes strictly to the calling account. A ``{wid}`` that belongs to
another owner resolves through ``webhooks.get_webhook_owned`` and returns **404, never 403** —
a wrong id is not an existence oracle (same IDOR posture as ``_require_owned`` for agreements).

Routes:
    * ``GET  /api/mysign/webhooks``               list this account's subscriptions
    * ``POST /api/mysign/webhooks``               create one (``{url, events?}``)
    * ``DELETE /api/mysign/webhooks/{wid}``       delete one
    * ``POST /api/mysign/webhooks/{wid}/rotate``  rotate the signing secret
    * ``GET  /api/mysign/webhooks/{wid}/deliveries``  recent delivery/audit log
    * ``POST /api/mysign/webhooks/{wid}/test``    send a sample ``envelope.sent`` ping
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..http_helpers import _require_sign_acct

router = APIRouter()


@router.get("/api/mysign/webhooks")
async def webhooks_list(req: Request) -> Any:
    """Every webhook subscription owned by the calling account."""
    from .. import webhooks

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    out = await asyncio.to_thread(webhooks.list_webhooks, acct["id"])
    return {"webhooks": out, "events": list(webhooks.EVENTS)}


@router.post("/api/mysign/webhooks")
async def webhooks_create(req: Request) -> Any:
    """Create a subscription. Body: ``{url, events?}`` — ``events`` is a list (or comma string);
    omit / ``["*"]`` for all events. Returns the created row incl. its ``whsec_`` secret."""
    from .. import webhooks

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    try:
        body = await req.json()
    except Exception:  # noqa: BLE001 — malformed/empty JSON body → clean 400
        return JSONResponse({"ok": False, "error": "invalid JSON body"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"ok": False, "error": "invalid body"}, status_code=400)
    url = (body.get("url") or "").strip()
    if not url:
        return JSONResponse({"ok": False, "error": "url required"}, status_code=400)
    try:
        row = await asyncio.to_thread(webhooks.create_webhook, acct["id"], url, body.get("events"))
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    return {"ok": True, "webhook": row}


@router.delete("/api/mysign/webhooks/{wid:int}")
async def webhooks_delete(wid: int, req: Request) -> Any:
    """Delete an owned subscription (404 cross-owner; idempotent)."""
    from .. import webhooks

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    ok = await asyncio.to_thread(webhooks.delete_webhook, acct["id"], wid)
    if not ok:
        return JSONResponse({"error": "not found"}, status_code=404)  # 404, not 403 (no oracle)
    return {"ok": True}


@router.post("/api/mysign/webhooks/{wid:int}/rotate")
async def webhooks_rotate(wid: int, req: Request) -> Any:
    """Rotate an owned subscription's signing secret (invalidates the old one)."""
    from .. import webhooks

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    row = await asyncio.to_thread(webhooks.rotate_secret, acct["id"], wid)
    if row is None:
        return JSONResponse({"error": "not found"}, status_code=404)  # 404, not 403 (no oracle)
    return {"ok": True, "webhook": row}


@router.get("/api/mysign/webhooks/{wid:int}/deliveries")
async def webhooks_deliveries(wid: int, req: Request, limit: int = 50) -> Any:
    """Recent delivery/audit log for an owned subscription (newest first)."""
    from .. import webhooks

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    rows = await asyncio.to_thread(webhooks.recent_deliveries, acct["id"], wid, limit)
    if rows is None:
        return JSONResponse({"error": "not found"}, status_code=404)  # 404, not 403 (no oracle)
    return {"deliveries": rows}


@router.post("/api/mysign/webhooks/{wid:int}/test")
async def webhooks_test(wid: int, req: Request) -> Any:
    """Send a sample ``envelope.sent`` ping to an owned subscription so the operator can confirm
    their receiver + signature verification before relying on live events. Scheduled in the
    background exactly like a real emit (never blocks); the result shows in the delivery log."""
    from .. import webhooks

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    row = await asyncio.to_thread(webhooks.get_webhook_owned, acct["id"], wid)
    if row is None:
        return JSONResponse({"error": "not found"}, status_code=404)  # 404, not 403 (no oracle)
    payload = {"agreement_id": None, "status": "test", "ping": True}
    scheduled = await asyncio.to_thread(
        webhooks.emit, webhooks.EVENT_ENVELOPE_SENT, payload, acct["id"]
    )
    return {"ok": True, "scheduled": scheduled}
