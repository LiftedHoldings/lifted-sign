"""``/api/sign-ops/*`` — the operator console.

Operator-only routes over the self-serve accounts: list every account + doc counts, a summary
(total/active/suspended + hypothetical MRR), suspend/unsuspend, and a test-tenant purge.

In the host application these were reachable only on the admin host behind the Google admin gate.
This standalone build has no admin gate, so authorization is enforced HERE: the caller must present
a valid sign session whose email is in ``config.ADMIN_EMAILS``. With ADMIN_EMAILS empty (the
default) the entire console is closed — every route returns 403, so a fresh self-host never exposes
an unauthenticated operator surface.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .. import config
from ..http_helpers import _sign_acct

router = APIRouter()


def _require_operator(req: Request):
    """Return (account, None) if the caller is a signed-in operator (email in ADMIN_EMAILS), else
    (None, 403-response). 403 (not 401) — the console simply isn't available to non-operators, and
    ADMIN_EMAILS is authoritative, never a hardcoded identity."""
    acct = _sign_acct(req)
    email = (acct or {}).get("email", "").strip().lower()
    if not acct or not config.ADMIN_EMAILS or email not in config.ADMIN_EMAILS:
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    return acct, None


@router.get("/api/sign-ops/accounts")  # every sign account + owner-scoped doc counts
async def sign_ops_accounts(req: Request) -> Any:
    from .. import sign_ops

    _acct, err = _require_operator(req)
    if err:
        return err
    return {"accounts": await asyncio.to_thread(sign_ops.list_accounts)}


@router.get("/api/sign-ops/summary")  # total/active/suspended + docs + hypothetical MRR
async def sign_ops_summary(req: Request) -> Any:
    from .. import sign_ops

    _acct, err = _require_operator(req)
    if err:
        return err
    return await asyncio.to_thread(sign_ops.summary)


@router.post("/api/sign-ops/accounts/{aid}/status")  # suspend / unsuspend a sign account
async def sign_ops_set_status(aid: int, req: Request) -> Any:
    from .. import sign_ops

    _acct, err = _require_operator(req)
    if err:
        return err
    try:
        b = await req.json()
    except Exception:
        b = {}
    suspended = bool((b or {}).get("suspended"))
    res = await asyncio.to_thread(sign_ops.set_status, aid, suspended)
    if not res.get("ok"):
        return JSONResponse(res, status_code=404)
    return res


@router.post("/api/sign-ops/purge-test")  # clear leftover isotest-*/p2test-* test tenants
async def sign_ops_purge_test(req: Request) -> Any:
    from .. import sign_ops

    _acct, err = _require_operator(req)
    if err:
        return err
    return await asyncio.to_thread(sign_ops.purge_test_rows)
