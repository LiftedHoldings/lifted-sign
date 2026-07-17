"""``/api/mysign/*`` — the multi-tenant product API.

Every route is account-scoped: authentication is the shared ``_require_sign_acct`` gate (cookie
session OR developer Bearer key), and every ``{aid}`` route funnels through ``_require_owned`` —
the single IDOR choke-point that returns 404 (never 403, no existence oracle) for a document the
account doesn't own. Draft-only mutations are gated inside the ``esign`` engine, not here.

Also hosts the account-SECURITY routes (SMS 2FA enroll/disable, billing), which use the
cookie-ONLY ``_require_sign_cookie`` gate so a shared/logged developer API key can never change
an account's security config.
"""

from __future__ import annotations

import asyncio
import re as _re
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from ..http_helpers import (
    _pdf_upload_error,
    _require_owned,
    _require_sign_acct,
    _require_sign_cookie,
    _sign_acct,
    _sign_public_base,
)

router = APIRouter()


# --- account 2FA (SMS) — cookie-only, never a Bearer key --------------------
@router.post("/api/mysign/2fa/phone/start")
async def mysign_2fa_phone_start(req: Request) -> Any:
    """Send a Twilio-Verify code to a phone the account wants to enroll for SMS 2FA."""
    from .. import db, sign_portal_auth

    acct, err = _require_sign_cookie(req)  # account security: cookie-only, never a Bearer key
    if err:
        return err
    b = await req.json()
    phone = (b.get("phone") or "").strip()
    if not sign_portal_auth.valid_phone(phone):
        return JSONResponse({"ok": False, "error": "invalid_phone"}, status_code=400)
    if not await asyncio.to_thread(
        db.auth_rate_allowed, f"signacct:phoneenroll:{acct['id']}", 5, 900
    ):
        return JSONResponse({"ok": False, "error": "rate_limited"}, status_code=429)
    ok = await asyncio.to_thread(sign_portal_auth.send_phone_code, phone)
    return JSONResponse({"ok": bool(ok)}, status_code=200 if ok else 502)


@router.post("/api/mysign/2fa/phone/confirm")
async def mysign_2fa_phone_confirm(req: Request) -> Any:
    """Verify the enrollment code → store the phone + arm SMS 2FA at login."""
    from .. import sign_accounts, sign_portal_auth

    acct, err = _require_sign_cookie(req)  # account security: cookie-only, never a Bearer key
    if err:
        return err
    b = await req.json()
    phone = (b.get("phone") or "").strip()
    if not await asyncio.to_thread(sign_portal_auth.check_phone_code, phone, b.get("code", "")):
        return JSONResponse({"ok": False, "error": "invalid_code"}, status_code=400)
    await asyncio.to_thread(
        sign_accounts.set_phone_2fa, acct["id"], sign_portal_auth._e164(phone), True
    )
    updated = await asyncio.to_thread(sign_accounts.account_by_id, acct["id"])
    return JSONResponse({"ok": True, "account": sign_accounts.public_view(updated)})


@router.post("/api/mysign/2fa/disable/challenge")
async def mysign_2fa_disable_challenge(req: Request) -> Any:
    """Step-up: send an SMS OTP to the enrolled phone so the account holder can confirm turning
    SMS 2FA off (mirrors the login SMS challenge — disabling a second factor must prove possession
    of it, not just a live session)."""
    from .. import sign_portal_auth

    acct, err = _require_sign_cookie(req)  # account security: cookie-only, never a Bearer key
    if err:
        return err
    if not acct.get("sms_2fa"):
        return JSONResponse({"ok": True})  # nothing enrolled — no challenge needed
    sent = await asyncio.to_thread(sign_portal_auth.send_login_sms, acct)
    return JSONResponse({"ok": bool(sent)})


@router.post("/api/mysign/2fa/disable")
async def mysign_2fa_disable(req: Request) -> Any:
    """Disable SMS 2FA. Requires a fresh SMS OTP (from /disable/challenge) — a session alone must
    not be able to strip the second factor (parity with the TOTP-disable path)."""
    from .. import sign_accounts, sign_portal_auth

    acct, err = _require_sign_cookie(req)  # account security: cookie-only, never a Bearer key
    if err:
        return err
    if not acct.get("sms_2fa"):
        # already off — idempotent no-op, no code required
        updated = await asyncio.to_thread(sign_accounts.account_by_id, acct["id"])
        return JSONResponse({"ok": True, "account": sign_accounts.public_view(updated)})
    b = await req.json()
    code = (b.get("code") or "").strip()
    ok = await asyncio.to_thread(sign_portal_auth.verify_login_sms, acct["id"], code)
    if not ok:
        return JSONResponse({"ok": False, "error": "invalid_code"}, status_code=400)
    await asyncio.to_thread(sign_accounts.disable_sms_2fa, acct["id"])
    updated = await asyncio.to_thread(sign_accounts.account_by_id, acct["id"])
    return JSONResponse({"ok": True, "account": sign_accounts.public_view(updated)})


# --- agreements -------------------------------------------------------------
@router.get("/api/mysign/agreements")
async def mysign_list(req: Request, limit: int = 50, offset: int = 0) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    out = await asyncio.to_thread(esign.list_agreements_for_owner, acct["id"], limit, offset)
    total = await asyncio.to_thread(esign.count_agreements_for_owner, acct["id"])
    return {
        "agreements": out,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + len(out) < total,
    }


@router.post("/api/mysign/agreements")
async def mysign_create(req: Request) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    form = await req.form()
    up = form.get("file")
    if up is None:
        return JSONResponse({"ok": False, "error": "file required"}, status_code=400)
    raw = await up.read()
    name = form.get("name") or getattr(up, "filename", "Agreement")
    if err := _pdf_upload_error(raw):
        return JSONResponse({"ok": False, "error": err}, status_code=400)
    aid = await asyncio.to_thread(
        esign.create_agreement, name, raw, "", acct["email"], None, acct["id"]
    )
    return {"ok": True, "id": aid}


# --- reusable TEMPLATES (owner-scoped: a tenant sees/uses ONLY its own) ------
@router.get("/api/mysign/templates")
async def mysign_templates_list(req: Request) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    out = await asyncio.to_thread(esign.list_templates_for_owner, acct["id"])
    return {"templates": out}


@router.get("/api/mysign/templates/{tid:int}")
async def mysign_templates_get(tid: int, req: Request) -> Any:
    """A single OWNED template, incl. its fields — an API caller reads the prefill fields
    (prefill/prompt/field_key) here to know what ``answers`` to pass to /use. 404 cross-tenant."""
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    t = await asyncio.to_thread(esign.get_template_owned, tid, acct["id"])
    if not t:
        return JSONResponse({"error": "not found"}, status_code=404)  # 404, not 403 (no oracle)
    return {"template": t}


@router.post("/api/mysign/templates")
async def mysign_templates_create(req: Request) -> Any:
    """Save a template. 'Save as template' from an existing OWNED agreement (agreement_id), or from
    an explicit layout. owner_account_id is stamped from the session — create_template owner-gates
    the source agreement so a tenant can't snapshot another tenant's document."""
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    try:
        b = await req.json()
    except Exception:
        b = {}
    src = b.get("agreement_id") or b.get("source_agreement_id")
    res = await asyncio.to_thread(
        esign.create_template,
        (b.get("name") or "").strip() or None,
        int(src) if src else None,
        b.get("layout") or None,
        acct["email"],
        acct["id"],
    )
    return JSONResponse(res, status_code=200 if res.get("ok") else 400)


@router.post("/api/mysign/templates/{tid:int}/archive")
async def mysign_templates_archive(tid: int, req: Request) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    ok = await asyncio.to_thread(esign.archive_template_owned, tid, acct["id"])  # owner-scoped
    if not ok:
        return JSONResponse({"error": "not found"}, status_code=404)  # 404, not 403 (no oracle)
    return {"ok": True}


@router.post("/api/mysign/templates/{tid:int}/use")
async def mysign_templates_use(tid: int, req: Request) -> Any:
    """Instantiate a new DRAFT from an OWNED template. get_template_owned is enforced inside
    instantiate_agreement_from_template; a cross-tenant tid returns 404."""
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    try:
        b = await req.json()
    except Exception:
        b = {}
    answers = b.get("answers") if isinstance(b.get("answers"), dict) else None
    res = await asyncio.to_thread(
        esign.instantiate_agreement_from_template,
        tid,
        b.get("recipients") or None,
        (b.get("name") or "").strip() or None,
        acct["email"],
        acct["id"],
        answers,
    )
    if not res.get("ok"):
        code = 404 if res.get("error") == "template not found" else 400
        return JSONResponse(res, status_code=code)
    return res


@router.post("/api/mysign/agreements/{aid:int}/detect")
async def mysign_detect_prefill(aid: int, req: Request) -> Any:
    """Smart-detect prefill fields ({{tokens}} + common labels) in an OWNED draft's PDF and add any
    new ones. Owner-scoped (get_agreement_owned inside autodetect_prefill_owned). Zero-cost/local."""
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    res = await asyncio.to_thread(esign.autodetect_prefill_owned, aid, acct["id"])
    # Owner-miss = 404 (no oracle); business rejections (locked/no_source) return in-body with
    # HTTP 200, mirroring the sibling place-fields convention.
    if res.get("error") == "not_found":
        return JSONResponse({"error": "not found"}, status_code=404)
    return res


@router.get("/api/mysign/agreements/{aid:int}")
async def mysign_get(aid: int, req: Request) -> Any:
    acct, err = await _require_sign_acct(req)
    if err:
        return err
    agr, nf = await _require_owned(aid, acct, full=True)
    return nf or agr


@router.get("/api/mysign/agreements/{aid:int}/pages")
async def mysign_pages(aid: int, req: Request) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    pages = await asyncio.to_thread(esign.page_info, aid)
    return {"pages": pages, "count": len(pages)}


@router.get("/api/mysign/agreements/{aid:int}/page/{n:int}")
async def mysign_page(aid: int, n: int, req: Request):
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    png = await asyncio.to_thread(esign.page_render, aid, n)
    if not png:
        return JSONResponse({"error": "no page"}, status_code=404)
    return Response(content=png, media_type="image/png")


@router.get("/api/mysign/agreements/{aid:int}/pdf")
async def mysign_pdf(aid: int, req: Request):
    """Raw presented PDF bytes for the editor's PDF.js high-fidelity canvas — same owner
    choke-point (_require_sign_acct → _require_owned) and same source (presented_bytes) as the
    PNG page render, so canvas and PNG stay pixel-identical."""
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    data = await asyncio.to_thread(esign.presented_bytes, aid)
    if not data:
        return JSONResponse({"error": "no document"}, status_code=404)
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Cache-Control": "no-store"},
    )


@router.post("/api/mysign/agreements/{aid:int}/signers")
async def mysign_signers(aid: int, req: Request) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    b = await req.json()
    res = await asyncio.to_thread(esign.set_signers, aid, b.get("signers", []))
    if isinstance(res, dict):
        return res
    return {"ok": True, "signers": res}


@router.post("/api/mysign/agreements/{aid:int}/order-mode")
async def mysign_order_mode(aid: int, req: Request) -> Any:
    """Set signing order: 'sequential' (route one signer at a time) or 'parallel' (all at once).
    Owner-scoped + draft-only; send() enforces the chosen order."""
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    b = await req.json()
    return await asyncio.to_thread(
        esign.set_order_mode_owned, aid, acct["id"], str(b.get("mode") or "")
    )


@router.post("/api/mysign/agreements/{aid:int}/fields")
async def mysign_fields(aid: int, req: Request) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    b = await req.json()
    # place_fields resolves anchor-text / points / normalized placement + signer-by-email, then
    # persists (fail-closed). Back-compat: raw normalized fields + signer_id pass straight through.
    res = await asyncio.to_thread(esign.place_fields, aid, b.get("fields", []))
    return res


# --- draft page ops (reorder / rotate / delete / add) -----------------------
# Each op goes through _require_sign_acct → _require_owned (the same IDOR choke-point as
# set_fields — a tenant hitting another's aid gets 404 before any file is touched) and the
# DRAFT-ONLY gate lives inside the esign.* function (past-draft ⇒ "locked").
def _pages_status(res: dict) -> int:
    """Map a page-op result to an HTTP status: 200 ok, 409 when locked (already sent),
    400 for any other validation error (bad page/order/rotation/not a PDF)."""
    if res.get("ok"):
        return 200
    return 409 if str(res.get("error", "")).startswith("locked") else 400


@router.post("/api/mysign/agreements/{aid:int}/pages/reorder")
async def mysign_pages_reorder(aid: int, req: Request) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    b = await req.json()
    res = await asyncio.to_thread(esign.reorder_pages, aid, b.get("order", []))
    return JSONResponse(res, status_code=_pages_status(res))


@router.post("/api/mysign/agreements/{aid:int}/pages/rotate")
async def mysign_pages_rotate(aid: int, req: Request) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    b = await req.json()
    res = await asyncio.to_thread(
        esign.rotate_page, aid, int(b.get("page", -1)), int(b.get("deg", 0))
    )
    return JSONResponse(res, status_code=_pages_status(res))


@router.post("/api/mysign/agreements/{aid:int}/pages/delete")
async def mysign_pages_delete(aid: int, req: Request) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    b = await req.json()
    res = await asyncio.to_thread(esign.delete_page, aid, int(b.get("page", -1)))
    return JSONResponse(res, status_code=_pages_status(res))


@router.post("/api/mysign/agreements/{aid:int}/pages/add")
async def mysign_pages_add(aid: int, req: Request) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    form = await req.form()
    up = form.get("file")
    if up is None:
        return JSONResponse({"ok": False, "error": "file required"}, status_code=400)
    raw = await up.read()
    if err := _pdf_upload_error(raw):
        return JSONResponse({"ok": False, "error": err}, status_code=400)
    res = await asyncio.to_thread(esign.add_pages, aid, raw)
    return JSONResponse(res, status_code=_pages_status(res))


@router.post("/api/mysign/agreements/{aid:int}/redact")
async def mysign_redact(aid: int, req: Request) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    b = await req.json()
    res = await asyncio.to_thread(esign.redact_regions, aid, b.get("regions", []))
    return JSONResponse(res, status_code=_pages_status(res))


@router.delete("/api/mysign/agreements/{aid:int}")
async def mysign_delete(aid: int, req: Request) -> Any:
    """Delete a DRAFT the account owns (sent/completed are legal records → void only). Same
    owner choke-point as the other mysign routes; 404 unowned, 409 if already sent."""
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    res = await asyncio.to_thread(esign.delete_draft_owned, aid, acct["id"])
    code = 200 if res.get("ok") else (409 if res.get("error") == "locked" else 404)
    return JSONResponse(res, status_code=code)


@router.post("/api/mysign/agreements/{aid:int}/text")
async def mysign_add_text(aid: int, req: Request) -> Any:
    """Burn author-typed text into the draft PDF (Add-text tool). Same owner choke-point
    and draft-gate as /redact; 409 once sent, 400 on any malformed/unsupported item."""
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    b = await req.json()
    res = await asyncio.to_thread(esign.add_texts, aid, b.get("items", []))
    return JSONResponse(res, status_code=_pages_status(res))


@router.get("/api/mysign/agreements/{aid:int}/spans")
async def mysign_spans(aid: int, req: Request) -> Any:
    """Editable text runs on page N (for click-to-edit-in-place). Owner-gated twin of the
    public signer /text route — same _require_sign_acct → _require_owned IDOR choke-point
    (404 for non-owner). Reading spans is allowed on any status; editing them is draft-gated."""
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    try:
        page = int(req.query_params.get("page", 0))
    except (TypeError, ValueError):
        page = 0
    spans = await asyncio.to_thread(esign.page_spans, aid, page)
    return {"ok": True, "spans": spans}


@router.post("/api/mysign/agreements/{aid:int}/edit-text")
async def mysign_edit_text(aid: int, req: Request) -> Any:
    """Replace existing text runs IN PLACE on the draft PDF (Edit-text tool). Same owner
    choke-point and draft-gate as /text and /redact; 409 once sent, 400 on any refusable item
    (rotated / no_run / too_long / bad bbox / unsupported)."""
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    b = await req.json()
    res = await asyncio.to_thread(esign.edit_texts, aid, b.get("items", []))
    return JSONResponse(res, status_code=_pages_status(res))


@router.post("/api/mysign/agreements/{aid:int}/send")
async def mysign_send(aid: int, req: Request) -> Any:
    from .. import esign, sign_accounts

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    # Server-side paywall — a canceled/suspended account cannot dispatch (no email, no status
    # change). This is BEFORE esign.send, so no invite goes out.
    if not await asyncio.to_thread(sign_accounts.can_send, acct["id"]):
        return JSONResponse(
            {"ok": False, "error": "subscription_inactive", "billing": True}, status_code=403
        )
    # Email verification gate: a password account must confirm its email before it can send
    # documents (blocks squatting/spam on an unverified address). Google accounts are pre-verified.
    if not sign_accounts.is_email_verified(acct):
        return JSONResponse({"ok": False, "error": "email_unverified"}, status_code=403)
    try:
        body = await req.json()
    except Exception:
        body = {}
    if body.get("message") is not None:
        await asyncio.to_thread(esign.update_message, aid, body["message"])
    res = await asyncio.to_thread(esign.send, aid, _sign_public_base())
    return res


@router.post("/api/mysign/agreements/{aid:int}/remind")
async def mysign_remind(aid: int, req: Request) -> Any:
    from .. import esign, sign_accounts

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    if not await asyncio.to_thread(sign_accounts.can_send, acct["id"]):
        return JSONResponse(
            {"ok": False, "error": "subscription_inactive", "billing": True}, status_code=403
        )
    if not sign_accounts.is_email_verified(acct):
        return JSONResponse({"ok": False, "error": "email_unverified"}, status_code=403)
    return await asyncio.to_thread(esign.remind, aid, _sign_public_base())


@router.post("/api/mysign/agreements/{aid:int}/void")
async def mysign_void(aid: int, req: Request) -> Any:
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    _, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    try:
        b = await req.json()
    except Exception:
        b = {}
    reason = str(b.get("reason") or "")  # recorded on the voided audit event
    return {"ok": await asyncio.to_thread(esign.void, aid, reason)}


@router.get("/api/mysign/agreements/{aid:int}/download")
async def mysign_download(aid: int, req: Request):
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    agr, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    data = await asyncio.to_thread(esign.executed_bytes, aid)
    if not data:
        return JSONResponse({"error": "no document"}, status_code=404)
    base = _re.sub(r"\.pdf$", "", agr.get("name", "") or "", flags=_re.I)
    base = _re.sub(r'[\\/:*?"<>|\r\n]+', "", base).strip() or f"agreement-{aid}"
    suffix = "-SIGNED" if agr.get("status") == "completed" else ""
    fn = f"{base}{suffix}.pdf"[:90]
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{fn}"'},
    )


@router.get("/api/mysign/agreements/{aid:int}/certificate")
async def mysign_certificate(aid: int, req: Request):
    from .. import esign

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    agr, nf = await _require_owned(aid, acct)
    if nf:
        return nf
    data = await asyncio.to_thread(esign.certificate_bytes, aid)
    if not data:
        return JSONResponse({"error": "not completed"}, status_code=404)
    base = _re.sub(r"\.pdf$", "", agr.get("name", "") or "", flags=_re.I)
    base = _re.sub(r'[\\/:*?"<>|\r\n]+', "", base).strip() or f"agreement-{aid}"
    fn = f"{base}-CERTIFICATE.pdf"[:90]
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{fn}"'},
    )


@router.get("/api/mysign/account")
async def mysign_account(req: Request) -> Any:
    from .. import esign, sign_accounts

    acct, err = await _require_sign_acct(req)
    if err:
        return err
    view = sign_accounts.public_view(acct)
    view["agreement_count"] = await asyncio.to_thread(esign.count_agreements_for_owner, acct["id"])
    return {"account": view}


# --- developer API-key management (session-authed ONLY — no minting a key with a key) -----
@router.get("/api/mysign/api-keys")
async def mysign_api_keys_list(req: Request) -> Any:
    from .. import sign_api_keys

    acct = _sign_acct(req)  # cookie session only (not Bearer): key management needs the human
    if not acct:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    keys = await asyncio.to_thread(sign_api_keys.list_for_account, acct["id"])
    return {"keys": keys}


@router.post("/api/mysign/api-keys")
async def mysign_api_keys_create(req: Request) -> Any:
    from .. import sign_api_keys

    acct = _sign_acct(req)
    if not acct:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        b = await req.json()
    except Exception:
        b = {}
    raw, meta = await asyncio.to_thread(
        sign_api_keys.issue, acct["id"], str(b.get("label") or ""), str(b.get("mode") or "live")
    )
    # the raw key is returned exactly ONCE — the client must show + store it now
    return {"ok": True, "key": raw, "meta": meta}


@router.post("/api/mysign/api-keys/{kid:int}/revoke")
async def mysign_api_keys_revoke(kid: int, req: Request) -> Any:
    from .. import sign_api_keys

    acct = _sign_acct(req)
    if not acct:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    ok = await asyncio.to_thread(sign_api_keys.revoke, kid, acct["id"])  # owner-scoped
    return {"ok": ok}


@router.post("/api/mysign/account/billing/activate")
async def mysign_billing_activate(req: Request) -> Any:
    from .. import sign_accounts

    acct, err = _require_sign_cookie(req)  # account/billing: cookie-only, never a Bearer key
    if err:
        return err
    # BILLING SEAM (deferred). Re-affirms an already-active account only (no charge, no
    # canceled→active). Mass-assignment safe — the request body is ignored entirely.
    res = await asyncio.to_thread(sign_accounts.activate_subscription, acct["id"])
    if not res.get("ok"):
        return JSONResponse(res, status_code=402)
    return res
