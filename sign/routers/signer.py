"""Public signer surface — the tokenized signing experience.

* ``GET /sign/{token}``            — the standalone signer page (its JS reads the token from the URL
  and drives the token API below). Not the dashboard; a strict CSP + no-store.
* ``/api/sign/token/{token}/*``    — metadata, page images, challenge, consent, submit, decline,
  withdraw-consent, download. All token-scoped and public: the token IS the credential, so a
  sender access-lock challenge (DOB/SSN/passcode) gates document + page rendering until passed,
  and terminal/expired documents stop serving pages (revocation defeat).
* ``GET /api/sign/disclosure``     — canonical ERSD disclosure text + version.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, JSONResponse, Response

from ..http_helpers import WEB_DIR, _client_ip

router = APIRouter()


@router.get("/sign/{token}")
async def sign_page_html(token: str) -> FileResponse:
    """Standalone signer experience (not the dashboard) — the JS reads the token from the URL
    and drives /api/sign/token/*. Fonts are vendored (served from /static), so the page needs no
    external hosts; the global strict CSP applies."""
    return FileResponse(
        WEB_DIR / "sign.html",
        headers={
            "Cache-Control": "no-store, must-revalidate",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


@router.get("/api/sign/token/{token}")
async def sign_token_payload(token: str, req: Request) -> Any:
    from .. import esign

    pl = await asyncio.to_thread(
        esign.signing_payload, token, _client_ip(req), req.headers.get("user-agent", "")
    )
    # Gate the document/signing on a passed access-lock challenge (signing-page surface).
    if pl and pl.get("ok"):
        srow = await asyncio.to_thread(esign.signer_by_token_public, token)
        if (
            srow
            and (srow.get("challenge_type") or "none") != "none"
            and not srow.get("challenge_passed_at")
        ):
            return {
                "ok": False,
                "challenge_required": True,
                "challenge_type": srow["challenge_type"],
                "challenge_prompt": srow.get("challenge_prompt") or "",
            }
    return pl or JSONResponse({"error": "invalid or expired link"}, status_code=404)


@router.post("/api/sign/token/{token}/challenge")
async def sign_token_challenge(token: str, req: Request) -> dict[str, Any]:
    """The signer passes the sender access-lock challenge on the signing page. Public (token-scoped).
    On success marks the signer's challenge_passed_at so the doc unlocks."""
    from .. import esign, esign_access

    b = await req.json()
    srow = await asyncio.to_thread(esign.signer_by_token_public, token)
    if not srow:
        # Uniform shape — don't reveal whether the token exists.
        return {"ok": False, "attempts_remaining": 5}
    agr = await asyncio.to_thread(esign.get_agreement, int(srow["agreement_id"]))
    env_id = (agr or {}).get("envelope_id", "")
    res = await asyncio.to_thread(
        esign_access.verify_challenge,
        env_id,
        int(srow["id"]),
        b.get("value", ""),
        _client_ip(req),
    )
    # NOTE: esign_access.verify_challenge already persists challenge_passed_at on success
    # (single authoritative writer) — don't double-write it here.
    return res


@router.get("/api/sign/token/{token}/page/{n:int}")
async def sign_token_page(token: str, n: int):
    from .. import db, esign

    conn = db.connect()
    try:
        row = conn.execute(
            "SELECT agreement_id FROM agreement_signers WHERE token=?", (token,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return JSONResponse({"error": "invalid"}, status_code=404)
    # A leaked token must not render the document image until the sender access-lock is passed
    # (the metadata route gates this; the page-image route must too).
    srow = await asyncio.to_thread(esign.signer_by_token_public, token)
    if (
        srow
        and (srow.get("challenge_type") or "none") != "none"
        and not srow.get("challenge_passed_at")
    ):
        return JSONResponse({"error": "challenge required"}, status_code=403)
    # Terminal-status/expiry gate: a voided/cancelled/declined or expired document must not keep
    # serving its page images (revocation defeat) — mirror signing_payload's gate here too.
    blocked = await asyncio.to_thread(esign.signer_render_blocked, token)
    if blocked == "invalid":
        return JSONResponse({"error": "invalid"}, status_code=404)
    if blocked:
        return JSONResponse({"error": blocked}, status_code=410)
    png = await asyncio.to_thread(esign.page_render, row["agreement_id"], n)
    return Response(content=png or b"", media_type="image/png")


@router.post("/api/sign/token/{token}/submit")
async def sign_token_submit(token: str, req: Request) -> dict[str, Any]:
    from .. import esign

    b = await req.json()
    res = await asyncio.to_thread(
        esign.submit_signature,
        token,
        b.get("values", {}),
        bool(b.get("consent")),
        _client_ip(req),
        req.headers.get("user-agent", ""),
        b.get("field_meta") or {},
    )
    return res


@router.post("/api/sign/token/{token}/consent")
async def sign_token_consent(token: str, req: Request) -> dict[str, Any]:
    """ESIGN consent capture BEFORE signing (consumer flows). Idempotent."""
    from .. import esign

    b = await req.json()
    return await asyncio.to_thread(
        esign.record_consent,
        token,
        b,
        _client_ip(req),
        req.headers.get("user-agent", ""),
    )


@router.post("/api/sign/token/{token}/withdraw-consent")
async def sign_token_withdraw(token: str, req: Request) -> dict[str, Any]:
    from .. import esign

    try:
        b = await req.json()
    except Exception:
        b = {}
    return await asyncio.to_thread(
        esign.withdraw_consent,
        token,
        b.get("reason", ""),
        _client_ip(req),
        req.headers.get("user-agent", ""),
    )


@router.get("/api/sign/token/{token}/download")
async def sign_token_download(token: str):
    """Signer-facing executed-PDF download — only after completion, token-scoped."""
    from .. import esign

    res = await asyncio.to_thread(esign.signer_download, token)
    if not res.get("ok"):
        return JSONResponse({"error": res.get("error", "not found")}, status_code=404)
    return Response(
        content=res["bytes"],
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{res["filename"]}"'},
    )


@router.post("/api/sign/token/{token}/decline")
async def sign_token_decline(token: str, req: Request) -> dict[str, Any]:
    from .. import esign

    b = await req.json()
    return await asyncio.to_thread(
        esign.decline,
        token,
        b.get("reason", ""),
        _client_ip(req),
        req.headers.get("user-agent", ""),
    )


@router.get("/api/sign/disclosure")
async def sign_disclosure(consumer: int = 0, version: str = "latest") -> dict[str, Any]:
    """Canonical ERSD disclosure text + version (public). Single source of disclosure truth so
    the signer page render and the certificate embed use identical hashed bytes."""
    from .. import esign_disclosure

    return esign_disclosure.disclosure(bool(consumer))


