"""Envelope return-view — proven-identity signer session (``/envelope`` + ``/api/envelope/*``).

A returning signer proves identity via Google email-match OR an emailed OTP, which mints a
short-lived ``__Host-ls_env`` cookie scoped to ONE ``{env_id, signer_id}``. Every ``/api/envelope``
call re-authorizes from the signed token (never the path/body), a sender access-lock challenge is a
second gate after identity, and cross-party PII (other signers' emails/IPs) is masked or withheld.

Google OAuth for this flow uses a DEDICATED redirect (``/api/envelope/auth/callback``); the
login-URL + code-exchange delegate to the sign-owned ``hub_auth`` OAuth engine (env-configured,
degrades cleanly when Google isn't set up), with a redirect_uri distinct from the sender-login one.
"""

from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response

from .. import config
from ..http_helpers import (
    OAUTH_STATE_TTL,
    WEB_DIR,
    _client_ip,
    _new_oauth_state,
    _oauth_state_ok,
)

router = APIRouter()

ENV_STATE_COOKIE = config.cookie_name("ls_env_state")
ENV_NONCE_COOKIE = config.cookie_name("ls_env_nonce")
_ENV_TIMELINE_LABELS = {
    "created": "Created",
    "sent": "Sent for signature",
    "emailed": "Invitation emailed",
    "viewed": "Document viewed",
    "signer_authenticated": "Signer authenticated",
    "econsent_accepted": "E-sign consent accepted",
    "records_access_demonstrated": "Records access demonstrated",
    "signature_adopted": "Signature adopted",
    "field_signed": "Field signed",
    "signed": "Signed",
    "doc_frozen": "Document frozen",
    "doc_sealed": "Document sealed",
    "completed": "Completed",
    "completed_copy_delivered": "Completed copy delivered",
    "declined": "Declined",
    "econsent_withdrawn": "E-sign consent withdrawn",
    "voided": "Voided",
    "reminded": "Reminder sent",
    "access_challenge_passed": "Identity check passed",
    "access_challenge_failed": "Identity check failed",
    "access_challenge_locked": "Identity check locked",
    "access_challenge_configured": "Identity check configured",
    "envelope_access_verified": "Envelope access verified",
    "envelope_viewed": "Envelope viewed",
}


# --- Google OAuth for the envelope callback (dedicated redirect_uri) ---------
def _env_redirect_uri(req: Request) -> str:
    """Dedicated Google callback for the envelope flow (must be registered in the Google console)."""
    base = (config.local().get("esign_public_url") or str(req.base_url)).rstrip("/")
    return f"{base}/api/envelope/auth/callback"


# --- small helpers ----------------------------------------------------------
def _mask_email_display(email: str) -> str:
    e = (email or "").strip()
    if "@" not in e:
        return "••••" if e else ""
    local, _, domain = e.partition("@")
    head = local[0] if local else ""
    return f"{head}••••@{domain}"


def _set_env_cookie(resp, tok: str) -> None:
    from .. import esign_access

    resp.set_cookie(
        esign_access.COOKIE,
        tok,
        max_age=esign_access.ENV_SESSION_TTL,
        httponly=True,
        secure=config.cookie_secure(),
        samesite="strict",
    )


def _envelope_error_page(msg: str):
    safe = (msg or "").replace("<", "&lt;").replace(">", "&gt;")
    html = (
        "<!doctype html><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>Lifted Sign</title><body style='font-family:system-ui;background:#04070b;"
        "color:#e6f0ee;display:flex;min-height:100vh;align-items:center;justify-content:center;"
        "margin:0'><div style='max-width:420px;padding:32px;text-align:center'>"
        "<div style='font-weight:700;font-size:18px;margin-bottom:10px;color:#5AA6FF'>"
        "Lifted Sign</div>"
        f"<p style='line-height:1.5'>{safe}</p></div></body>"
    )
    return HTMLResponse(
        html,
        status_code=200,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


@router.get("/envelope/{envelope_id}")
async def envelope_page(envelope_id: str) -> FileResponse:
    """Envelope return-view shell. The page is a shell — all data is gated by the env-session API.
    Fonts are vendored (served from /static), so the page needs no external hosts; the global
    strict CSP applies."""
    return FileResponse(
        WEB_DIR / "envelope.html",
        headers={
            "Cache-Control": "no-store, must-revalidate",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )


@router.post("/api/envelope/{env_id}/auth/start")
async def envelope_auth_start(env_id: str, req: Request):
    """Begin identity verification. method=google → OAuth redirect; method=otp → send a Verify code
    to the on-record address (server picks address; client picks channel)."""
    from .. import db, esign_access, hub_auth, webauth

    b = await req.json()
    method = (b.get("method") or "").strip().lower()
    if method == "google":
        nonce = _new_oauth_state()
        state_nonce = _new_oauth_state()
        # Bind env_id inside the signed state so the callback knows the envelope w/o trusting a param.
        state = webauth._sign(
            {
                "k": "envstate",
                "env_id": env_id,
                "s": state_nonce,
                "exp": time.time() + OAUTH_STATE_TTL,
            }
        )
        url = hub_auth.google_login_url(state, _env_redirect_uri(req), nonce=nonce)
        resp = JSONResponse({"ok": True, "redirect": url})
        resp.set_cookie(
            ENV_STATE_COOKIE,
            state_nonce,
            max_age=OAUTH_STATE_TTL,
            httponly=True,
            secure=config.cookie_secure(),
            samesite="lax",
        )
        resp.set_cookie(
            ENV_NONCE_COOKIE,
            nonce,
            max_age=OAUTH_STATE_TTL,
            httponly=True,
            secure=config.cookie_secure(),
            samesite="lax",
        )
        return resp
    if method == "otp":
        channel = "email"  # email codes + Google only (no SMS/phone — simpler, no number required)
        hint = (b.get("signer_hint") or "").strip()
        ip = _client_ip(req)
        # NO enumeration oracle. Throttle the probe per-IP+envelope, send only on a real match,
        # and ALWAYS return the identical shape (never echo the real destination or reveal whether
        # `hint` is a signer). The client shows "if that's on file, a code was sent".
        if db.auth_rate_allowed(f"env:otpstart:{env_id}:{ip}", 12, 3600):
            s = await asyncio.to_thread(esign_access.resolve_signer_by_email, env_id, hint)
            if s:
                await asyncio.to_thread(
                    esign_access.send_env_otp, env_id, int(s["id"]), channel, ip
                )
        return {"ok": True, "channel": channel}
    return {"ok": False, "error": "unsupported method"}


@router.get("/api/envelope/auth/callback")
async def envelope_auth_callback(req: Request, code: str = "", state: str = ""):
    """Google OAuth redirect-back. Verifies state + nonce, matches the verified email to a signer
    ON THIS envelope, then mints the scoped env-session cookie and redirects to the page."""
    from .. import db, esign, esign_access, hub_auth, webauth

    state_cookie = req.cookies.get(ENV_STATE_COOKIE)
    nonce_cookie = req.cookies.get(ENV_NONCE_COOKIE)

    def _err(msg):
        # The OAuth state/nonce are strictly single-use — clear them on EVERY exit (success and all
        # error branches) so a leaked `state` can't be replayed in its window.
        r = _envelope_error_page(msg)
        r.delete_cookie(ENV_STATE_COOKIE)
        r.delete_cookie(ENV_NONCE_COOKIE)
        return r

    sd = webauth._unsign(state or "")
    if not sd or sd.get("k") != "envstate" or not _oauth_state_ok(state_cookie, sd.get("s")):
        return _err("Your sign-in link expired. Please reopen your envelope.")
    env_id = sd.get("env_id", "")
    email = await asyncio.to_thread(
        hub_auth.exchange_code, code, _env_redirect_uri(req), nonce_cookie
    )
    if not email:
        return _err("We couldn't verify your Google sign-in.")
    s = await asyncio.to_thread(esign_access.match_google_signer, env_id, email)
    if not s:
        return _err("This Google account isn't a signer on this envelope.")
    agr = await asyncio.to_thread(esign.agreement_by_envelope, env_id)
    if not agr:
        return _err("Envelope not found.")
    now = time.time()
    has_chal = (s.get("challenge_type") or "none") != "none"

    def _persist():
        conn = db.connect()
        try:
            conn.execute(
                "UPDATE agreement_signers SET env_auth_method='google', env_auth_at=?, "
                "env_auth_email=? WHERE id=?",
                (now, email, int(s["id"])),
            )
            esign._event(
                conn,
                int(agr["id"]),
                esign.ENVELOPE_ACCESS_VERIFIED,
                signer_id=int(s["id"]),
                ip=_client_ip(req),
                ua=req.headers.get("user-agent", ""),
                detail=f"google:{email}",
            )
            conn.commit()
        finally:
            conn.close()

    await asyncio.to_thread(_persist)
    chal_ok = not has_chal
    tok = esign_access.mint_env_session(
        env_id,
        int(s["id"]),
        email,
        "google",
        chal_ok,
        int(agr.get("env_session_epoch", 0) or 0),
    )
    resp = RedirectResponse(f"/envelope/{env_id}", status_code=303)
    _set_env_cookie(resp, tok)
    resp.delete_cookie(ENV_STATE_COOKIE)
    resp.delete_cookie(ENV_NONCE_COOKIE)
    return resp


@router.post("/api/envelope/{env_id}/auth/otp-verify")
async def envelope_otp_verify(env_id: str, req: Request):
    """Verify an emailed OTP. On success mints the scoped env-session cookie."""
    from .. import db, esign, esign_access

    b = await req.json()
    channel = "email"  # email codes + Google only (no SMS)
    hint = (b.get("signer_hint") or "").strip()
    code = b.get("code") or ""
    s = await asyncio.to_thread(esign_access.resolve_signer_by_email, env_id, hint)
    if not s:
        return {"ok": False, "error": "That code didn't match."}
    ok = await asyncio.to_thread(esign_access.check_env_otp, env_id, int(s["id"]), code, channel)
    if not ok:
        return {"ok": False, "error": "That code didn't match."}
    agr = await asyncio.to_thread(esign.agreement_by_envelope, env_id)
    if not agr:
        return {"ok": False, "error": "Envelope not found."}
    now = time.time()
    m = f"otp:{'sms' if channel == 'sms' else 'email'}"

    def _persist():
        conn = db.connect()
        try:
            conn.execute(
                "UPDATE agreement_signers SET env_auth_method=?, env_auth_at=?, "
                "otp_verified_at=? WHERE id=?",
                (m, now, now, int(s["id"])),
            )
            esign._event(
                conn,
                int(agr["id"]),
                esign.ENVELOPE_ACCESS_VERIFIED,
                signer_id=int(s["id"]),
                ip=_client_ip(req),
                ua=req.headers.get("user-agent", ""),
                detail=m,
            )
            conn.commit()
        finally:
            conn.close()

    await asyncio.to_thread(_persist)
    has_chal = (s.get("challenge_type") or "none") != "none"
    chal_ok = not has_chal
    tok = esign_access.mint_env_session(
        env_id,
        int(s["id"]),
        s.get("email") or "",
        m,
        chal_ok,
        int(agr.get("env_session_epoch", 0) or 0),
    )
    resp = JSONResponse({"ok": True})
    _set_env_cookie(resp, tok)
    return resp


@router.get("/api/envelope/{env_id}")
async def envelope_data(env_id: str, req: Request):
    """Scoped, read-mostly envelope payload. Authz from the signed token only."""
    from .. import db, esign, esign_access

    guard = await asyncio.to_thread(
        esign_access.require_env_session, env_id, req.cookies.get(esign_access.COOKIE)
    )
    if guard is None:
        return JSONResponse(
            {"ok": False, "error": "Sign in to view this envelope.", "need_auth": True},
            status_code=401,
        )
    if len(guard) == 4:  # voided/cancelled
        return {
            "ok": False,
            "voided": True,
            "message": "This document was voided by the sender.",
        }
    sess, agr, signer = guard
    # Challenge gate (second factor after identity). Withhold everything until passed.
    if (signer.get("challenge_type") or "none") != "none" and not sess.get("chal_ok"):
        return {
            "ok": False,
            "challenge_required": True,
            "challenge_type": signer["challenge_type"],
            "challenge_prompt": signer.get("challenge_prompt") or "",
        }
    # Build from the guard-VALIDATED agreement id, never the path-supplied env_id.
    agr_full = await asyncio.to_thread(esign.get_agreement, int(agr["id"]), True)
    signers = agr_full.get("signers", []) if agr_full else agr.get("signers", [])
    events = (agr_full or {}).get("events", []) or []
    parties = [
        {
            "name": s.get("name") or "",
            "email_masked": _mask_email_display(s.get("email") or ""),
            "role": s.get("role") or "signer",
            "status": s.get("status") or "pending",
            "signed_at": s.get("signed_at"),
        }
        for s in signers
    ]
    # Never expose another party's IP to this viewer — only stamp the IP on the viewer's OWN events;
    # blank it for everyone else (cross-party PII).
    timeline = [
        {
            "at": e.get("at"),
            "type_label": _ENV_TIMELINE_LABELS.get(
                (e.get("type") or "").lower(),
                (e.get("type") or "").replace("_", " ").title(),
            ),
            "actor": next(
                (s.get("name") for s in signers if s.get("id") == e.get("signer_id")),
                "",
            ),
            "ip": (e.get("ip") or "") if e.get("signer_id") == signer["id"] else "",
        }
        for e in events
    ]
    completed = agr.get("status") == "completed"

    # Emit ENVELOPE_VIEWED once per signer (dedupe like COMPLETED_COPY_DELIVERED).
    def _mark_viewed():
        conn = db.connect()
        try:
            seen = conn.execute(
                "SELECT 1 FROM agreement_events WHERE agreement_id=? AND signer_id=? "
                "AND type='ENVELOPE_VIEWED' LIMIT 1",
                (int(agr["id"]), int(signer["id"])),
            ).fetchone()
            if not seen:
                esign._event(
                    conn,
                    int(agr["id"]),
                    esign.ENVELOPE_VIEWED,
                    signer_id=int(signer["id"]),
                    ip=_client_ip(req),
                    ua=req.headers.get("user-agent", ""),
                    detail="envelope page",
                )
                conn.commit()
        finally:
            conn.close()

    await asyncio.to_thread(_mark_viewed)
    return {
        "ok": True,
        "envelope": {
            "id": env_id,
            "name": agr.get("name"),
            "status": agr.get("status"),
            "created_at": agr.get("created_at"),
            "completed_at": agr.get("completed_at"),
        },
        "me": {
            "signer_id": int(signer["id"]),
            "name": signer.get("name") or "",
            "email_masked": _mask_email_display(signer.get("email") or ""),
            "status": signer.get("status") or "pending",
        },
        "parties": parties,
        "timeline": timeline,
        "download": {
            "available": completed,
            "doc_url": f"/api/envelope/{env_id}/download",
            "cert_url": f"/api/envelope/{env_id}/certificate",
        },
        "brand": esign._BRAND,
    }


@router.post("/api/envelope/{env_id}/challenge")
async def envelope_challenge(env_id: str, req: Request):
    """Pass the access-lock challenge AFTER identity. On success the env-session is re-minted with
    chal_ok=True (rotated, same TTL)."""
    from .. import esign_access

    guard = await asyncio.to_thread(
        esign_access.require_env_session, env_id, req.cookies.get(esign_access.COOKIE)
    )
    if guard is None:
        return JSONResponse(
            {"ok": False, "error": "Sign in to view this envelope.", "need_auth": True},
            status_code=401,
        )
    if len(guard) == 4:
        return {
            "ok": False,
            "voided": True,
            "message": "This document was voided by the sender.",
        }
    sess, agr, signer = guard
    b = await req.json()
    res = await asyncio.to_thread(
        esign_access.verify_challenge,
        env_id,
        int(signer["id"]),
        b.get("value", ""),
        _client_ip(req),
    )
    if not res.get("ok"):
        return res
    tok = esign_access.mint_env_session(
        env_id,
        int(signer["id"]),
        sess.get("email_lc") or "",
        sess.get("m") or "",
        True,
        int(agr.get("env_session_epoch", 0) or 0),
    )
    resp = JSONResponse({"ok": True})
    _set_env_cookie(resp, tok)
    return resp


@router.get("/api/envelope/{env_id}/inbox")
async def envelope_inbox(env_id: str, req: Request):
    """Multi-envelope inbox: once the email is verified, list EVERY envelope addressed to that same
    email so a returning signer can choose from all of them. Metadata only; an envelope with an
    unmet access-lock is flagged `locked` and its contents stay gated until that challenge is passed
    (see /switch)."""
    from .. import esign, esign_access

    guard = await asyncio.to_thread(
        esign_access.require_env_session, env_id, req.cookies.get(esign_access.COOKIE)
    )
    if guard is None:
        return JSONResponse(
            {
                "ok": False,
                "error": "Sign in to view your envelopes.",
                "need_auth": True,
            },
            status_code=401,
        )
    if len(guard) == 4:
        return {"ok": False, "voided": True}
    sess, agr, signer = guard
    email_lc = (sess.get("email_lc") or "").lower()
    items = await asyncio.to_thread(esign.envelopes_for_email, email_lc)
    for it in items:
        it["current"] = it["envelope_id"] == env_id
    return {
        "ok": True,
        "email_masked": _mask_email_display(email_lc),
        "count": len(items),
        "envelopes": items,
    }


@router.post("/api/envelope/{env_id}/switch")
async def envelope_switch(env_id: str, req: Request):
    """Open another envelope addressed to the SAME already-verified email. Email ownership was
    proven once (Google/OTP); we re-mint the scoped session for the target WITHOUT a second email
    check — but the target's OWN access-lock challenge is still enforced (chal_ok stays false until
    passed), so a sender's per-envelope DOB/SSN/code gate is never bypassed."""
    from .. import esign, esign_access

    guard = await asyncio.to_thread(
        esign_access.require_env_session, env_id, req.cookies.get(esign_access.COOKIE)
    )
    if guard is None:
        return JSONResponse(
            {"ok": False, "error": "Sign in first.", "need_auth": True}, status_code=401
        )
    if len(guard) == 4:
        return {"ok": False, "voided": True}
    sess, agr, signer = guard
    email_lc = (sess.get("email_lc") or "").lower()
    target = ((await req.json()).get("target") or "").strip()
    if not target:
        return JSONResponse({"ok": False, "error": "No envelope specified."}, status_code=400)
    # The verified email must be a signer on the target envelope (no IDOR / cross-email access).
    ts = await asyncio.to_thread(esign_access.match_google_signer, target, email_lc)
    if not ts:
        return JSONResponse(
            {"ok": False, "error": "That document isn't addressed to you."},
            status_code=403,
        )
    tagr = await asyncio.to_thread(esign.agreement_by_envelope, target)
    if not tagr:
        return JSONResponse({"ok": False, "error": "Envelope not found."}, status_code=404)
    tsf = await asyncio.to_thread(esign.signer_for_envelope, target, int(ts["id"]))
    has_chal = ((tsf or {}).get("challenge_type") or "none") != "none"

    def _log():
        from .. import db

        conn = db.connect()
        try:
            esign._event(
                conn,
                int(tagr["id"]),
                esign.ENVELOPE_ACCESS_VERIFIED,
                signer_id=int(ts["id"]),
                ip=_client_ip(req),
                ua=req.headers.get("user-agent", ""),
                detail=f"inbox-switch:{sess.get('m') or 'email'}",
            )
            conn.commit()
        finally:
            conn.close()

    await asyncio.to_thread(_log)
    tok = esign_access.mint_env_session(
        target,
        int(ts["id"]),
        email_lc,
        sess.get("m") or "email",
        not has_chal,
        int(tagr.get("env_session_epoch", 0) or 0),
    )
    resp = JSONResponse({"ok": True, "env_id": target, "challenge_required": has_chal})
    _set_env_cookie(resp, tok)
    return resp


def _env_download_guard(env_id: str, req: Request):
    """Shared gate for download/certificate: valid session + chal_ok (if a challenge is set)."""
    from .. import esign_access

    guard = esign_access.require_env_session(env_id, req.cookies.get(esign_access.COOKIE))
    if guard is None or len(guard) == 4:
        return None
    sess, agr, signer = guard
    if (signer.get("challenge_type") or "none") != "none" and not sess.get("chal_ok"):
        return None
    return (agr, signer)


@router.get("/api/envelope/{env_id}/download")
async def envelope_download(env_id: str, req: Request):
    from .. import esign

    g = await asyncio.to_thread(_env_download_guard, env_id, req)
    if not g:
        return JSONResponse({"error": "Sign in to view this envelope."}, status_code=401)
    agr, signer = g
    if agr.get("status") != "completed":
        return JSONResponse({"error": "not yet completed"}, status_code=404)
    res = await asyncio.to_thread(esign.signer_download_by_id, int(agr["id"]), int(signer["id"]))
    if not res.get("ok"):
        return JSONResponse({"error": res.get("error", "not found")}, status_code=404)
    return Response(
        content=res["bytes"],
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{res["filename"]}"'},
    )


@router.get("/api/envelope/{env_id}/certificate")
async def envelope_certificate(env_id: str, req: Request):
    from .. import esign
    import re as _re

    g = await asyncio.to_thread(_env_download_guard, env_id, req)
    if not g:
        return JSONResponse({"error": "Sign in to view this envelope."}, status_code=401)
    agr, _signer = g
    if agr.get("status") != "completed":
        return JSONResponse({"error": "not yet completed"}, status_code=404)
    data = await asyncio.to_thread(esign.certificate_bytes, int(agr["id"]))
    if not data:
        return JSONResponse({"error": "not completed"}, status_code=404)
    base = _re.sub(r"\.pdf$", "", agr.get("name", "") or "", flags=_re.I)
    base = _re.sub(r'[\\/:*?"<>|\r\n]+', "", base).strip() or f"agreement-{agr['id']}"
    fn = f"{base}-CERTIFICATE.pdf"[:90]
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{fn}"'},
    )
