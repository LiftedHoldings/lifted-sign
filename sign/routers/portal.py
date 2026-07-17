"""``/api/sign-portal/auth/*`` — tenant signup / login.

Two credentialed paths, no passwords:

* **Phone-OTP** (Twilio Verify) — enter a phone, get an SMS code; a new number also supplies an
  email + name to create the account.
* **Google** — OpenID Connect; a verified Google email proves ownership and takes control of an
  account whose email was never verified.

Optional TOTP (Google Authenticator) second factor is enrolled/confirmed/disabled here. Every
route is public-allowlisted (no admin gate); the in-handler session check is the only authn, so a
missed check is unauthenticated access — hence the shared ``_sign_acct`` helper on every gated
route.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from ..http_helpers import (
    OAUTH_STATE_TTL,
    _client_ip,
    _new_oauth_state,
    _oauth_state_ok,
    _set_sign_cookie,
    _sign_acct,
)

router = APIRouter()


# --- phone-OTP signup/login -------------------------------------------------
@router.post("/api/sign-portal/auth/phone/start")
async def signp_phone_start(req: Request) -> Any:
    from .. import sign_portal_auth

    b = await req.json()
    phone = b.get("phone") or ""
    if not sign_portal_auth.valid_phone(phone):
        return JSONResponse({"ok": False, "error": "invalid_phone"}, status_code=400)
    if not sign_portal_auth.phone_start_allowed(_client_ip(req), phone):
        return JSONResponse({"ok": False, "error": "rate_limited"}, status_code=429)
    sent = await asyncio.to_thread(sign_portal_auth.send_phone_code, phone)
    if not sent:
        return JSONResponse({"ok": False, "error": "sms_unavailable"}, status_code=503)
    # Bake the phone (+ optional signup email/name) into a signed short-lived cookie. verify checks
    # the code against THIS number, so an attacker can't send to their phone then verify a victim's.
    resp = JSONResponse({"ok": True, "next": "code"})
    resp.set_cookie(
        sign_portal_auth.COOKIE_PHONE,
        sign_portal_auth.make_phone_pending(phone, b.get("email"), b.get("name")),
        max_age=sign_portal_auth.PENDING_PHONE_TTL,
        httponly=True,
        secure=True,
        samesite="lax",
    )
    return resp


@router.post("/api/sign-portal/auth/phone/verify")
async def signp_phone_verify(req: Request) -> Any:
    from .. import config, sign_accounts, sign_portal_auth

    b = await req.json()
    pend = sign_portal_auth.redeem_phone_pending(req.cookies.get(sign_portal_auth.COOKIE_PHONE))
    if not pend:
        return JSONResponse({"ok": False, "error": "expired"}, status_code=401)
    phone = pend["ph"]
    if not await asyncio.to_thread(sign_portal_auth.check_phone_code, phone, b.get("code", "")):
        return JSONResponse({"ok": False, "error": "invalid_code"}, status_code=401)
    acct = await asyncio.to_thread(sign_accounts.account_by_phone, phone)
    if not acct:
        # New number → sign up. An email is required (senders receive the signed PDF + are the
        # invite "from"); name is optional. Accept them from the pending cookie or the verify body.
        email = (pend.get("em") or (b.get("email") or "")).strip().lower()
        name = (pend.get("nm") or (b.get("name") or "")).strip()
        if "@" not in email or "." not in email.split("@")[-1]:
            return JSONResponse({"ok": False, "error": "email_required"}, status_code=200)
        # Closed install: refuse to create a new account (existing accounts still sign in by phone).
        if not config.SIGNUPS_OPEN:
            return JSONResponse({"ok": False, "error": "signups_closed"}, status_code=403)
        # SECURITY: the OTP proves PHONE ownership, NOT email ownership. So we must NEVER attach this
        # phone to an existing account just because the email matches — that would let anyone who
        # knows a victim's email take over their account by verifying their own phone. create_account
        # enforces a unique email: an existing email comes back "exists" and we refuse (the real
        # owner signs in with their existing method — Google, or a phone already on the account).
        res = await asyncio.to_thread(sign_accounts.create_account, email, name, None)
        if res.get("error") == "exists":
            return JSONResponse({"ok": False, "error": "email_in_use"}, status_code=409)
        if res.get("error"):
            return JSONResponse({"ok": False, "error": res["error"]}, status_code=400)
        await asyncio.to_thread(sign_accounts.attach_phone, res["id"], phone)
        acct = await asyncio.to_thread(sign_accounts.account_by_id, res["id"])
        # The phone is verified, but the self-asserted email still needs confirming before the
        # account can SEND documents (anti-spam) — fire the verification email.
        await asyncio.to_thread(sign_portal_auth.send_verify_email, acct)
    # Optional 2FA: if the account armed Google Authenticator (TOTP), require it before the full
    # session — phone-OTP alone isn't enough once the owner opted into a second factor.
    if acct.get("totp_secret"):
        resp = JSONResponse({"ok": True, "next": "2fa"})
        resp.set_cookie(
            sign_portal_auth.COOKIE_2FA,
            sign_portal_auth.make_2fa_pending(acct["id"]),
            max_age=sign_portal_auth.PENDING_2FA_TTL,
            httponly=True,
            secure=True,
            samesite="lax",
        )
        resp.delete_cookie(
            sign_portal_auth.COOKIE_PHONE, httponly=True, secure=True, samesite="lax"
        )
        return resp
    await asyncio.to_thread(sign_accounts.touch_login, acct["id"])
    resp = JSONResponse({"ok": True, "account": sign_accounts.public_view(acct)})
    _set_sign_cookie(resp, sign_portal_auth.make_session(acct["id"]))
    resp.delete_cookie(sign_portal_auth.COOKIE_PHONE, httponly=True, secure=True, samesite="lax")
    return resp


@router.post("/api/sign-portal/auth/2fa")
async def signp_2fa(req: Request) -> Any:
    """Second-factor step (Google Authenticator / TOTP only). Redeems the pending-2FA half-session
    set by phone-verify or the Google callback and completes login on a correct TOTP code."""
    from .. import sign_accounts, sign_portal_auth

    b = await req.json()
    pend = sign_portal_auth.redeem_2fa_pending(sign_portal_auth.pending_2fa_cookie(req.cookies))
    if not pend:
        return JSONResponse({"ok": False, "error": "expired"}, status_code=401)
    aid = int(pend["aid"])
    acct = await asyncio.to_thread(sign_accounts.account_by_id, aid)
    if not acct or acct.get("status") != "active":
        return JSONResponse({"ok": False, "error": "invalid"}, status_code=401)
    ok = bool(acct.get("totp_secret")) and await asyncio.to_thread(
        sign_portal_auth.verify_totp_for_account, aid, b.get("code", "")
    )
    if not ok:
        return JSONResponse({"ok": False, "error": "invalid_code"}, status_code=401)
    await asyncio.to_thread(sign_accounts.touch_login, aid)
    resp = JSONResponse({"ok": True, "account": sign_accounts.public_view(acct)})
    _set_sign_cookie(resp, sign_portal_auth.make_session(aid))
    resp.delete_cookie(sign_portal_auth.COOKIE_2FA, httponly=True, secure=True, samesite="lax")
    return resp


@router.get("/api/sign-portal/verify-email")
async def signp_verify_email(token: str = ""):
    """One-click email-verification link target (clicked from the confirmation email; public,
    no session). Verifies the signed token → marks the account verified → back to the app."""
    from .. import sign_accounts, sign_portal_auth

    d = await asyncio.to_thread(sign_portal_auth.read_verify_token, token)
    if not d:
        return RedirectResponse("/app?verify_error=1")
    # Bind the token to the account's CURRENT email — a stale link for an old address is rejected.
    acct = await asyncio.to_thread(sign_accounts.account_by_id, int(d["aid"]))
    if (
        not acct
        or (acct.get("email") or "").strip().lower() != str(d.get("em", "")).strip().lower()
    ):
        return RedirectResponse("/app?verify_error=1")
    await asyncio.to_thread(sign_accounts.set_email_verified, int(d["aid"]))
    return RedirectResponse("/app?verified=1")


@router.post("/api/sign-portal/auth/resend-verify")
async def signp_resend_verify(req: Request) -> Any:
    acct = _sign_acct(req)
    if not acct:
        return JSONResponse({"ok": False}, status_code=401)
    if not acct.get("email_verified") and not acct.get("google_sub"):
        from .. import sign_portal_auth

        await asyncio.to_thread(sign_portal_auth.send_verify_email, acct)
    return JSONResponse({"ok": True})  # uniform response (don't reveal verified state)


# --- email magic-link sign-in (zero-config self-host default) ---------------
@router.post("/api/sign-portal/auth/magic/start")
async def signp_magic_start(req: Request) -> Any:
    """Request a passwordless sign-in link. ENUMERATION-SAFE: always returns {ok:True} — whether
    a link is actually sent (account exists / signups open) is decided quietly in send_magic_link,
    never revealed here. Throttled per IP + per email. Needs no external service (the link
    console-prints when SMTP is unset)."""
    from .. import sign_portal_auth

    b = await req.json()
    email = (b.get("email") or "").strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        return JSONResponse({"ok": False, "error": "invalid_email"}, status_code=400)
    if sign_portal_auth.magic_start_allowed(_client_ip(req), email):
        await asyncio.to_thread(sign_portal_auth.send_magic_link, email, b.get("name") or "")
    return JSONResponse({"ok": True})  # uniform: never reveal whether the address exists


@router.get("/api/sign-portal/auth/magic/verify")
async def signp_magic_verify(req: Request, token: str = ""):
    """Consume a magic-link token: create-or-load the account for its email, then mint a session.
    A clicked link proves control of the mailbox — the SAME ownership proof Google gives — so a
    first click both creates the account (gated on SIGNUPS_OPEN) and marks its email verified.
    An armed TOTP is honored (hand off to the 2FA step) so a magic link can't bypass 2FA."""
    from .. import config, db, sign_accounts, sign_portal_auth

    d = await asyncio.to_thread(sign_portal_auth.read_magic_token, token)
    if not d:
        return RedirectResponse("/app?sign_error=magic")
    email = str(d.get("em") or "").strip().lower()
    name = str(d.get("nm") or "").strip()
    if "@" not in email:
        return RedirectResponse("/app?sign_error=magic")
    # Single-use: atomically consume the token's jti BEFORE minting a session, so a link that
    # lingers in a mail relay / proxy / scanner log or shared mailbox can't be replayed to open a
    # second session after the legitimate click. claim_once returns False on any repeat.
    jti = str(d.get("jti") or "")
    if not jti or not await asyncio.to_thread(
        db.claim_once, f"magic_used:{jti}", {"exp": d.get("exp")}
    ):
        return RedirectResponse("/app?sign_error=magic")
    acct = await asyncio.to_thread(sign_accounts.account_by_email, email)
    if not acct:
        # New email → sign up. Refuse creation on a closed install (existing accounts still log in).
        if not config.SIGNUPS_OPEN:
            return RedirectResponse("/app?sign_error=closed")
        res = await asyncio.to_thread(sign_accounts.create_account, email, name, None)
        if res.get("error"):
            return RedirectResponse("/app?sign_error=create")
        # The clicked link proves mailbox control → the email is verified (parity with Google).
        await asyncio.to_thread(sign_accounts.set_email_verified, res["id"])
        acct = await asyncio.to_thread(sign_accounts.account_by_id, res["id"])
    elif not acct.get("email_verified"):
        # Returning account that never verified: the click proves ownership — mark it verified.
        await asyncio.to_thread(sign_accounts.set_email_verified, acct["id"])
    # Optional 2FA: mirror the Google-callback handoff so an armed authenticator isn't bypassed.
    if acct.get("totp_secret"):
        resp = RedirectResponse("/app?need_2fa=1")
        resp.set_cookie(
            sign_portal_auth.COOKIE_2FA,
            sign_portal_auth.make_2fa_pending(acct["id"]),
            max_age=sign_portal_auth.PENDING_2FA_TTL,
            httponly=True,
            secure=True,
            samesite="lax",
        )
        return resp
    await asyncio.to_thread(sign_accounts.touch_login, acct["id"])
    resp = RedirectResponse("/app")
    _set_sign_cookie(resp, sign_portal_auth.make_session(acct["id"]))
    return resp


# --- configured sign-in methods (public; drives the SPA auth card) ----------
@router.get("/api/sign-portal/auth/methods")
async def signp_methods() -> Any:
    """Which sign-in methods this install can offer (magic always on; google/phone if configured),
    so the SPA renders only usable methods and never a dead button."""
    from .. import sign_portal_auth

    return JSONResponse(sign_portal_auth.available_methods())


# --- session lifecycle ------------------------------------------------------
@router.post("/api/sign-portal/auth/logout")
async def signp_logout(req: Request) -> Any:
    from .. import sign_accounts, sign_portal_auth

    acct = _sign_acct(req)
    if acct:
        await asyncio.to_thread(sign_accounts.bump_session_version, acct["id"])
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(sign_portal_auth.COOKIE, httponly=True, secure=True, samesite="lax")
    resp.delete_cookie(sign_portal_auth.COOKIE_2FA, httponly=True, secure=True, samesite="lax")
    return resp


@router.get("/api/sign-portal/auth/me")
async def signp_me(req: Request) -> Any:
    from .. import sign_accounts

    acct = _sign_acct(req)
    if not acct:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {"account": sign_accounts.public_view(acct)}


# --- Google OpenID Connect --------------------------------------------------
@router.get("/api/sign-portal/auth/google")
async def signp_google(req: Request):
    from .. import sign_portal_auth

    state = _new_oauth_state()
    nonce = _new_oauth_state()
    url = sign_portal_auth.google_login_url(state, nonce)
    # Google unconfigured ⇒ empty URL. Redirecting to '' makes the browser re-request THIS route
    # (relative resolve) → redirect loop. Fail to a friendly hint instead of a dead button.
    if not url:
        return RedirectResponse("/app?sign_error=google_unconfigured")
    resp = RedirectResponse(url)
    resp.set_cookie(
        sign_portal_auth.STATE_COOKIE,
        state,
        max_age=OAUTH_STATE_TTL,
        httponly=True,
        secure=True,
        samesite="lax",
    )
    resp.set_cookie(
        sign_portal_auth.NONCE_COOKIE,
        nonce,
        max_age=OAUTH_STATE_TTL,
        httponly=True,
        secure=True,
        samesite="lax",
    )
    return resp


@router.get("/api/sign-portal/auth/google/callback")
async def signp_google_cb(req: Request, code: str = "", state: str = ""):
    from .. import config, sign_accounts, sign_portal_auth

    cookie_state = sign_portal_auth.oauth_state_cookie(req.cookies)
    nonce = sign_portal_auth.oauth_nonce_cookie(req.cookies)
    if not _oauth_state_ok(cookie_state, state):
        return RedirectResponse("/app?sign_error=state")
    # A missing nonce cookie must be a hard failure — otherwise id_token replay protection is
    # silently disabled by simply stripping the cookie.
    if not nonce:
        return RedirectResponse("/app?sign_error=state")
    email = await asyncio.to_thread(sign_portal_auth.google_exchange, code, nonce)
    if not email:
        return RedirectResponse("/app?sign_error=google")
    email = email.strip().lower()
    acct = await asyncio.to_thread(sign_accounts.account_by_email, email)
    if not acct:
        # New account. Refuse creation on a closed install (existing accounts still sign in).
        if not config.SIGNUPS_OPEN:
            return RedirectResponse("/app?sign_error=closed")
        acct = await asyncio.to_thread(
            sign_accounts.create_account, email, email.split("@")[0], None, ""
        )
        if acct.get("error"):
            return RedirectResponse("/app?sign_error=create")
    elif not acct.get("email_verified"):
        # Google PROVES ownership of this email. If the account's email was never verified, any phone
        # on it was bound by an UNVERIFIED phone-signup — possibly a squatter who pre-registered this
        # address with their own number. The proven owner takes control: drop that untrusted phone so
        # the squatter loses phone-OTP co-access, then mark the email verified.
        if acct.get("phone"):
            await asyncio.to_thread(sign_accounts.attach_phone, acct["id"], "")
        await asyncio.to_thread(sign_accounts.set_email_verified, acct["id"])
    # Optional 2FA (Google Authenticator / TOTP): if armed, hand off to the TOTP step instead of a
    # full session — the SPA shows the code prompt on ?need_2fa=1 and posts to /auth/2fa.
    if acct.get("totp_secret"):
        resp = RedirectResponse("/app?need_2fa=1")
        resp.set_cookie(
            sign_portal_auth.COOKIE_2FA,
            sign_portal_auth.make_2fa_pending(acct["id"]),
            max_age=sign_portal_auth.PENDING_2FA_TTL,
            httponly=True,
            secure=True,
            samesite="lax",
        )
        resp.delete_cookie(
            sign_portal_auth.STATE_COOKIE, httponly=True, secure=True, samesite="lax"
        )
        resp.delete_cookie(
            sign_portal_auth.NONCE_COOKIE, httponly=True, secure=True, samesite="lax"
        )
        return resp
    await asyncio.to_thread(sign_accounts.touch_login, acct["id"])
    resp = RedirectResponse("/app")  # "/" is the marketing landing; the app lives at /app
    _set_sign_cookie(resp, sign_portal_auth.make_session(acct["id"]))
    resp.delete_cookie(sign_portal_auth.STATE_COOKIE, httponly=True, secure=True, samesite="lax")
    resp.delete_cookie(sign_portal_auth.NONCE_COOKIE, httponly=True, secure=True, samesite="lax")
    return resp


# --- TOTP (Google Authenticator) enroll / confirm / disable -----------------
@router.post("/api/sign-portal/auth/totp/enroll")
async def signp_totp_enroll(req: Request) -> Any:
    from .. import webauth

    acct = _sign_acct(req)
    if not acct:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    secret = webauth.gen_totp_secret()
    uri = webauth.totp_uri(secret, account=acct["email"], issuer="LiftedSign")
    # Stash the PENDING secret in a short-lived signed cookie so confirm can verify it before
    # persisting (never persist an unconfirmed secret).
    resp = JSONResponse({"secret": secret, "uri": uri, "qr": webauth.totp_qr(uri)})
    resp.set_cookie(
        "__Host-ls_sign_totp",
        webauth._sign({"k": "signtotp", "aid": acct["id"], "s": secret, "exp": time.time() + 600}),
        max_age=600,
        httponly=True,
        secure=True,
        samesite="lax",
    )
    return resp


@router.post("/api/sign-portal/auth/totp/confirm")
async def signp_totp_confirm(req: Request) -> Any:
    from .. import crypto, sign_accounts, sign_portal_auth, webauth

    acct = _sign_acct(req)
    if not acct:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    b = await req.json()
    pend = webauth._unsign(req.cookies.get("__Host-ls_sign_totp"))
    if not (pend and pend.get("k") == "signtotp" and int(pend.get("aid", 0)) == acct["id"]):
        return JSONResponse({"ok": False, "error": "expired"}, status_code=400)
    secret = pend.get("s") or ""
    # Per-account replay marker (not the global one) so a concurrent enrollment can't reject a
    # valid confirm code in the same 30s step.
    if not await asyncio.to_thread(
        sign_portal_auth.verify_totp_for_pending, acct["id"], secret, b.get("code", "")
    ):
        return JSONResponse({"ok": False, "error": "invalid_code"}, status_code=400)
    await asyncio.to_thread(sign_accounts.set_totp, acct["id"], crypto.encrypt(secret))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("__Host-ls_sign_totp", httponly=True, secure=True, samesite="lax")
    return resp


@router.post("/api/sign-portal/auth/totp/disable")
async def signp_totp_disable(req: Request) -> Any:
    from .. import sign_accounts, sign_portal_auth

    acct = _sign_acct(req)
    if not acct:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    b = await req.json()
    if not acct.get("totp_secret"):
        return {"ok": True}
    ok = await asyncio.to_thread(
        sign_portal_auth.verify_totp_for_account, acct["id"], b.get("code", "")
    )
    if not ok:
        return JSONResponse({"ok": False, "error": "invalid_code"}, status_code=400)
    await asyncio.to_thread(sign_accounts.clear_totp, acct["id"])
    return {"ok": True}
