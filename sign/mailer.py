"""Outbound transactional email over plain SMTP (self-host friendly, no external dependencies).

Used by the e-sign flow to deliver signing-link invites, reminders, the declined
notice, the expired notice, the envelope-access link, one-time verification codes,
and the completed, fully-executed document (with the sealed PDF attached).

Transport is stdlib ``smtplib`` + ``email.mime`` — no Gmail API, no OAuth, no host
application. SMTP settings come from the process environment:

    SMTP_HOST       SMTP relay host. **Unset ⇒ console mode**: the message is
                    printed to stdout (recipient, subject, links/OTP, attachment
                    names) instead of being sent, so local dev and CI work with
                    zero configuration and mail never silently disappears.
    SMTP_PORT       Default 587 (STARTTLS). Port 465 ⇒ implicit TLS (SMTP_SSL).
    SMTP_USER       SMTP auth username (optional — omit for an open relay).
    SMTP_PASSWORD   SMTP auth password.
    SMTP_STARTTLS   Default true. Upgrade the connection with STARTTLS before auth.
    MAIL_REPLY_TO   Optional default Reply-To when a caller does not pass reply_to.

Identity comes from :mod:`sign.config` — never a hardcoded address or domain:

    config.MAIL_FROM        From address. **Blank ⇒ console mode** (an operator
                            who has not set a sender never accidentally sends).
    config.MAIL_FROM_NAME   From display name (default "Lifted Sign").
    config.PUBLIC_BASE_URL  Base for email asset URLs (the header lockup / footer mark).
    config.LEGAL_ENTITY     Operator's legal entity for the footer (blank ⇒ omitted).
    config.LEGAL_ADDRESS    Operator's mailing address for the footer (blank ⇒ omitted).

Templates are DocuSign / Stripe / Ramp-grade transactional email. They follow the
proven bulletproof pattern so they render identically in REAL clients (Gmail,
Outlook desktop/web, Apple Mail, Yahoo) and never end up as invisible dark-on-white:

  * LIGHT-DEFAULT design. A neutral page (#eef2f6) with a CENTERED white card. Dark
    surfaces are confined to the brand header band and the footer — areas that hold
    light text by design, so a client that "forces light" can't invert them into
    unreadable text. Every text color is paired with an explicit, opaque background.
  * role="presentation" tables for ALL layout. The 600px container is centered with
    align="center" + margin:auto, and a bgcolor= attribute backs every colored cell
    (not CSS alone) so Outlook/Win renders the fills.
  * Fully INLINE styles. The single <head><style> block is progressive enhancement
    only (mobile stacking + an optional prefers-color-scheme dark theme) — strip it
    and the email still looks finished.
  * SYSTEM font stack only (no Google Fonts — many clients block remote fonts), with
    a display option for the wordmark. NO emoji; icons are pure CSS shapes.
  * VML roundrect button fallback so the CTA is a solid, clickable pill in Outlook.
  * A hidden preheader per template and a genuine multipart/alternative text/plain
    part (materially improves inbox placement; HTML-only mail reads as spam)."""

from __future__ import annotations

import os
import re
import smtplib
import sys
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from html import escape, unescape
from typing import Any

from . import config


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _html_to_text(html: str) -> str:
    """A readable text/plain fallback from the HTML body. A genuine multipart/alternative
    with a text part materially improves inbox placement — HTML-only mail looks like spam."""
    # Drop the hidden preheader span so it doesn't leak into the plain-text body twice.
    t = re.sub(r'(?is)<span[^>]*class="ls-preheader"[^>]*>.*?</span>', "", html)
    t = re.sub(r"(?is)<(script|style).*?</\1>", "", t)
    t = re.sub(r"(?i)<br\s*/?>", "\n", t)
    t = re.sub(r"(?i)</(p|div|tr|h1|h2|h3|table|li)>", "\n", t)
    t = re.sub(r"<[^>]+>", "", t)
    t = unescape(t)
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r"\n[ \t]+", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip() or "Open this email in an HTML-capable client to view it."


def _console_dump(
    to: str,
    subject: str,
    body_text: str,
    attachments: list[tuple[str, bytes]] | None,
    reason: str,
) -> None:
    """Print the message to stdout when SMTP is not configured. Surfaces the recipient,
    subject, the plain-text body (which carries every signing link and OTP code), and
    the names/sizes of any attachments — so local dev and CI can see exactly what would
    have been sent without a relay. Never sends, never raises."""
    urls = re.findall(r"https?://[^\s\"'<>]+", body_text)
    line = "=" * 72
    parts = [
        f"\n{line}",
        f"[sign.mailer] EMAIL (console mode — {reason})",
        line,
        f"To:      {to}",
        f"Subject: {subject}",
    ]
    if urls:
        parts.append("Links:")
        parts.extend(f"  {u}" for u in dict.fromkeys(urls))
    if attachments:
        parts.append("Attachments:")
        parts.extend(f"  {fn} ({len(data)} bytes)" for fn, data in attachments)
    parts.append("-" * 72)
    parts.append(body_text.strip())
    parts.append(line + "\n")
    text = "\n".join(parts)
    # Console mode is the "no SMTP configured" path and must never raise. A Windows
    # cp1252 stdout can't encode the unicode em-dashes in the plain-text body, so a
    # bare print() could throw UnicodeEncodeError — re-encode with replacement first.
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        enc = sys.stdout.encoding or "utf-8"
        sys.stdout.write(text.encode(enc, "replace").decode(enc, "replace") + "\n")
        sys.stdout.flush()


def _build_message(
    to: str,
    subject: str,
    html: str,
    from_addr: str,
    from_name: str,
    attachments: list[tuple[str, bytes]] | None,
    reply_to: str,
    text: str | None,
) -> MIMEMultipart:
    """Assemble a multipart/mixed message: a multipart/alternative (text FIRST, then
    HTML) plus one MIMEApplication part per attachment. The sealed 'completed' PDF is
    delivered exactly this way — attachment support is not optional."""
    msg = MIMEMultipart("mixed")
    msg["To"] = to
    msg["From"] = formataddr((from_name, from_addr)) if from_name else from_addr
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(text or _html_to_text(html), "plain", "utf-8"))  # text part FIRST
    alt.attach(MIMEText(html, "html", "utf-8"))
    msg.attach(alt)
    for fn, data in attachments or []:
        subtype = "pdf" if str(fn).lower().endswith(".pdf") else "octet-stream"
        part = MIMEApplication(data, _subtype=subtype)
        part.add_header("Content-Disposition", "attachment", filename=fn)
        msg.attach(part)
    return msg


def send_html(
    to: str,
    subject: str,
    html: str,
    attachments: list[tuple[str, bytes]] | None = None,
    from_name: str | None = None,
    text: str | None = None,
    reply_to: str | None = None,
) -> dict[str, Any]:
    """Send an HTML email (with optional (filename, bytes) attachments) over SMTP.

    Returns a result dict — ``{"ok": True, ...}`` on success, ``{"ok": False,
    "error": ...}`` on an SMTP failure, ``{"ok": True, "console": True}`` when no
    relay is configured. Never raises on a missing SMTP configuration; callers treat
    a falsy ``ok`` as "not delivered" and carry on."""
    from_addr = (config.MAIL_FROM or "").strip()
    from_name = from_name if from_name is not None else config.MAIL_FROM_NAME
    reply_to = (reply_to if reply_to is not None else _env("MAIL_REPLY_TO")) or ""
    host = _env("SMTP_HOST")

    body_text = text or _html_to_text(html)

    # Console mode: no relay configured, or no sender identity set. Print, don't send.
    if not host or not from_addr:
        reason = "SMTP_HOST unset" if not host else "MAIL_FROM blank"
        _console_dump(to, subject, body_text, attachments, reason)
        return {"ok": True, "console": True, "from": from_addr}

    msg = _build_message(to, subject, html, from_addr, from_name, attachments, reply_to, text)

    port = int(_env("SMTP_PORT", "587") or "587")
    user = os.environ.get("SMTP_USER") or ""
    password = os.environ.get("SMTP_PASSWORD") or ""
    use_starttls = _env_bool("SMTP_STARTTLS", True)

    try:
        if port == 465:
            # Implicit TLS from the first byte (SMTPS).
            with smtplib.SMTP_SSL(host, port, timeout=30) as srv:
                if user:
                    srv.login(user, password)
                srv.sendmail(from_addr, [to], msg.as_bytes())
        else:
            with smtplib.SMTP(host, port, timeout=30) as srv:
                srv.ehlo()
                if use_starttls:
                    srv.starttls()
                    srv.ehlo()
                if user:
                    srv.login(user, password)
                srv.sendmail(from_addr, [to], msg.as_bytes())
        return {"ok": True, "from": from_addr}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:180]}


# --- branded e-sign templates ----------------------------------------------------
# LIGHT-DEFAULT, bulletproof transactional email. The composition is deliberate and
# centered: a 600px white card centered on a neutral page, a dark brand header band
# carrying the centered LiftedSign wordmark, a clear headline hierarchy, a single
# prominent centered emerald CTA, the document chip, an optional quote block, and a
# refined footer with the ESIGN/UETA line + envelope id. Every colored region sets
# BOTH a bgcolor= attribute and a CSS background, and every text color sits on an
# explicit opaque fill — so no client can produce invisible text. Each template is
# built body-first then wrapped in _BASE.

# Brand tokens — Lifted Design System, Sign brand scope (data-brand="sign").
# Light card surfaces for the body; the deepest ink (#05080e) only on the brand
# header + footer bands, which carry light text by design. Hexes are the exact DS
# token values (tokens/colors.css) — emails need them inlined.
_PAGE = "#eef1f6"  # outer page canvas (DS email chrome bg)
_CARD = "#ffffff"  # centered email card
_PANEL = "#f5f8fd"  # inner panels / message + code blocks (DS blue-tinted)
_DARK = "#05080e"  # brand header band = DS --void (carries light text by design)
_DARK2 = "#0a0f18"  # footer band (a touch lighter than the header)

_LINE = "#e3e8f0"  # card hairline border
_LINE2 = "#dde5ee"  # panel / doc-card borders
_LINE3 = "#e3e9f4"  # message-block border

_INK = "#0b1020"  # primary text on white = DS --ink-900
_INK2 = "#3a4658"  # secondary body text on white
_MUTE = "#7a8a98"  # muted / labels on white
_FAINT = "#9aa7b6"  # faintest captions on white
_ONDARK = "#eff3f9"  # primary text on the dark bands = DS --mist-100
_ONDARK2 = "#aeb8d0"  # secondary text on the dark bands = DS --mist-300

_EM = "#1E4FD6"  # DS --blue-700 — accent text/labels (AA-readable on white)
_EM_BTN = "#2E6BFF"  # DS --blue — button + accent fill (bulletproof bgcolor)
_EM_BTN2 = "#1E4FD6"  # DS --blue-700 — deep gradient stop for the CTA
_EM_BORDER = "#5E7BFF"  # DS --indigo-bright — button hairline border
_EM_HDR = "#5E7BFF"  # bright blue — used on the dark header/footer (reads there)
_HDR_LABEL = "#7c93c6"  # DS muted eyebrow label on the dark header
_FOOT_LINK = "#5E7BFF"  # bright blue wordmark accent in the footer
_FOOT_ID = "#4a5a78"  # DS --slate-500 — footer id label
_EM_INK = "#ffffff"  # ink-on-blue (button label)
_TINT = "rgba(46,107,255,0.12)"  # DS blue tint for the doc-card icon tile

_RED = "#d64545"  # decline accent (AA on white)
_RED2 = "#b83a3a"
_RED_INK = "#a35b5b"  # decline reason label
_RED_BG = "#fbf3f3"  # decline reason fill
_RED_LN = "#f0dada"  # decline reason border
_AMBER = "#b9760a"  # reminder accent text (DS-tuned, AA on white)
_AMBER_BG = "#fdf4e3"  # reminder pill fill
_AMBER_LN = "#f3dca6"  # reminder pill border
_AMBER_BAR = "#F5A524"  # reminder top-accent bar (DS --warning-ish amber)
_AMBER_TILE = "rgba(245,165,36,0.14)"  # reminder doc-card icon tile

# System font stacks only. NO remote/Google fonts. The DS uses Sora for display
# and JetBrains Mono for ids/codes; both gracefully fall back to client-safe
# system fonts so the email renders identically everywhere.
_DISP = "'Sora',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
_SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
_MONO = "'JetBrains Mono',ui-monospace,'SFMono-Regular',Menlo,Consolas,monospace"


def _preheader(text: str) -> str:
    """Hidden inbox-preview line. Padded so clients don't pull following markup
    into the snippet. Never rendered visibly."""
    pad = "&#847;&zwnj;&nbsp;" * 60
    return (
        f'<span class="ls-preheader" style="display:none!important;visibility:hidden;'
        f"opacity:0;color:transparent;height:0;width:0;max-height:0;max-width:0;"
        f'overflow:hidden;mso-hide:all">{escape(text)}{pad}</span>'
    )


def _asset(path: str) -> str:
    """Absolute URL to an email asset, rooted at the operator's own PUBLIC_BASE_URL —
    never a hardcoded host. Email clients can't run JS, so the animated header lockup
    must be a served GIF; clients that block images fall back to the alt text."""
    return f"{(config.PUBLIC_BASE_URL or '').rstrip('/')}/{path.lstrip('/')}"


_BASE = """<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="x-apple-disable-message-reformatting">
  <meta name="format-detection" content="telephone=no,date=no,address=no,email=no">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <title>Lifted Sign</title>
  <!--[if mso]><style>table,td,div,p,a,h1{{font-family:'Segoe UI',Arial,sans-serif!important}}</style><![endif]-->
  <style>
    /* Progressive enhancement only — the email is fully styled inline without this. */
    body{{margin:0;padding:0;width:100%!important}}
    table{{border-collapse:collapse}}
    img{{border:0;line-height:100%;outline:none;text-decoration:none}}
    a{{color:{_EM}}}
    @media (max-width:620px){{
      .ls-card{{width:100%!important}}
      .ls-pad{{padding-left:24px!important;padding-right:24px!important}}
      .ls-hpad{{padding-left:24px!important;padding-right:24px!important}}
    }}
    @media (prefers-color-scheme:dark){{
      /* Keep it readable in dark mode without breaking the light default. */
      .ls-page{{background-color:#070a12!important}}
      .ls-card{{background-color:#0f1626!important;border-color:#202c46!important}}
      .ls-ink{{color:{_ONDARK}!important}}
      .ls-ink2{{color:#cdd5e4!important}}
      .ls-mute{{color:#aeb8d0!important}}
      .ls-panel{{background-color:#141d31!important;border-color:#202c46!important}}
    }}
  </style>
</head>
<body style="margin:0;padding:0;background-color:{_PAGE};width:100%;\
-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%">
  {{preheader}}
  <!-- full-bleed page background -->
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"
    class="ls-page" bgcolor="{_PAGE}" style="background-color:{_PAGE};width:100%">
  <tr><td align="center" style="padding:34px 16px;font-family:{_SANS}">

    <!-- centered 600px card -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center" width="600"
      class="ls-card" bgcolor="{_CARD}" style="width:600px;max-width:600px;margin:0 auto;
      background-color:{_CARD};border:1px solid {_LINE};border-radius:18px;overflow:hidden;
      box-shadow:0 14px 40px rgba(11,16,32,.12)">

      <!-- dark brand header band: spinning globe lockup over a DS radial blue glow -->
      <tr><td align="center" class="ls-hpad" background="{_DARK}" bgcolor="{_DARK}"
        style="background-color:{_DARK};background-image:radial-gradient(640px 300px at 50% -30%,\
rgba(46,107,255,0.32),rgba(5,8,14,0) 64%);padding:34px 40px 28px">
        <img src="{{logo_src}}" width="208" height="44" alt="Lifted Sign"
          style="display:block;width:208px;height:44px;max-width:208px;margin:0 auto;
          border:0;outline:none;text-decoration:none"/>{{header_disc}}
        <div style="margin-top:14px;font-family:{_MONO};font-size:11px;font-weight:700;
          letter-spacing:.22em;text-transform:uppercase;color:{_HDR_LABEL}">{{eyebrow}}</div>
      </td></tr>
      <!-- DS blue hairline under the header -->
      <tr><td height="3" bgcolor="{{accent}}" style="height:3px;line-height:3px;font-size:0;
        background-color:{{accent}}">&nbsp;</td></tr>

      <!-- white content body -->
      <tr><td class="ls-pad" bgcolor="{_CARD}"
        style="background-color:{_CARD};padding:36px 44px 34px">
        {{body}}
      </td></tr>

      <!-- dark footer band -->
      <tr><td class="ls-pad" bgcolor="{_DARK2}"
        style="background-color:{_DARK2};padding:24px 40px 26px">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"><tr>
          <td style="vertical-align:top;width:30px;padding-right:12px">
            <img src="{{footer_img}}" width="22" height="22" alt=""
              style="display:block;width:22px;height:22px;border-radius:5px;border:0;outline:none;\
text-decoration:none"></td>
          <td style="vertical-align:top;color:{_ONDARK2};font-size:11.5px;line-height:1.7;\
font-family:{_SANS}">
            {{footer_legal}}{{envelope}}
          </td></tr></table>
      </td></tr>

    </table>

    <!-- sub-footer caption -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center" width="600"
      style="width:600px;max-width:600px;margin:0 auto"><tr>
      <td align="center" style="padding:18px 20px 0;color:{_MUTE};font-size:11px;line-height:1.6;
        font-family:{_SANS}">
        Lifted Sign &middot; Sign. Sealed. Delivered.</td></tr></table>

  </td></tr></table>
</body></html>""".format(
    _EM=_EM,
    _PAGE=_PAGE,
    _CARD=_CARD,
    _DARK=_DARK,
    _DARK2=_DARK2,
    _LINE=_LINE,
    _SANS=_SANS,
    _MONO=_MONO,
    _ONDARK=_ONDARK,
    _ONDARK2=_ONDARK2,
    _HDR_LABEL=_HDR_LABEL,
    _MUTE=_MUTE,
)


def _footer_legal() -> str:
    """The footer legal line. The product display name 'Lifted Sign' is constant; the
    operator's legal entity and mailing address come from config (blank ⇒ omitted) —
    no hardcoded company or address survives. The ESIGN/UETA statement is generic law,
    not identity, so it stays."""
    entity = (config.LEGAL_ENTITY or "").strip()
    address = (config.LEGAL_ADDRESS or "").strip()
    entity_part = f"&nbsp;&middot;&nbsp; {escape(entity)}" if entity else ""
    address_part = f"<br>{escape(address)}" if address else ""
    return (
        f'<span style="color:{_FOOT_LINK};font-weight:700;letter-spacing:.02em">Lifted Sign</span>'
        f"{entity_part} &mdash; a legally binding electronic signature under the U.S. ESIGN Act "
        f"(15&nbsp;U.S.C. ch.&nbsp;96) &amp; UETA, recorded in a tamper-evident audit trail and "
        f"Certificate of Completion.{address_part}"
    )


def _wrap(
    body: str,
    preheader: str = "",
    env_id: str = "",
    eyebrow: str = "Signature requested",
    accent: str = _EM_BTN,
    header_disc: str = "",
) -> str:
    """Compose a finished email: drop the per-template body, eyebrow, header accent
    bar colour and (optionally) a header status disc into the bulletproof _BASE shell.
    Asset URLs and the legal footer are resolved from config here so no hardcoded host
    or company name is baked into the templates. eyebrow/accent/header_disc are private
    composition knobs — the public template signatures never change."""
    envelope = ""
    if env_id:
        envelope = (
            f'<br><span style="display:inline-block;margin-top:11px;font-family:{_MONO};'
            f'font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:{_FOOT_ID}">'
            f"Envelope&nbsp;ID:&nbsp;"
            f'<span style="color:{_HDR_LABEL}">{escape(env_id)}</span></span>'
        )
    return (
        _BASE.replace("{preheader}", _preheader(preheader) if preheader else "")
        .replace("{logo_src}", escape(_asset("static/lifted-sign-lockup.gif"), quote=True))
        .replace("{footer_img}", escape(_asset("static/lifted-fp.png"), quote=True))
        .replace("{footer_legal}", _footer_legal())
        .replace("{eyebrow}", escape(eyebrow))
        .replace("{accent}", accent)
        .replace("{header_disc}", header_disc)
        .replace("{envelope}", envelope)
        .replace("{body}", body)
    )


def _safe_url(url: str) -> str:
    """Only allow http(s) links in the href — never javascript:/data: etc."""
    u = (url or "").strip()
    if not (u.startswith("http://") or u.startswith("https://")):
        return "#"
    return escape(u, quote=True)


def _headline(text: str, align: str = "center") -> str:
    return (
        f'<h1 style="font-family:{_DISP};font-size:25px;line-height:1.28;margin:0;'
        f'font-weight:800;letter-spacing:-.02em;color:{_INK};text-align:{align}" '
        f'class="ls-ink">{text}</h1>'
    )


def _lead(text: str) -> str:
    return (
        f'<p style="color:{_INK2};font-size:15px;line-height:1.65;margin:14px auto 0;'
        f'text-align:center;max-width:50ch" class="ls-ink2">{text}</p>'
    )


def _doc_card(doc_name: str, status_label: str, status_color: str, tile_bg: str = _TINT) -> str:
    """DS document chip: a thin coloured accent bar on top, a monospace 'PDF' icon
    tile, the file name, and an uppercase mono status line. Light panel with an
    explicit fill so the dark text on it is always readable. status_color tints the
    accent bar, the tile glyph and the status line; tile_bg tints the tile fill."""
    return f"""
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"
        class="ls-panel" style="margin:24px 0 0;border:1px solid {_LINE2};border-radius:12px;
        overflow:hidden">
        <tr><td height="3" bgcolor="{status_color}" style="height:3px;line-height:3px;font-size:0;
          background-color:{status_color}">&nbsp;</td></tr>
        <tr><td bgcolor="{_CARD}" style="padding:16px 18px;background-color:{_CARD}">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"><tr>
            <td width="40" valign="middle" style="width:40px">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
                <td width="36" height="36" align="center" valign="middle" bgcolor="{_PANEL}"
                  style="width:36px;height:36px;background-color:{tile_bg};border-radius:9px;
                  color:{status_color};font-family:{_MONO};font-size:11px;font-weight:700">PDF</td>
              </tr></table></td>
            <td style="padding-left:14px;vertical-align:middle">
              <div style="font-size:15px;font-weight:700;color:{_INK};font-family:{_SANS}"
                class="ls-ink">{escape(doc_name)}</div>
              <div style="font-family:{_MONO};font-size:10.5px;font-weight:700;letter-spacing:.1em;
                text-transform:uppercase;color:{status_color};margin-top:4px">{escape(status_label)}</div>
            </td></tr></table>
        </td></tr></table>"""


def _status_disc(color1: str, color2: str, mark: str) -> str:
    """A solid 52px DS status disc carrying a bulletproof glyph (HTML entity, centered
    via line-height) — no emoji, no CSS-positioned bars, so it renders identically in
    every client. mark='check' -> &#10003;; mark='x' -> &times;. color1 fills the disc;
    color2 is retained for the signature (legacy gradient stop, unused on the flat fill)."""
    glyph = "&#10003;" if mark == "check" else ("&times;" if mark == "x" else "")
    return (
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center" '
        f'style="margin:0 auto"><tr>'
        f'<td width="52" height="52" align="center" valign="middle" bgcolor="{color1}" '
        f'style="width:52px;height:52px;background-color:{color1};border-radius:50%;color:#ffffff;'
        f"font-family:{_MONO};font-size:24px;font-weight:700;line-height:52px;"
        f'text-align:center">{glyph}</td></tr></table>'
    )


def _status_header(color1: str, color2: str, mark: str, title: str) -> str:
    """Centered status disc + title stack for the completed / declined emails."""
    return f"""
      {_status_disc(color1, color2, mark)}
      <div style="height:16px;line-height:16px;font-size:0">&nbsp;</div>
      {_headline(title)}"""


def _cta(url: str, label: str) -> str:
    """A big, branded, bulletproof, CENTERED CTA in DS Sign blue. VML roundrect renders a
    solid blue pill in Outlook; everyone else gets the solid #2E6BFF fill with an
    indigo-bright hairline border (the DS button treatment)."""
    safe = _safe_url(url)
    return f"""
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center"
        style="margin:28px auto 6px"><tr><td align="center" bgcolor="{_EM_BTN}"
        style="border-radius:12px;background-color:{_EM_BTN}">
        <!--[if mso]>
        <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word"
          href="{safe}" style="height:52px;v-text-anchor:middle;width:280px" arcsize="23%"
          stroke="f" fillcolor="{_EM_BTN}">
          <w:anchorlock/><center style="color:{_EM_INK};font-family:'Segoe UI',Arial,sans-serif;
            font-size:16px;font-weight:bold">{escape(label)}</center>
        </v:roundrect>
        <![endif]-->
        <!--[if !mso]><!-- -->
        <a href="{safe}" target="_blank" style="display:inline-block;
          background-color:{_EM_BTN};color:{_EM_INK};text-decoration:none;
          font-family:{_SANS};font-weight:700;font-size:16px;line-height:1;padding:16px 40px;
          border-radius:12px;letter-spacing:.01em;border:1px solid {_EM_BORDER}">{escape(label)}</a>
        <!--<![endif]-->
      </td></tr></table>"""


def _fallback_link(url: str, note: str = "Button not working? Copy and paste this link:") -> str:
    return (
        f'<p style="color:{_FAINT};font-size:11.5px;line-height:1.6;margin:12px 0 0;text-align:center" '
        f'class="ls-mute">{escape(note)}<br>'
        f'<span style="font-family:{_MONO};color:{_EM};word-break:break-all">{escape(url)}</span></p>'
    )


def _quote_block(message: str) -> str:
    """Optional sender note, rendered as a DS message block: a blue-tinted panel with a
    blue left rule. Plain (non-italic) per the DS reference."""
    if not (message and message.strip()):
        return ""
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'class="ls-panel" bgcolor="{_PANEL}" style="margin:16px 0 0;background-color:{_PANEL};'
        f'border:1px solid {_LINE3};border-left:3px solid {_EM_BTN};border-radius:10px"><tr>'
        f'<td style="padding:14px 18px;color:{_INK2};font-size:14px;line-height:1.65" '
        f'class="ls-ink2">'
        f"{escape(message).replace(chr(10), '<br>')}</td></tr></table>"
    )


def _note(text: str) -> str:
    return (
        f'<p style="color:{_MUTE};font-size:12px;line-height:1.6;margin:14px 0 0;'
        f'text-align:center" class="ls-mute">{text}</p>'
    )


def _greeting(name: str) -> str:
    if name and name.strip():
        return f"Hi {escape(name.strip().split()[0])},"
    return "Hello,"


def invite_html(
    signer_name: str, doc_name: str, message: str, url: str, sender: str = "A sender"
) -> str:
    """Signature-requested invite. Everything is interpolated into HTML that lands in an
    external signer's inbox — escape all values (HTML email injection / phishing) and
    constrain the link to http(s). `sender` is a neutral default (no hardcoded identity);
    callers pass the real agreement creator's name."""
    pre = f"{(sender or 'A sender').strip()} has requested your signature on {doc_name}."
    body = f"""
      <p style="font-size:13px;color:{_MUTE};margin:0 0 12px;text-align:center" class="ls-mute">{
        _greeting(signer_name)
    }</p>
      {_headline(f"{escape(sender)} has requested<br>your signature")}
      {
        _lead(
            "You've been invited to review and electronically sign the document below. "
            "It takes about a minute &mdash; no account required."
        )
    }
      {_doc_card(doc_name, "Awaiting your signature", _EM_BTN)}
      {_quote_block(message)}
      {_cta(url, "Review & Sign")}
      {_note("This is your personal, single-use signing link &mdash; please don't forward it.")}
      {_fallback_link(url)}"""
    return _wrap(body, preheader=pre, eyebrow="Signature requested", accent=_EM_BTN)


def reminder_html(
    signer_name: str, doc_name: str, message: str, url: str, sender: str = "A sender"
) -> str:
    """Friendly nudge when a signature is still outstanding. Same premium look as the
    invite, an amber 'Reminder' pill, distinct headline and CTA."""
    pre = f"Reminder: your signature is still needed on {doc_name}."
    body = f"""
      <p style="font-size:13px;color:{_MUTE};margin:0 0 14px;text-align:center" class="ls-mute">{
        _greeting(signer_name)
    }</p>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center"
        style="margin:0 auto 14px"><tr><td align="center" bgcolor="{_AMBER_BG}"
        style="background-color:{_AMBER_BG};border:1px solid {_AMBER_LN};border-radius:999px;
        padding:6px 16px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
        color:{_AMBER}">Reminder</td></tr></table>
      {_headline("Your signature is still needed")}
      {
        _lead(
            f"Just a gentle nudge &mdash; {escape(sender)} is waiting on your signature for the "
            "document below. It only takes a minute to complete."
        )
    }
      {_doc_card(doc_name, "Awaiting your signature", _AMBER, tile_bg=_AMBER_TILE)}
      {_quote_block(message)}
      {_cta(url, "Review & Sign Now")}
      {_note("Already signed? You can safely ignore this reminder.")}
      {_fallback_link(url)}"""
    return _wrap(body, preheader=pre, eyebrow="A gentle reminder", accent=_AMBER_BAR)


def completed_html(
    doc_name: str, env_id: str, envelope_url: str = "", seal_method: str = "pades"
) -> str:
    """All-parties-signed confirmation. The sealed, fully-executed PDF + the LiftedSign
    Certificate of Completion are attached by the caller; this message announces it and
    carries the envelope id for the audit trail. `envelope_url` (optional) adds a CTA to the
    signer's secure verified-access envelope page to re-download / track anytime.

    `seal_method` selects the accurate seal wording ('pades' → a PKCS#7/PAdES certification
    signature; anything else → the AES-256 integrity seal used when no signing cert is
    configured), so the email never misstates how the document was sealed."""
    seal_desc = (
        "digitally signed with a PAdES certification signature"
        if seal_method == "pades"
        else "tamper-sealed (AES-256 integrity seal)"
    )
    pre = f"Signed & completed: {doc_name}. Your sealed copy is attached."
    body = f"""
      {_headline("Signed &amp; completed")}
      {
        _lead(
            f"All parties have signed <b style='color:{_INK}'>{escape(doc_name)}</b>. The "
            f"fully-executed copy, sealed and bundled with the LiftedSign "
            f"<b style='color:{_INK}'>Certificate of Completion</b>, is attached to this email "
            f"for your records."
        )
    }
      {_doc_card(doc_name, "Completed &middot; sealed", _EM_BTN)}
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"
        class="ls-panel" bgcolor="{_PANEL}" style="margin:14px 0 0;background-color:{_PANEL};
        border:1px solid {_LINE3};border-radius:12px"><tr>
        <td style="vertical-align:top;width:36px;padding:15px 0 15px 18px">
          <div style="width:14px;height:14px;border:2px solid {_EM_BTN};border-radius:50% 50% 50% 0;
            transform:rotate(-45deg);margin-top:2px"></div></td>
        <td style="padding:14px 18px 14px 6px;color:{
        _INK2
    };font-size:12.5px;line-height:1.7" class="ls-ink2">
          <b style="color:{_INK}" class="ls-ink">Attached:</b> the fully-executed PDF, {
        seal_desc
    }, plus a
          Certificate of Completion listing each signer, authentication method, IP, and per-action
          UTC timestamps. Keep this copy &mdash; it is your accurate, reproducible record under
          ESIGN &sect;7001(d) / UETA &sect;12.</td></tr></table>
      {
        (
            f'<p style="text-align:center;color:{_INK2};font-size:12.5px;line-height:1.6;margin:20px 0 0" class="ls-ink2">'
            f"Need it again later? Open your secure envelope page and verify your email to see and "
            f'download <b style="color:{_INK}" class="ls-ink">every document addressed to you</b> &mdash; not '
            f"just this one. Documents you receive over time all appear there.</p>"
            + _cta(envelope_url, "View this & all your documents")
        )
        if envelope_url
        else ""
    }
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%"
        bgcolor="{_DARK}" style="margin:22px 0 0;background-color:{_DARK};border-radius:12px"><tr>
        <td align="center" style="padding:18px 22px">
          <div style="font-size:13px;color:{_ONDARK2};line-height:1.6;margin-bottom:12px">
            Your records are complete and securely stored.</div>
          <div style="font-family:{
        _MONO
    };font-size:10px;letter-spacing:.2em;text-transform:uppercase;\
color:{_ONDARK2}">Powered by</div>
          <div style="font-family:{
        _DISP
    };font-size:18px;font-weight:800;letter-spacing:.01em;margin-top:5px">
            <span style="color:{_ONDARK}">Lifted</span><span style="color:{
        _EM_HDR
    }">Sign</span></div>
        </td></tr></table>"""
    return _wrap(
        body,
        preheader=pre,
        env_id=env_id,
        eyebrow="Signed &amp; completed",
        accent=_EM_BTN,
        header_disc='<div style="height:18px;line-height:18px;font-size:0">&nbsp;</div>'
        + _status_disc(_EM_BTN, _EM_BTN2, "check"),
    )


def envelope_html(signer_name: str, doc_name: str, env_id: str, url: str) -> str:
    """ "View / track your envelope" link. Sent to a signer (or alongside the completed
    notice) so they can return to a secure, verified-access page to watch every party's
    progress and, once finished, download their sealed copy and Certificate of Completion
    anytime. Identity is re-proven (Google sign-in or a one-time code) on that page before
    anything is shown — this email reveals nothing and the link is not a bypass.

    Reuses the same light-default, bulletproof helpers as every other template; escape all
    values (HTML email injection / phishing) and constrain the link to http(s). The
    Envelope ID prints in the footer (env_id) for the audit trail."""
    pre = (
        f"View status, all parties' progress, and download your sealed copy of {doc_name} anytime."
    )
    body = f"""
      <p style="font-size:13px;color:{_MUTE};margin:0 0 12px;text-align:center" class="ls-mute">{
        _greeting(signer_name)
    }</p>
      {_headline("Track &amp; access your envelope")}
      {
        _lead(
            "View status, all parties' progress, and download your sealed copy and "
            "certificate anytime &mdash; securely."
        )
    }
      {_doc_card(doc_name, "Your envelope", _EM_BTN)}
      {_cta(url, "Open my envelope")}
      {
        _note(
            "You'll verify it's you (Google sign-in or a one-time code) before anything is shown."
        )
    }
      {_fallback_link(url)}"""
    return _wrap(body, preheader=pre, env_id=env_id, eyebrow="Secure access", accent=_EM_BTN)


def otp_html(code: str) -> str:
    """One-time verification code email for envelope access. Reveals nothing about the
    document — the code is the only sensitive content."""
    c = escape((code or "").strip())
    pre = "Your Lifted Sign verification code — expires in 10 minutes."
    body = f"""
      {_headline("Your verification code")}
      {
        _lead(
            "Enter this code on the Lifted Sign page to securely access your envelope. "
            "It expires in 10 minutes."
        )
    }
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" align="center"
        style="margin:26px 0 6px"><tr><td align="center">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
          <td align="center" bgcolor="{_PANEL}" style="background-color:{_PANEL};
            border:1px solid {_LINE2};border-radius:14px;padding:20px 36px;font-family:{_MONO};
            font-size:34px;font-weight:700;letter-spacing:.32em;color:{_INK}" class="ls-ink">{
        c
    }</td>
        </tr></table></td></tr></table>
      {
        _note(
            "If you didn't request this code, you can safely ignore this email &mdash; no one can "
            "access your documents without it."
        )
    }"""
    return _wrap(body, preheader=pre, eyebrow="Secure access", accent=_EM_BTN)


def declined_html(doc_name: str, decliner_name: str, reason: str, env_id: str) -> str:
    """Sent to the sender when a signer declines to sign. Red accent, names the decliner
    and their stated reason (if any)."""
    who = (decliner_name or "").strip() or "A signer"
    pre = f"{who} declined to sign {doc_name}."
    if reason and reason.strip():
        reason_html = (
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
            f'class="ls-panel" bgcolor="{_RED_BG}" style="margin:14px 0 0;background-color:{_RED_BG};'
            f'border:1px solid {_RED_LN};border-left:3px solid {_RED};border-radius:10px"><tr>'
            f'<td style="padding:14px 18px;color:{_INK2};font-size:14px;line-height:1.65" class="ls-ink2">'
            f'<div style="font-family:{_MONO};font-size:11px;letter-spacing:.06em;'
            f"text-transform:uppercase;color:{_RED_INK};"
            f'font-weight:700;margin-bottom:6px">Reason given</div>'
            f"{escape(reason).replace(chr(10), '<br>')}</td></tr></table>"
        )
    else:
        reason_html = (
            f'<p style="color:{_MUTE};font-size:13px;line-height:1.6;margin:14px 0 0;'
            f'text-align:center" class="ls-mute">No reason was provided.</p>'
        )
    body = f"""
      {_headline("Signature declined")}
      {
        _lead(
            f"<b style='color:{_INK}'>{escape(who)}</b> declined to sign "
            f"<b style='color:{_INK}'>{escape(doc_name)}</b>. The envelope has been marked "
            f"<b style='color:{_RED}'>declined</b> and no further signatures will be collected."
        )
    }
      {_doc_card(doc_name, "Declined", _RED, tile_bg="rgba(214,69,69,0.12)")}
      {reason_html}
      {
        _note(
            "You can revise the document and start a new envelope, or reach out to the signer "
            "directly to resolve their concern."
        )
    }"""
    return _wrap(
        body,
        preheader=pre,
        env_id=env_id,
        eyebrow="Signature declined",
        accent=_RED,
        header_disc='<div style="height:18px;line-height:18px;font-size:0">&nbsp;</div>'
        + _status_disc(_RED, _RED2, "x"),
    )


def expired_html(doc_name: str, env_id: str) -> str:
    """Sent to the SENDER (never the signers) when an envelope auto-expires — its signing window
    elapsed before everyone signed. Amber accent; prompts the sender to send a fresh request."""
    pre = f"Your signing request {doc_name} has expired."
    body = f"""
      {_headline("Signing request expired")}
      {
        _lead(
            f"Your envelope <b style='color:{_INK}'>{escape(doc_name)}</b> reached its signing "
            f"deadline before all signatures were collected, so it has been marked "
            f"<b style='color:{_AMBER}'>expired</b>. Existing signers can no longer sign it."
        )
    }
      {_doc_card(doc_name, "Expired", _AMBER, tile_bg=_AMBER_TILE)}
      {
        _note(
            "To keep it moving, create a new envelope from the same document and send a fresh "
            "request. Anyone who already signed will need to sign the new copy."
        )
    }"""
    return _wrap(
        body, preheader=pre, env_id=env_id, eyebrow="Signing request expired", accent=_AMBER_BAR
    )
