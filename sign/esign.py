"""Native e-signature engine — ESIGN/UETA-compliant, no third-party service.

An *agreement* = a PDF + ordered/parallel *signers* + placed *fields*. Sending mints a
per-signer token; the signer opens a hosted page (IP + user-agent logged on view),
fills their fields, draws/types a signature, consents, and submits (IP + timestamp
logged). When every signer is done we stamp all values into the PDF, append a
tamper-evident Signature Certificate (parties + full IP-stamped audit trail + SHA-256),
and store the executed copy.

Field types (Adobe-parity): signature, initials, date, name, email, title, company,
text, checkbox. Every state transition is recorded in agreement_events for the audit.
"""

from __future__ import annotations

import datetime
import io
import json
import logging
import re
import secrets
import time
from pathlib import Path
from typing import Any

from . import config as _cfg
from . import db, esign_disclosure, mailer, pdf_edit, pdf_ops, pdf_sign

log = logging.getLogger(__name__)

# Public brand text surfaced to the signer page (no secrets — safe to serialize). The signer page
# is styled entirely by the Lifted DS (data-brand="sign" → blue); the old emerald color tokens +
# applyBrand() colour plumbing were dead after the DS rebuild (the page never referenced them) and
# were removed. Only the wordmark/company text is consumed today. (Per-sender white-label is a
# roadmap item, not a shipped capability.)
_BRAND = {
    "name": "Lifted Sign",
    "wordmark": "Lifted Sign",
    # Operator's legal entity (blank by default; set via LEGAL_ENTITY). Surfaced on the
    # signer page footer — never a hardcoded company name in this public build.
    "company": _cfg.LEGAL_ENTITY,
}


def _fmt_signed(ts) -> str:
    """Local datetime label for the on-page signature stamp (e.g. '2026-06-04 18:39 CDT')."""
    if not ts:
        return ""
    try:
        d = datetime.datetime.fromtimestamp(float(ts)).astimezone()
        return d.strftime("%Y-%m-%d %H:%M ") + (d.tzname() or "")
    except Exception:
        return ""


ESIGN_DIR = _cfg.DATA_DIR / "esign"
SIGNER_COLORS = ["#7c6cff", "#22c55e", "#f59e0b", "#ec4899", "#06b6d4", "#ef4444"]
# L-20: a leaked invite link must not stay valid forever. Block NEW signing actions on a
# token once the agreement is older than this (viewing completed/executed copies is unaffected).
# Generous window so legitimate slow signers aren't cut off.
SIGN_TOKEN_TTL_DAYS = 60
# EXPIRY (Phase-1): an out_for_signature envelope auto-expires this many days after send. Kept in
# lockstep with the link TTL so a link isn't time-blocked while the envelope still reads as open.
ESIGN_EXPIRY_DAYS = 60
# A finalize() 'sealing' claim older than this is an abandoned seal (the process died
# out-of-band before completing or releasing) and may be reclaimed. Must exceed the worst-case
# seal duration (stamp + PAdES + email), which is seconds; 120s is a wide safety margin.
_SEAL_STALE_S = 120


def _sender_email(agr: dict | None = None) -> str:
    """L-23: resolve the address that should receive sender notifications (decline alerts,
    executed-copy CC). Prefer the agreement's own creator/sender when it's an email address,
    else the configured MAIL_FROM. Keeps a sane default so nothing breaks when the creator is a
    display name (e.g. 'Will') or missing; a blank MAIL_FROM is fine — mailer console-mode
    handles an empty from/notify address."""
    cb = ((agr or {}).get("created_by") or "").strip() if agr else ""
    if "@" in cb and "." in cb.split("@")[-1]:
        return cb
    cfg = _cfg.local().get("esign", {}) or {}
    dflt = (cfg.get("sender_email") or cfg.get("notify_email") or "").strip()
    if dflt:
        return dflt
    return _cfg.MAIL_FROM


def _token_expired(agr: dict) -> bool:
    """L-20: True when the signing link is older than SIGN_TOKEN_TTL_DAYS. The TTL clock starts
    at SEND (sent_at), not draft creation — a draft that sat for months then sent must give the
    signer the full window, not dead links on arrival. Falls back to created_at for legacy rows.
    Already-executed copies remain viewable elsewhere."""
    try:
        created = float(agr.get("sent_at") or agr.get("created_at") or 0)
    except Exception:
        return False
    if created <= 0:
        return False
    return (time.time() - created) > SIGN_TOKEN_TTL_DAYS * 86400


def signer_render_blocked(token: str) -> str | None:
    """Terminal-status/expiry gate for the PUBLIC signing surface (page images + actions).
    Returns 'invalid' | 'revoked' | 'expired' when the token must NOT render/act, else None.
    Completed / already-signed stay viewable (the done screen re-fetches page images), so only
    voided/cancelled/declined and expired-for-unsigned are blocked. Mirrors signing_payload's
    gate so the page-image route can't leak a revoked/expired document."""
    conn = db.connect()
    try:
        s = _signer_by_token(conn, token)
        if not s:
            return "invalid"
        agr = get_agreement(s["agreement_id"])
        if not agr:
            return "invalid"
        if agr["status"] in ("voided", "cancelled", "declined"):
            return "revoked"
        if agr["status"] == "expired":
            return "expired"
        if s["status"] != "signed" and agr["status"] != "completed" and _token_expired(agr):
            return "expired"
        return None
    finally:
        conn.close()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS agreements (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, message TEXT DEFAULT '',
  status TEXT DEFAULT 'draft', created_by TEXT DEFAULT '', order_mode TEXT DEFAULT 'parallel',
  source_path TEXT DEFAULT '', executed_path TEXT DEFAULT '', doc_hash TEXT DEFAULT '',
  created_at REAL, sent_at REAL, completed_at REAL);
CREATE TABLE IF NOT EXISTS agreement_signers (
  id INTEGER PRIMARY KEY AUTOINCREMENT, agreement_id INTEGER NOT NULL,
  name TEXT, email TEXT, role TEXT DEFAULT 'signer', sign_order INTEGER DEFAULT 1,
  color TEXT DEFAULT '', token TEXT, status TEXT DEFAULT 'pending',
  viewed_at REAL, signed_at REAL, ip TEXT DEFAULT '', user_agent TEXT DEFAULT '',
  consent INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS agreement_fields (
  id INTEGER PRIMARY KEY AUTOINCREMENT, agreement_id INTEGER NOT NULL, signer_id INTEGER,
  type TEXT, page INTEGER DEFAULT 0, x REAL, y REAL, w REAL, h REAL,
  required INTEGER DEFAULT 1, value TEXT DEFAULT '', placeholder TEXT DEFAULT '',
  prefill INTEGER DEFAULT 0, prompt TEXT DEFAULT '', field_key TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS agreement_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, agreement_id INTEGER NOT NULL, signer_id INTEGER,
  type TEXT, ip TEXT DEFAULT '', user_agent TEXT DEFAULT '', detail TEXT DEFAULT '', at REAL);
CREATE INDEX IF NOT EXISTS idx_signers_agr ON agreement_signers(agreement_id);
CREATE INDEX IF NOT EXISTS idx_fields_agr ON agreement_fields(agreement_id);
CREATE INDEX IF NOT EXISTS idx_events_agr ON agreement_events(agreement_id);
-- Named, persisted reusable TEMPLATES (esign-templates cluster). Additive: a template is a
-- snapshot of a reusable layout — the blank source PDF (by path and/or company-doc id) plus the
-- signer ROLES and the placed FIELD layout, stored as JSON so a fresh agreement can be
-- instantiated from it without touching the agreements/agreement_signers/agreement_fields tables.
-- signers_json = [{name,email,role,order,is_consumer,auth}]; fields_json = [{signer_index,type,
-- page,x,y,w,h,required,value,placeholder}] where signer_index points into signers_json.
CREATE TABLE IF NOT EXISTS esign_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, created_by TEXT DEFAULT '',
  source_path TEXT DEFAULT '', doc_hash TEXT DEFAULT '', source_doc_id INTEGER,
  source_agreement_id INTEGER, signers_json TEXT DEFAULT '[]', fields_json TEXT DEFAULT '[]',
  page_n INTEGER DEFAULT 0, created_at REAL, archived_at REAL);
CREATE INDEX IF NOT EXISTS idx_tpl_arch ON esign_templates(archived_at);
"""


def ensure_tables() -> None:
    conn = db.connect()
    try:
        conn.executescript(_SCHEMA)
        # additive migrations (envelope/transaction id + per-signature id)
        acols = db._columns(conn, "agreements")
        if "envelope_id" not in acols:
            conn.execute("ALTER TABLE agreements ADD COLUMN envelope_id TEXT DEFAULT ''")
        if "source_doc_id" not in acols:  # link back to the Company Doc it was opened from
            conn.execute("ALTER TABLE agreements ADD COLUMN source_doc_id INTEGER")
        # frozen-on-send + tamper-seal hash chain (additive)
        for col, ddl in (
            ("frozen_path", "frozen_path TEXT DEFAULT ''"),
            ("frozen_hash", "frozen_hash TEXT DEFAULT ''"),
            ("sealed_hash", "sealed_hash TEXT DEFAULT ''"),
            ("preseal_hash", "preseal_hash TEXT DEFAULT ''"),
            # How the executed copy was sealed: 'pades' (real PAdES certification
            # signature, DocMDP L1) when a signing cert is configured, else 'aes'
            # (the AES-256 fallback). Read back by certificate_bytes() so the standalone
            # cert preview states the same method as the embedded one.
            ("seal_method", "seal_method TEXT DEFAULT ''"),
            # TRAN-2: per-envelope session revocation epoch. A sender "revoke all envelope
            # access" (or a void) bumps this; env-session tokens embed the epoch at mint and
            # require_env_session denies on mismatch. Mirrors hub_db.admin_session_version.
            ("env_session_epoch", "env_session_epoch INTEGER DEFAULT 0"),
            # LiftedSign multi-tenant owner (sign_accounts.id). NULL = legacy admin/Will rows —
            # never surfaced to any sender account. The tenant scoping choke-point (SIGN-TENANT-1):
            # /api/mysign/* reads/writes filter on this column; NULL rows fail every WHERE
            # owner_account_id=? (NULL never equals a value) so admin's docs stay invisible.
            ("owner_account_id", "owner_account_id INTEGER"),
            # finalize()'s atomic seal claim stamps this when it sets status='sealing'. A
            # 'sealing' row whose sealing_at is older than _SEAL_STALE_S is treated as an
            # ABANDONED seal (the process died out-of-band — OOM/redeploy/SIGKILL) and is
            # reclaimable, so an interrupted seal self-heals instead of stranding forever.
            ("sealing_at", "sealing_at REAL"),
            # EDIT-TEXT: comma-separated 0-based page indices that received an in-place text
            # edit (edit_texts). At send-time these pages are rasterized into the frozen
            # snapshot so the sent PDF's visible text == its extracted text (closes the
            # vector-cover remanence of edit-in-place). '' = no edits.
            ("edited_pages", "edited_pages TEXT DEFAULT ''"),
            # EXPIRY (Phase-1): expires_at is stamped at send (now + ESIGN_EXPIRY_DAYS); the
            # background sweep flips out_for_signature envelopes past it to status='expired' and
            # records expired_at. NULL expires_at (legacy/in-flight sends) never expires (safe).
            ("expires_at", "expires_at REAL"),
            ("expired_at", "expired_at REAL"),
        ):
            if col not in acols:
                conn.execute(f"ALTER TABLE agreements ADD COLUMN {ddl}")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agreements_owner ON agreements(owner_account_id)"
        )
        # SIGN-TENANT: owner-scope templates too (mirror agreements). NULL = legacy admin/Will
        # templates, invisible to every tenant (NULL never satisfies owner_account_id=?).
        tcols = db._columns(conn, "esign_templates")
        if "owner_account_id" not in tcols:
            conn.execute("ALTER TABLE esign_templates ADD COLUMN owner_account_id INTEGER")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tpl_owner ON esign_templates(owner_account_id)"
        )
        scols = db._columns(conn, "agreement_signers")
        if "signature_id" not in scols:
            conn.execute("ALTER TABLE agreement_signers ADD COLUMN signature_id TEXT DEFAULT ''")
        # ESIGN/UETA consent + attribution columns (additive; defaults preserve B2B flow)
        # SECURITY / DATA-MINIMIZATION (PII-1): challenge_hash stores ONLY a salted PBKDF2 digest of a
        # normalized expected value — NEVER the plaintext. For low-entropy types (ssn_last4 = 10^4, dob)
        # the hash is offline-brute-forceable in milliseconds, so it provides confidentiality only against
        # casual DB reads, NOT a determined attacker; the REAL defense is online rate-limit + lockout
        # (db.auth_limit_*). Full 'ssn' is offered but labeled "not recommended" in the admin UI and SHOULD
        # be avoided (GLBA / state SSN-protection breach exposure with negligible security benefit).
        # L-38: the legacy `otp_code` column was DROPPED from this schema — an OTP code is NEVER
        # persisted (the self-issued email OTP keeps only an HMAC in settings; see esign_access),
        # so the column was dead (created, never written, never read). Existing DBs keep the now-
        # unused column harmlessly; new DBs simply don't create it.
        for col, ddl in (
            ("is_consumer", "is_consumer INTEGER DEFAULT 0"),
            ("auth_method", "auth_method TEXT DEFAULT 'email'"),
            ("consent_at", "consent_at REAL"),
            ("consent_ip", "consent_ip TEXT DEFAULT ''"),
            ("disclosure_version", "disclosure_version TEXT DEFAULT ''"),
            ("disclosure_text_hash", "disclosure_text_hash TEXT DEFAULT ''"),
            ("access_demonstrated", "access_demonstrated INTEGER DEFAULT 0"),
            ("access_method", "access_method TEXT DEFAULT ''"),
            ("consent_withdrawn_at", "consent_withdrawn_at REAL"),
            ("otp_verified_at", "otp_verified_at REAL"),
            # Sender access-lock challenge (CHAL-1). challenge_hash = Fernet-wrapped base64(pbkdf2 digest).
            (
                "challenge_type",
                "challenge_type TEXT DEFAULT 'none'",
            ),  # none|code|text|dob|ssn|ssn_last4
            (
                "challenge_prompt",
                "challenge_prompt TEXT DEFAULT ''",
            ),  # shown to signer; NEVER the answer
            (
                "challenge_salt",
                "challenge_salt TEXT DEFAULT ''",
            ),  # base64(16 random bytes); '' when none
            (
                "challenge_hash",
                "challenge_hash TEXT DEFAULT ''",
            ),  # Fernet-wrapped base64(pbkdf2 digest); '' when none
            (
                "challenge_iters",
                "challenge_iters INTEGER DEFAULT 0",
            ),  # PBKDF2 iterations actually used (>=200000)
            # CHAL-4: signing-page "challenge passed" marker (envelope page uses chal_ok in the session token)
            ("challenge_passed_at", "challenge_passed_at REAL"),
            # ENV-8 / CERT-3: identity-verification evidence captured opening the ENVELOPE session
            (
                "env_auth_method",
                "env_auth_method TEXT DEFAULT ''",
            ),  # 'google' | 'otp:email' | 'otp:sms'
            ("env_auth_at", "env_auth_at REAL"),  # timestamp of that mint
            (
                "env_auth_email",
                "env_auth_email TEXT DEFAULT ''",
            ),  # google-verified email (only for method=google)
        ):
            if col not in scols:
                conn.execute(f"ALTER TABLE agreement_signers ADD COLUMN {ddl}")
        fcols = db._columns(conn, "agreement_fields")
        for col, ddl in (
            ("adopted_at", "adopted_at REAL"),
            ("sign_method", "sign_method TEXT DEFAULT ''"),
            # SMART TEMPLATES: a prefill field is filled by the SENDER (not a signer) — its `prompt`
            # is the questionnaire question shown at template-use time; field_key is a stable id.
            ("prefill", "prefill INTEGER DEFAULT 0"),
            ("prompt", "prompt TEXT DEFAULT ''"),
            ("field_key", "field_key TEXT DEFAULT ''"),
        ):
            if col not in fcols:
                conn.execute(f"ALTER TABLE agreement_fields ADD COLUMN {ddl}")
        conn.commit()
    finally:
        conn.close()


def _envelope_id() -> str:
    return "LS-" + secrets.token_hex(12).upper()  # LiftedSign envelope/transaction id


def _signature_id() -> str:
    return "LS-SIG-" + secrets.token_hex(8).upper()


# Access-challenge + envelope-access event types. detail is TYPE-ONLY (CHAL-6) — a raw
# challenge value, SSN, DOB, or OTP MUST NEVER be passed into _event() with these.
ACCESS_CHALLENGE_PASSED = "ACCESS_CHALLENGE_PASSED"  # detail="type=dob"
ACCESS_CHALLENGE_FAILED = "ACCESS_CHALLENGE_FAILED"  # detail="type=last4"
ACCESS_CHALLENGE_LOCKED = "ACCESS_CHALLENGE_LOCKED"  # detail="type=ssn_last4"
ACCESS_CHALLENGE_CONFIGURED = "ACCESS_CHALLENGE_CONFIGURED"  # admin setup (CHAL-7); never the value
ENVELOPE_ACCESS_VERIFIED = (
    "ENVELOPE_ACCESS_VERIFIED"  # detail="google:a@b.com" / "otp:sms" / "otp:email"
)
ENVELOPE_VIEWED = "ENVELOPE_VIEWED"  # detail="envelope page"
_CHALLENGE_EVENTS = (
    ACCESS_CHALLENGE_PASSED,
    ACCESS_CHALLENGE_FAILED,
    ACCESS_CHALLENGE_LOCKED,
    ACCESS_CHALLENGE_CONFIGURED,
    ENVELOPE_ACCESS_VERIFIED,
    ENVELOPE_VIEWED,
)


# Secret signer columns stripped from EVERY serialized/admin/client payload (CHAL-7 / PII-2).
# Only esign_access.py reads these — and only via the dedicated raw accessors below.
_SIGNER_SECRET_COLS = (
    "challenge_hash",
    "challenge_salt",
    "challenge_iters",
)


def _strip_signer_secrets(s: dict) -> dict:
    for k in _SIGNER_SECRET_COLS:
        s.pop(k, None)
    # expose a boolean the UI needs without revealing anything
    s["has_challenge"] = (s.get("challenge_type") or "none") != "none"
    return s


ensure_tables()
ESIGN_DIR.mkdir(parents=True, exist_ok=True)


# --- helpers ---------------------------------------------------------------------
def _rows(cur) -> list[dict]:
    return [dict(r) for r in cur.fetchall()]


def _event(
    conn,
    agreement_id: int,
    etype: str,
    signer_id: int | None = None,
    ip: str = "",
    ua: str = "",
    detail: str = "",
) -> None:
    conn.execute(
        "INSERT INTO agreement_events(agreement_id,signer_id,type,ip,user_agent,detail,at)"
        " VALUES(?,?,?,?,?,?,?)",
        (agreement_id, signer_id, etype, ip, ua[:300], detail[:300], time.time()),
    )


# --- create / edit ---------------------------------------------------------------
def create_agreement(
    name: str,
    pdf_bytes: bytes,
    message: str = "",
    created_by: str = "Will",
    source_doc_id: int | None = None,
    owner_account_id: int | None = None,
) -> int:
    # SIGN-TENANT-1: owner_account_id stamps the sending sign_account (NULL for the admin/Will
    # path). This is the tenant identity every /api/mysign/* query scopes on — created_by is a
    # free-text display name and is NEVER used for authorization.
    conn = db.connect()
    try:
        aid = db.insert_returning(
            conn,
            "INSERT INTO agreements(name,message,status,created_by,created_at,source_doc_id,owner_account_id)"
            " VALUES(?,?,?,?,?,?,?)",
            (
                name or "Untitled",
                message,
                "draft",
                created_by,
                time.time(),
                source_doc_id,
                owner_account_id,
            ),
        )
        path = ESIGN_DIR / f"agr_{aid}_source.pdf"
        path.write_bytes(pdf_bytes)
        conn.execute(
            "UPDATE agreements SET source_path=?, doc_hash=?, envelope_id=? WHERE id=?",
            (str(path), pdf_edit.sha256(pdf_bytes), _envelope_id(), aid),
        )
        _event(conn, aid, "created", detail=f"{pdf_edit.page_count(pdf_bytes)} pages")
        conn.commit()
        return aid
    finally:
        conn.close()


def _source_bytes(agr: dict) -> bytes:
    return Path(agr["source_path"]).read_bytes()


def _presented_bytes(agr: dict) -> bytes:
    """The exact bytes shown to signers: the frozen-on-send snapshot when present
    (post-send immutability), else the live source (drafts / legacy agreements)."""
    fp = agr.get("frozen_path")
    if fp and Path(fp).exists():
        return Path(fp).read_bytes()
    return _source_bytes(agr)


def page_spans(agreement_id: int, page: int) -> list[dict]:
    """Existing text spans on a page (for click-to-edit in the editor)."""
    agr = get_agreement(agreement_id)
    if not agr:
        return []
    return pdf_edit.page_text_spans(_source_bytes(agr), page)


def apply_edits(agreement_id: int, edits: list[dict]) -> bool:
    agr = get_agreement(agreement_id)
    if not agr or agr["status"] != "draft":
        return False
    try:
        new = pdf_edit.apply_edits(_source_bytes(agr), edits)
    except ValueError:
        # Overflowing add-text raises rather than silently dropping lines — fail closed.
        return False
    Path(agr["source_path"]).write_bytes(new)
    conn = db.connect()
    try:
        conn.execute(
            "UPDATE agreements SET doc_hash=? WHERE id=?",
            (pdf_edit.sha256(new), agreement_id),
        )
        _event(conn, agreement_id, "edited", detail=f"{len(edits)} edit(s)")
        conn.commit()
    finally:
        conn.close()
    return True


# --- page operations (reorder / rotate / delete / add) ---------------------------
# DRAFT-ONLY. Every op rewrites the source PDF via the PERMISSIVE pdf_ops engine
# (pikepdf — deliberately fitz/PyMuPDF-FREE, so this write path carries no AGPL
# obligation) and REMAPS agreement_fields so placed fields track the page change.
# The doc_hash bump and the field remap commit together (one connection) so a field
# layout can never desync from the PDF a signer will see.
#
# Coordinate convention (agreement_fields.x,y,w,h): normalized fractions [0..1] of
# the page, origin TOP-LEFT, y increasing DOWNWARD, (x,y) = the box's top-left corner
# (see pdf_edit._rect / page_text_spans and the signer/editor overlay CSS).


def _draft_source(agreement_id: int):
    """Fetch a draft agreement for a page op. Returns (agr, None) when it exists, is
    a draft, and has a source PDF; otherwise (None, error-dict). Mirrors the
    frozen-on-send draft gate used by set_signers/set_fields (EDITOR-1)."""
    agr = get_agreement(agreement_id)
    if not agr or not agr.get("source_path"):
        return None, {"ok": False, "error": "not found"}
    if agr.get("status") not in ("draft", None, ""):
        return None, {"ok": False, "error": "locked — already sent"}
    return agr, None


def _rewrite_source_and_remap(
    agr: dict, new_pdf_bytes: bytes, remap_fn, event_kind: str, detail: str
):
    """Write new_pdf_bytes over the agreement's source PDF, bump doc_hash, run
    remap_fn(conn) to fix agreement_fields, and emit an audit event — the remap and
    the doc_hash bump commit together so fields never desync from the PDF. Callers
    MUST have already enforced the draft gate (via _draft_source). Returns the
    refreshed page count + field list."""
    aid = agr["id"]
    new_hash = pdf_edit.sha256(new_pdf_bytes)
    # File first, then DB: if the DB step crashes, the next op re-derives page_count
    # from the file, so the layout self-heals rather than pointing at stale bytes.
    Path(agr["source_path"]).write_bytes(new_pdf_bytes)
    conn = db.connect()
    try:
        conn.execute("UPDATE agreements SET doc_hash=? WHERE id=?", (new_hash, aid))
        remap_fn(conn)
        _event(conn, aid, event_kind, detail=detail)
        conn.commit()
        fields = _rows(conn.execute("SELECT * FROM agreement_fields WHERE agreement_id=?", (aid,)))
    finally:
        conn.close()
    return {
        "ok": True,
        "page_count": pdf_ops.page_count(new_pdf_bytes),
        "doc_hash": new_hash,
        "fields": fields,
    }


def delete_page(agreement_id: int, page: int) -> dict:
    """Delete one 0-based page. Fields on that page are dropped; fields on later pages
    shift up by one. Refuses to delete the only page. Draft-only."""
    agr, err = _draft_source(agreement_id)
    if err:
        return err
    data = _source_bytes(agr)
    n = pdf_ops.page_count(data)
    try:
        page = int(page)
    except (TypeError, ValueError):
        return {"ok": False, "error": "bad page"}
    if not (0 <= page < n):
        return {"ok": False, "error": "bad page"}
    if n <= 1:
        return {"ok": False, "error": "cannot delete the only page"}
    new = pdf_ops.delete_pages(data, [page])

    def remap(conn):
        conn.execute(
            "DELETE FROM agreement_fields WHERE agreement_id=? AND page=?", (agreement_id, page)
        )
        conn.execute(
            "UPDATE agreement_fields SET page=page-1 WHERE agreement_id=? AND page>?",
            (agreement_id, page),
        )
        # keep edited_pages in lock-step (else send() flattens the wrong page → remanence)
        _remap_edited_pages_in_txn(
            conn, agreement_id, lambda i: None if i == page else (i - 1 if i > page else i)
        )

    return _rewrite_source_and_remap(agr, new, remap, "pages_delete", f"deleted page {page + 1}")


def reorder_pages(agreement_id: int, order: list) -> dict:
    """Reorder pages. `order` is a permutation of range(page_count) where
    order[new_index] == old_index (matches pdf_ops.reorder_pages). Each field's page
    is remapped old->new; coords unchanged. Draft-only."""
    agr, err = _draft_source(agreement_id)
    if err:
        return err
    data = _source_bytes(agr)
    n = pdf_ops.page_count(data)
    try:
        order = [int(i) for i in order]
    except (TypeError, ValueError):
        return {"ok": False, "error": "bad order"}
    if sorted(order) != list(range(n)):
        return {"ok": False, "error": "bad order"}
    new = pdf_ops.reorder_pages(data, order)
    new_of_old = {old: new_i for new_i, old in enumerate(order)}

    def remap(conn):
        # Two-phase (offset by +100000, then land) so overlapping source/target page
        # numbers can't collide mid-update and double-move a row.
        for old, new_i in new_of_old.items():
            conn.execute(
                "UPDATE agreement_fields SET page=? WHERE agreement_id=? AND page=?",
                (new_i + 100000, agreement_id, old),
            )
        conn.execute(
            "UPDATE agreement_fields SET page=page-100000 WHERE agreement_id=? AND page>=100000",
            (agreement_id,),
        )
        # remap edited_pages through the same permutation (old -> new) so send() flattens right
        _remap_edited_pages_in_txn(conn, agreement_id, lambda i: new_of_old.get(i))

    return _rewrite_source_and_remap(agr, new, remap, "pages_reorder", f"reordered {n} pages")


def rotate_page(agreement_id: int, page: int, deg: int) -> dict:
    """Rotate one 0-based page clockwise by deg in {90,180,270} and transform the
    normalized coords of fields ON that page into the rotated image space (top-left
    origin, y-down). Only fields on `page` are transformed. Draft-only."""
    agr, err = _draft_source(agreement_id)
    if err:
        return err
    data = _source_bytes(agr)
    n = pdf_ops.page_count(data)
    try:
        page = int(page)
        deg = int(deg) % 360
    except (TypeError, ValueError):
        return {"ok": False, "error": "bad rotation"}
    if not (0 <= page < n):
        return {"ok": False, "error": "bad page"}
    if deg not in (90, 180, 270):
        return {"ok": False, "error": "rotation must be 90, 180, or 270 degrees"}
    new = pdf_ops.rotate_pages(data, {page: deg})

    def remap(conn):
        rows = _rows(
            conn.execute(
                "SELECT id,x,y,w,h FROM agreement_fields WHERE agreement_id=? AND page=?",
                (agreement_id, page),
            )
        )
        for r in rows:
            x, y, w, h = r["x"], r["y"], r["w"], r["h"]
            if deg == 90:  # clockwise: (x,y)->(1-y,x), w/h swap
                nx, ny, nw, nh = 1 - y - h, x, h, w
            elif deg == 180:
                nx, ny, nw, nh = 1 - x - w, 1 - y - h, w, h
            else:  # 270 clockwise: (x,y)->(y,1-x), w/h swap
                nx, ny, nw, nh = y, 1 - x - w, h, w
            conn.execute(
                "UPDATE agreement_fields SET x=?,y=?,w=?,h=? WHERE id=?",
                (nx, ny, nw, nh, r["id"]),
            )

    return _rewrite_source_and_remap(
        agr, new, remap, "pages_rotate", f"rotated page {page + 1} by {deg} degrees"
    )


def add_pages(agreement_id: int, extra_pdf_bytes: bytes) -> dict:
    """Append another PDF's pages to the source. Appended pages carry no fields and
    land at higher indices, so existing fields (page + coords) are unchanged.
    Draft-only; rejects non-PDF input."""
    agr, err = _draft_source(agreement_id)
    if err:
        return err
    if not extra_pdf_bytes or extra_pdf_bytes[:4] != b"%PDF":
        return {"ok": False, "error": "not a PDF"}
    data = _source_bytes(agr)
    try:
        added = pdf_ops.page_count(extra_pdf_bytes)
    except ValueError:
        return {"ok": False, "error": "not a PDF"}
    new = pdf_ops.merge([data, extra_pdf_bytes])

    def remap(conn):
        # Appended pages get the highest indices; existing fields keep page + coords.
        pass

    return _rewrite_source_and_remap(agr, new, remap, "pages_add", f"added {added} page(s)")


def redact_regions(agreement_id: int, regions: list) -> dict:
    """Permanently REMOVE the covered content from the source PDF. Each region is
    {kind:'redact'|'whiteout', page, x, y, w, h} — coords normalized 0..1 of the page,
    origin TOP-LEFT (the same convention as agreement_fields). True content deletion: the
    redacted page is rasterized + flattened (pdf_edit.apply_edits -> pdf_redact) so the
    underlying text / vectors / image pixels are GONE, not merely painted over — safe even
    when a secret hides in a Form XObject.

    DESTRUCTIVE + permanent, so DRAFT-ONLY (a sent envelope's presented bytes are frozen
    and must never change) and FAIL-CLOSED: one malformed region rejects the whole batch
    before any file write, so a bad request can never partially destroy a document. This
    is stricter than stamp_fields' skip-bad tolerance precisely because redaction is
    irreversible — a silently-dropped region is worse than a clean 400.

    Redaction strips CONTENT, never fields: placed signature/date/etc. fields are separate
    overlays (agreement_fields) stamped at seal time, so the field remap is a no-op."""
    agr, err = _draft_source(agreement_id)
    if err:
        return err
    if not regions or not isinstance(regions, list):
        return {"ok": False, "error": "no regions"}
    data = _source_bytes(agr)
    n = pdf_ops.page_count(data)
    edits = []
    for r in regions:
        if not isinstance(r, dict):
            return {"ok": False, "error": "bad region"}
        kind = r.get("kind", "redact")
        if kind not in ("redact", "whiteout"):
            return {"ok": False, "error": "bad kind"}
        try:
            page = int(r.get("page"))
            x, y, w, h = (float(r["x"]), float(r["y"]), float(r["w"]), float(r["h"]))
        except (TypeError, ValueError, KeyError):
            return {"ok": False, "error": "bad region"}
        if not (0 <= page < n):
            return {"ok": False, "error": "bad page"}
        # In-range AND a non-degenerate box inside the page. The +0.0001 slack absorbs the
        # browser's %-coord float round-trip; pdf_edit._rect clamps for render, not safety.
        if not (
            0 <= x < 1
            and 0 <= y < 1
            and 0 < w <= 1
            and 0 < h <= 1
            and x + w <= 1.0001
            and y + h <= 1.0001
        ):
            return {"ok": False, "error": "bad coords"}
        edits.append({"kind": kind, "page": page, "x": x, "y": y, "w": w, "h": h})

    new = pdf_edit.apply_edits(data, edits)

    def remap(conn):
        # No-op: redaction removes page CONTENT, not fields. Placed field overlays keep
        # their page + coords (mirrors add_pages). Do NOT touch agreement_fields.
        pass

    return _rewrite_source_and_remap(
        agr, new, remap, "redacted", f"redacted {len(edits)} region(s)"
    )


# --- Add-text tool: caps + validation (mirrors redact_regions' fail-closed posture) --------
_TEXT_MAX_ITEMS = 50
_TEXT_MAX_LEN = 2000
_TEXT_MAX_LINES = 60
_TEXT_MIN_SIZE, _TEXT_MAX_SIZE = 6.0, 96.0
_TEXT_FONTS = ("sans", "serif", "mono")
_TEXT_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")


def add_texts(agreement_id: int, items: list) -> dict:
    """Burn author-typed text INTO the draft source PDF (Acrobat "Add Text"). Each item is
    {page, x, y, text, size?, color?, font?} — (x,y) normalized 0..1, origin TOP-LEFT, the
    point being the top-left anchor of the first line (pdf_edit's 'text' kind places the
    baseline at y*H + size). Written into the page CONTENT stream (pdf_edit.apply_edits ->
    pdf_stamp overlay) — not an annotation — so it is part of what signers see, what redaction
    can later remove, and what the PAdES certification covers.

    DRAFT-ONLY (sent envelopes are frozen) and FAIL-CLOSED like redact_regions: one malformed
    item rejects the whole batch before any file write. font is a family (sans/serif/mono);
    Latin-1 text renders in that base-14 family, anything else in the universal fallback face,
    and any character NEITHER can render 400s naming it — never silent tofu in a signed doc."""
    agr, err = _draft_source(agreement_id)
    if err:
        return err
    if not items or not isinstance(items, list):
        return {"ok": False, "error": "no items"}
    if len(items) > _TEXT_MAX_ITEMS:
        return {"ok": False, "error": f"too many items (max {_TEXT_MAX_ITEMS})"}
    data = _source_bytes(agr)
    n = pdf_ops.page_count(data)
    edits = []
    for it in items:
        if not isinstance(it, dict):
            return {"ok": False, "error": "bad item"}
        try:
            page = int(it.get("page"))
            x, y = float(it["x"]), float(it["y"])
        except (TypeError, ValueError, KeyError):
            return {"ok": False, "error": "bad item"}
        if not (0 <= page < n):
            return {"ok": False, "error": "bad page"}
        if not (0 <= x < 1 and 0 <= y < 1):
            return {"ok": False, "error": "bad coords"}
        text = it.get("text")
        if not isinstance(text, str) or not text.strip():
            return {"ok": False, "error": "empty text"}
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if len(text) > _TEXT_MAX_LEN:
            return {"ok": False, "error": f"text too long (max {_TEXT_MAX_LEN})"}
        if text.count("\n") + 1 > _TEXT_MAX_LINES:
            return {"ok": False, "error": f"too many lines (max {_TEXT_MAX_LINES})"}
        # Control chars (C0/C1/DEL except \n and \t) are latin-1-encodable, so they slip past
        # the font gate and bake blank/tofu glyphs — reject them explicitly.
        if any((ord(c) < 32 and c not in "\n\t") or (0x7F <= ord(c) <= 0x9F) for c in text):
            return {"ok": False, "error": "text contains control characters"}
        bad = pdf_edit.unsupported_chars(text)
        if bad:
            return {"ok": False, "error": "unsupported characters: " + bad}
        try:
            size = float(it.get("size", 12))
        except (TypeError, ValueError):
            return {"ok": False, "error": "bad size"}
        if not (_TEXT_MIN_SIZE <= size <= _TEXT_MAX_SIZE):
            return {"ok": False, "error": f"size must be {_TEXT_MIN_SIZE:g}-{_TEXT_MAX_SIZE:g}"}
        font = it.get("font", "sans")
        if font not in _TEXT_FONTS:
            return {"ok": False, "error": "bad font"}
        color = it.get("color", "#111111")
        if not isinstance(color, str) or not _TEXT_HEX.match(color):
            return {"ok": False, "error": "bad color"}
        edits.append(
            {
                "kind": "text",
                "page": page,
                "x": x,
                "y": y,
                "text": text,
                "size": size,
                "font": font,
                "color": color,
            }
        )

    try:
        new = pdf_edit.apply_edits(data, edits)
    except ValueError as ex:
        # apply_edits raises when a block would overflow the page bottom (insert_text silently
        # drops those lines otherwise). Fail closed — nothing is written.
        return {"ok": False, "error": str(ex)}

    def remap(conn):
        # No-op: added text is page CONTENT, not a field — placed field overlays keep their
        # page + coords (mirrors redact_regions / add_pages). Page-ops carry the baked text
        # with the page automatically since it lives in the content stream.
        pass

    return _rewrite_source_and_remap(
        agr, new, remap, "text_added", f"added {len(edits)} text block(s)"
    )


# --- Edit-existing-text tool: replace a text run in place (mirrors add_texts' posture) -----
_EDIT_MAX_ITEMS = 50


def _edited_page_list(agr: dict) -> list[int]:
    """Parse the agreement's `edited_pages` column into a sorted list of 0-based page indices."""
    raw = str(agr.get("edited_pages") or "")
    out = {int(p) for p in raw.split(",") if p.strip().isdigit()}
    return sorted(out)


def _remap_edited_pages_in_txn(conn, agreement_id: int, mapper) -> None:
    """Remap the agreements.edited_pages index list through a page-op, in the SAME txn as the
    field remap. `mapper(old_index) -> new_index | None` (None drops the page). WITHOUT this, a
    draft that is re-paginated (delete/reorder) after a text edit keeps stale indices, so send()
    flattens the wrong page and ships the pre-edit text recoverably under the cover rect in the
    SEALED legal PDF — a real integrity hole. Mirrors how agreement_fields.page is remapped."""
    row = conn.execute("SELECT edited_pages FROM agreements WHERE id=?", (agreement_id,)).fetchone()
    if row is None:
        return
    raw = str((row["edited_pages"] if not isinstance(row, tuple) else row[0]) or "")
    if not raw:
        return
    cur = [int(p) for p in raw.split(",") if p.strip().isdigit()]
    mapped = sorted({m for m in (mapper(i) for i in cur) if m is not None and m >= 0})
    conn.execute(
        "UPDATE agreements SET edited_pages=? WHERE id=?",
        (",".join(str(i) for i in mapped), agreement_id),
    )


def edit_texts(agreement_id: int, items: list) -> dict:
    """Replace existing text runs IN PLACE on the draft source PDF (vector cover+redraw with a
    font/size/colour/baseline the server RE-EXTRACTS from the pristine PDF — the client sends
    only {page, bbox, text}). Mirrors add_texts' posture exactly: DRAFT-ONLY (sent envelopes are
    frozen → "locked") and FAIL-CLOSED per item (a bad/unreproducible edit rejects the whole
    batch before any file write — a silently-corrupted legal PDF is worse than a clean error).

    Per-item bbox is {x,y,w,h} normalized 0..1 top-left. Returns the standard page-op result
    ({ok, page_count, doc_hash, fields}) on success, or {ok:False, error:<code>, item:<index>}
    where <code> ∈ locked / no items / bad page / bad bbox / empty / too_long / rotated / no_run
    / unsupported:<chars> / bad size / bad color — the codes the frontend maps to plain toasts."""
    agr, err = _draft_source(agreement_id)
    if err:
        return err
    if not items or not isinstance(items, list):
        return {"ok": False, "error": "no items"}
    if len(items) > _EDIT_MAX_ITEMS:
        return {"ok": False, "error": f"too many items (max {_EDIT_MAX_ITEMS})"}
    data = _source_bytes(agr)
    n = pdf_ops.page_count(data)
    edits = []
    for idx, it in enumerate(items):
        if not isinstance(it, dict):
            return {"ok": False, "error": "bad item", "item": idx}
        try:
            page = int(it.get("page"))
        except (TypeError, ValueError):
            return {"ok": False, "error": "bad item", "item": idx}
        if not (0 <= page < n):
            return {"ok": False, "error": "bad page", "item": idx}
        bb = it.get("bbox")
        if not isinstance(bb, dict):
            return {"ok": False, "error": "bad bbox", "item": idx}
        try:
            bx, by, bw, bh = float(bb["x"]), float(bb["y"]), float(bb["w"]), float(bb["h"])
        except (TypeError, ValueError, KeyError):
            return {"ok": False, "error": "bad bbox", "item": idx}
        x0, y0, x1, y1 = bx, by, bx + bw, by + bh
        # bbox in [0,1] with x1>x0, y1>y0 (small slack for the browser's %-coord float round-trip)
        if not (0 <= x0 < x1 <= 1.0001 and 0 <= y0 < y1 <= 1.0001):
            return {"ok": False, "error": "bad bbox", "item": idx}
        text = it.get("text")
        if not isinstance(text, str) or not text.strip():
            return {"ok": False, "error": "empty", "item": idx}
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if len(text) > _TEXT_MAX_LEN:
            return {"ok": False, "error": "too_long", "item": idx}
        # An in-place run edit is single-line; a newline can't be reproduced within one run box.
        if "\n" in text:
            return {"ok": False, "error": "bad text", "item": idx}
        # Control chars (C0/C1/DEL) are latin-1-encodable so they slip the font gate → bake tofu.
        if any((ord(c) < 32 and c != "\t") or (0x7F <= ord(c) <= 0x9F) for c in text):
            return {"ok": False, "error": "bad text", "item": idx}
        bad = pdf_edit.unsupported_chars(text)
        if bad:
            return {"ok": False, "error": "unsupported:" + bad, "item": idx}
        edit = {"idx": idx, "page": page, "bbox": [x0, y0, x1, y1], "text": text}
        if it.get("size") is not None:
            try:
                size = float(it["size"])
            except (TypeError, ValueError):
                return {"ok": False, "error": "bad size", "item": idx}
            if not (_TEXT_MIN_SIZE <= size <= _TEXT_MAX_SIZE):
                return {"ok": False, "error": "bad size", "item": idx}
            edit["size"] = size
        if it.get("color") is not None:
            color = it["color"]
            if not isinstance(color, str) or not _TEXT_HEX.match(color):
                return {"ok": False, "error": "bad color", "item": idx}
            edit["color"] = color
        edits.append(edit)

    try:
        new = pdf_edit.replace_runs(data, edits)
    except pdf_edit.EditError as ex:
        # Typed per-item refusal (rotated / no_run / too_long / empty) — fail closed, nothing written.
        return {"ok": False, "error": ex.code, "item": ex.item}
    except ValueError as ex:
        return {"ok": False, "error": str(ex)}

    edited_now = sorted({e["page"] for e in edits})

    def remap(conn):
        # Added/replaced text is page CONTENT, not a field — placed field overlays keep their
        # page + coords (mirrors add_texts / redact_regions). Additionally record which pages
        # were edited so send() can rasterize them into the frozen snapshot (remanence closure).
        row = conn.execute(
            "SELECT edited_pages FROM agreements WHERE id=?", (agreement_id,)
        ).fetchone()
        prev = set()
        if row is not None:
            prev_raw = str((row["edited_pages"] if not isinstance(row, tuple) else row[0]) or "")
            prev = {int(p) for p in prev_raw.split(",") if p.strip().isdigit()}
        allp = sorted(prev | set(edited_now))
        conn.execute(
            "UPDATE agreements SET edited_pages=? WHERE id=?",
            (",".join(str(p) for p in allp), agreement_id),
        )

    return _rewrite_source_and_remap(agr, new, remap, "text_edited", f"edited {len(edits)} run(s)")


_AUTH_METHODS = ("email", "email_otp", "access_code")


def set_signers(agreement_id: int, signers: list[dict]) -> Any:
    # Post-send immutability: once an agreement leaves draft, the frozen presented
    # version is authoritative — signers can no longer be rewritten (EDITOR-1).
    agr = get_agreement(agreement_id)
    if agr and agr.get("status") not in ("draft", None, ""):
        return {"ok": False, "error": "locked — already sent"}
    conn = db.connect()
    try:
        conn.execute("DELETE FROM agreement_signers WHERE agreement_id=?", (agreement_id,))
        for i, s in enumerate(signers):
            auth = (s.get("auth") or "email").strip().lower()
            if auth not in _AUTH_METHODS:
                auth = "email"
            conn.execute(
                "INSERT INTO agreement_signers(agreement_id,name,email,role,sign_order,color,status,is_consumer,auth_method)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    agreement_id,
                    s.get("name", ""),
                    (s.get("email", "") or "").strip().lower(),
                    s.get("role", "signer"),
                    int(s.get("order", i + 1)),
                    SIGNER_COLORS[i % len(SIGNER_COLORS)],
                    "pending",
                    1 if s.get("is_consumer") else 0,
                    auth,
                ),
            )
        conn.commit()
        return _rows(
            conn.execute(
                "SELECT * FROM agreement_signers WHERE agreement_id=? ORDER BY sign_order",
                (agreement_id,),
            )
        )
    finally:
        conn.close()


def update_message(agreement_id: int, message: str) -> None:
    conn = db.connect()
    try:
        conn.execute("UPDATE agreements SET message=? WHERE id=?", (message or "", agreement_id))
        conn.commit()
    finally:
        conn.close()


def set_fields(agreement_id: int, fields: list[dict]) -> Any:
    # Frozen-on-send: field layout is locked once the agreement is sent (EDITOR-1).
    agr = get_agreement(agreement_id)
    if agr and agr.get("status") not in ("draft", None, ""):
        return {"ok": False, "error": "locked — already sent"}
    conn = db.connect()
    try:
        conn.execute("DELETE FROM agreement_fields WHERE agreement_id=?", (agreement_id,))
        for f in fields:
            conn.execute(
                "INSERT INTO agreement_fields(agreement_id,signer_id,type,page,x,y,w,h,required,value,placeholder,prefill,prompt,field_key)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    agreement_id,
                    f.get("signer_id"),
                    f.get("type", "text"),
                    int(f.get("page", 0)),
                    float(f.get("x", 0)),
                    float(f.get("y", 0)),
                    float(f.get("w", 0)),
                    float(f.get("h", 0)),
                    1 if f.get("required", True) else 0,
                    str(f.get("value", "") or f.get("default", "") or ""),
                    f.get("placeholder", ""),
                    1 if f.get("prefill") else 0,
                    str(f.get("prompt", "") or ""),
                    str(f.get("field_key", "") or ""),
                ),
            )
        conn.commit()
        return conn.execute(
            "SELECT COUNT(*) FROM agreement_fields WHERE agreement_id=?",
            (agreement_id,),
        ).fetchone()[0]
    finally:
        conn.close()


# ---- programmatic field placement (anchor text / points / normalized) -----------------------
# The developer-friendly way to tag signature/field locations via the API: name text that already
# exists in the document ("anchor") and the field snaps to it — no coordinate math. Also accepts
# absolute PDF points and the raw normalized form. Fail-closed: an unresolvable field rejects the
# whole batch (a silently-dropped field on a legal document is worse than a clean error).

_FIELD_SIZE_PT = {
    "signature": (180.0, 44.0),
    "initials": (72.0, 44.0),
    "date": (110.0, 26.0),
    "text": (170.0, 26.0),
    "name": (180.0, 26.0),
    "email": (200.0, 26.0),
    "title": (170.0, 26.0),
    "company": (180.0, 26.0),
    "checkbox": (18.0, 18.0),
}
_ANCHOR_PLACE = ("right", "left", "below", "above", "over")


class PlaceError(Exception):
    def __init__(self, code: str, field: int, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.field = field
        self.detail = detail


def _anchor_hits(data: bytes) -> list[dict]:
    """Every line of extractable text as {page, W, H, text(lower), words:[(w_lower,x0,x1,top,bottom)]}
    — the search index for anchor matching (pdfplumber, top-left points)."""
    import pdfplumber

    lines: list[dict] = []
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        for pi, page in enumerate(pdf.pages):
            W = float(page.width) or 1.0
            H = float(page.height) or 1.0
            try:
                words = page.extract_words(use_text_flow=True) or []
            except Exception:  # noqa: BLE001 — a bad page shouldn't kill placement for the rest
                words = []
            # group words into lines by their vertical band (top within ~3pt)
            words = sorted(words, key=lambda w: (round(float(w["top"]) / 3.0), float(w["x0"])))
            cur: list = []
            cur_top = None
            for w in words:
                top = float(w["top"])
                if cur_top is None or abs(top - cur_top) <= 3.0:
                    cur.append(w)
                    cur_top = top if cur_top is None else cur_top
                else:
                    lines.append(_mk_line(pi, W, H, cur))
                    cur = [w]
                    cur_top = top
            if cur:
                lines.append(_mk_line(pi, W, H, cur))
    return lines


def _mk_line(pi, W, H, words) -> dict:
    ws = [
        (
            str(w["text"]).lower(),
            float(w["x0"]),
            float(w["x1"]),
            float(w["top"]),
            float(w["bottom"]),
        )
        for w in words
    ]
    # concatenated line text with a char->word map, so a substring anchor maps back to word bboxes
    text = ""
    char_word: list[int] = []
    for i, (t, *_rest) in enumerate(ws):
        if text:
            text += " "
            char_word.append(-1)
        for _c in t:
            char_word.append(i)
        text += t
    return {"page": pi, "W": W, "H": H, "text": text, "words": ws, "char_word": char_word}


def _find_anchor(lines, anchor: str, index: int):
    """Return (page, nx, ny, nw, nh) normalized bbox of the `index`-th (1-based) match of `anchor`,
    or None. Matches case-insensitively across word boundaries within a line."""
    needle = " ".join((anchor or "").lower().split())
    if not needle:
        return None
    seen = 0
    for ln in lines:
        hay = ln["text"]
        start = 0
        while True:
            pos = hay.find(needle, start)
            if pos < 0:
                break
            seen += 1
            start = pos + 1
            if seen != index:
                continue
            wi = {
                ln["char_word"][k]
                for k in range(pos, min(pos + len(needle), len(ln["char_word"])))
                if ln["char_word"][k] >= 0
            }
            if not wi:
                break
            span = [ln["words"][i] for i in sorted(wi)]
            x0 = min(s[1] for s in span)
            x1 = max(s[2] for s in span)
            top = min(s[3] for s in span)
            bot = max(s[4] for s in span)
            W, H = ln["W"], ln["H"]
            return (ln["page"], x0 / W, top / H, (x1 - x0) / W, (bot - top) / H)
    return None


# ---- SMART TEMPLATES: deterministic prefill-field detection (zero-cost, no AI/network) --------
# Tokens the author drops into the document to mark "fill this in": {{company}}, [DATE], <<amount>>.
_MERGE_TOKEN_RE = re.compile(
    r"\{\{\s*([a-z0-9][a-z0-9 _\-]*?)\s*\}\}"
    r"|\[\s*([a-z0-9][a-z0-9 _\-]{1,40}?)\s*\]"
    r"|<<\s*([a-z0-9][a-z0-9 _\-]*?)\s*>>"
)
# Curated labels a sender typically fills — matched as "<label>:" so we don't over-detect. The
# field lands just to the RIGHT of the label. Longest-first so "company name" beats "name".
_PREFILL_LABELS = [
    "effective date",
    "expiration date",
    "start date",
    "end date",
    "company name",
    "full name",
    "print name",
    "business name",
    "legal name",
    "contract value",
    "total amount",
    "job title",
    "phone number",
    "email address",
    "mailing address",
    "company",
    "address",
    "amount",
    "total",
    "title",
    "email",
    "phone",
    "date",
    "name",
]


def _humanize_token(token: str) -> str:
    t = re.sub(r"[_\-]+", " ", token or "").strip()
    t = re.sub(r"\s+", " ", t)
    return " ".join(w[:1].upper() + w[1:] for w in t.split())[:60]


def _prefill_type_for(label_lc: str) -> str:
    if "date" in label_lc:
        return "date"
    if "email" in label_lc:
        return "email"
    if "company" in label_lc or "business" in label_lc:
        return "company"
    if "title" in label_lc:
        return "title"
    if "name" in label_lc:
        return "name"
    return "text"


def _bbox_from_charspan(ln: dict, start: int, end: int):
    """Union bbox (points) of the words covering [start,end) of the line's concatenated text."""
    cw = ln["char_word"]
    wi = {cw[k] for k in range(start, min(end, len(cw))) if cw[k] >= 0}
    if not wi:
        return None
    span = [ln["words"][i] for i in sorted(wi)]
    return (
        min(s[1] for s in span),
        max(s[2] for s in span),
        min(s[3] for s in span),
        max(s[4] for s in span),
    )


def detect_prefill_fields(data: bytes, max_fields: int = 40) -> list[dict]:
    """Scan a PDF for merge tokens ({{x}}/[X]/<<x>>) and common sender-filled labels, returning
    normalized prefill-field records ready for set_fields: {type,page,x,y,w,h,prefill,prompt,
    field_key,placeholder,required}. Fully deterministic and local (pdfplumber word bboxes → the
    same top-left-points→normalized pipeline as anchor placement). Never raises."""
    try:
        lines = _anchor_hits(data)
    except Exception:  # noqa: BLE001 — detection is best-effort; a bad PDF just yields nothing
        return []
    out: list[dict] = []
    seen_keys: set[str] = set()

    def _emit(page, key, prompt, x0, x1, top, bot, W, H, over: bool):
        ftype = _prefill_type_for(prompt.lower())
        min_w_pt = _FIELD_SIZE_PT.get(ftype, (150.0, 26.0))[0]
        if over:  # place ON the token, but never narrower than the type's default box
            nx, ny = x0 / W, top / H
            nw = max((x1 - x0) / W, min_w_pt / W)
        else:  # place just to the RIGHT of a label
            nx, ny = (x1 + 6.0) / W, top / H
            nw = min_w_pt / W
        nh = max((bot - top) / H, 22.0 / H)
        nw = min(nw, 1.0)  # never wider than the page (a narrow page + a wide default box)
        nh = min(nh, 1.0)
        nx = max(0.0, min(nx, 1.0 - nw))
        ny = max(0.0, min(ny, 1.0 - nh))
        out.append(
            {
                "type": ftype,
                "page": page,
                "x": round(nx, 5),
                "y": round(ny, 5),
                "w": round(nw, 5),
                "h": round(nh, 5),
                "prefill": 1,
                "prompt": prompt,
                "field_key": key,
                "placeholder": prompt,
                "required": True,
            }
        )
        seen_keys.add(key)

    def _overlaps(a, occ) -> bool:
        return any(not (a[1] <= o[0] or o[1] <= a[0]) for o in occ)

    for ln in lines:
        W, H, page, text = ln["W"], ln["H"], ln["page"], ln["text"]
        occupied: list[tuple[int, int]] = []  # char spans already claimed on THIS line
        # 1) explicit merge tokens — highest confidence; placed OVER the token
        for m in _MERGE_TOKEN_RE.finditer(text):
            token = next((g for g in m.groups() if g), "")
            key = re.sub(r"[^a-z0-9]+", "_", token).strip("_")
            span = (m.start(), m.end())
            if not key or key in seen_keys or _overlaps(span, occupied):
                continue
            bb = _bbox_from_charspan(ln, m.start(), m.end())
            if not bb:
                continue
            occupied.append(span)
            _emit(page, key, _humanize_token(token), bb[0], bb[1], bb[2], bb[3], W, H, over=True)
            if len(out) >= max_fields:
                return out
        # 2) curated "<label>:" — placed to the RIGHT of the label. _PREFILL_LABELS is longest-first
        # so a compound ("company name") claims its span before the short suffix ("name") is tried; a
        # left word-boundary check blocks mid-word false hits ("username:" → NOT Name).
        for label in _PREFILL_LABELS:
            key = re.sub(r"[^a-z0-9]+", "_", label).strip("_")
            if key in seen_keys:
                continue
            start = 0
            while True:
                pos = text.find(label + ":", start)
                if pos < 0:
                    break
                start = pos + 1
                if pos > 0 and (text[pos - 1].isalnum() or text[pos - 1] == "_"):
                    continue  # mid-word (e.g. "surname:", "username:") — not a real label
                span = (pos, pos + len(label) + 1)
                if _overlaps(span, occupied):
                    continue  # already covered by a compound label / token on this line
                bb = _bbox_from_charspan(ln, pos, pos + len(label) + 1)
                if not bb:
                    continue
                occupied.append(span)
                _emit(
                    page, key, _humanize_token(label), bb[0], bb[1], bb[2], bb[3], W, H, over=False
                )
                if len(out) >= max_fields:
                    return out
                break  # one field per label per line
    return out


def autodetect_prefill_owned(agreement_id: int, owner_account_id: int) -> dict:
    """Owner-scoped: detect prefill fields in the draft's source PDF and ADD any not already present
    (by field_key) to its field set, preserving existing fields. DRAFT-only. Returns
    {ok, added, detected, fields:[…the newly added…]}."""
    agr = get_agreement_owned(agreement_id, owner_account_id)
    if not agr:
        return {"ok": False, "error": "not_found"}
    if (agr.get("status") or "draft") not in ("draft", "", None):
        return {"ok": False, "error": "locked — already sent"}
    try:
        data = _source_bytes(agr)
    except Exception:  # noqa: BLE001
        return {"ok": False, "error": "no_source"}
    detected = detect_prefill_fields(data)
    existing = agr.get("fields", []) or []
    have = {(f.get("field_key") or "") for f in existing if f.get("prefill")}
    added = [d for d in detected if d["field_key"] and d["field_key"] not in have]
    if added:
        set_fields(agreement_id, list(existing) + added)  # DELETE-then-INSERT keeps existing + new
    return {"ok": True, "added": len(added), "detected": len(detected), "fields": added}


def place_fields(agreement_id: int, fields: list) -> dict:
    """Resolve each field's placement (anchor text | absolute points | normalized) + signer (email
    or id) to the stored normalized form, then persist. DRAFT-only, fail-closed. Returns
    {ok, count, fields:[…placement report…]} or {ok:false, error, field}."""
    agr = get_agreement(agreement_id)
    if not agr:
        return {"ok": False, "error": "not_found"}
    if (agr.get("status") or "draft") not in ("draft", "", None):
        return {"ok": False, "error": "locked — already sent"}
    if not isinstance(fields, list) or not fields:
        return {"ok": False, "error": "no fields"}

    signers = agr.get("signers") or []
    by_email = {(s.get("email") or "").strip().lower(): s for s in signers}
    data = None  # lazy: only extract text if an anchor is actually used
    lines = None

    resolved: list[dict] = []
    report: list[dict] = []
    try:
        for i, f in enumerate(fields):
            if not isinstance(f, dict):
                raise PlaceError("bad_field", i)
            ftype = str(f.get("type") or "text").lower()
            # --- signer: email (strict) OR explicit signer_id (trusted, back-compat with the SPA
            # editor + raw set_fields), defaulting to the sole signer when unambiguous ---
            sid = f.get("signer_id")
            if f.get("signer"):
                s = by_email.get(str(f["signer"]).strip().lower())
                if not s:
                    raise PlaceError("signer_not_found", i, str(f.get("signer")))
                sid = s.get("id")
            elif sid is None and len(signers) == 1:
                sid = signers[0].get("id")
            if sid is None:
                raise PlaceError("signer_required", i)

            # --- coordinates: anchor | points | normalized ---
            if f.get("anchor"):
                if data is None:
                    data = _source_bytes(agr)
                    lines = _anchor_hits(data)
                hit = _find_anchor(lines, str(f["anchor"]), int(f.get("anchor_index", 1) or 1))
                if not hit:
                    raise PlaceError("anchor_not_found", i, str(f.get("anchor")))
                pg, ax, ay, aw, ah = hit
                dw, dh = _FIELD_SIZE_PT.get(ftype, _FIELD_SIZE_PT["text"])
                W = lines[0]["W"] if lines else 612.0
                H = lines[0]["H"] if lines else 792.0
                # page-specific dims (a line on that page carries them)
                for ln in lines:
                    if ln["page"] == pg:
                        W, H = ln["W"], ln["H"]
                        break
                fw = float(f.get("width", dw)) / W
                fh = float(f.get("height", dh)) / H
                ndx = float(f.get("dx", 6)) / W
                ndy = float(f.get("dy", 0)) / H
                place = str(f.get("place") or "right").lower()
                if place not in _ANCHOR_PLACE:
                    place = "right"
                if place == "right":
                    fx, fy = ax + aw + ndx, ay + ah / 2 - fh / 2 + ndy
                elif place == "left":
                    fx, fy = ax - fw - ndx, ay + ah / 2 - fh / 2 + ndy
                elif place == "below":
                    fx, fy = ax + ndx, ay + ah + ndy
                elif place == "above":
                    fx, fy = ax + ndx, ay - fh - ndy
                else:  # over
                    fx, fy = ax + ndx, ay + ndy
                page = pg
                w_, h_ = fw, fh
            else:
                page = int(f.get("page", 0))
                x_, y_ = float(f.get("x", 0)), float(f.get("y", 0))
                w_in = f.get("w", f.get("width"))
                h_in = f.get("h", f.get("height"))
                unit = str(f.get("unit") or "").lower()
                is_pt = (
                    unit in ("pt", "point", "points")
                    or x_ > 1.0
                    or y_ > 1.0
                    or (w_in and float(w_in) > 1.0)
                )
                if is_pt:
                    if data is None:
                        data = _source_bytes(agr)
                        lines = _anchor_hits(data)
                    W = H = None
                    for ln in lines or []:
                        if ln["page"] == page:
                            W, H = ln["W"], ln["H"]
                            break
                    if W is None:  # page has no text — fall back to letter
                        W, H = 612.0, 792.0
                    dw, dh = _FIELD_SIZE_PT.get(ftype, _FIELD_SIZE_PT["text"])
                    fx, fy = x_ / W, y_ / H
                    w_, h_ = (float(w_in) if w_in else dw) / W, (float(h_in) if h_in else dh) / H
                else:
                    fx, fy = x_, y_
                    w_ = float(w_in) if w_in else 0.2
                    h_ = float(h_in) if h_in else 0.04
            # clamp into the page
            w_ = max(0.001, min(w_, 1.0))
            h_ = max(0.001, min(h_, 1.0))
            fx = max(0.0, min(fx, 1.0 - w_))
            fy = max(0.0, min(fy, 1.0 - h_))
            rf = {
                "signer_id": sid,
                "type": ftype,
                "page": page,
                "x": round(fx, 5),
                "y": round(fy, 5),
                "w": round(w_, 5),
                "h": round(h_, 5),
                "required": bool(f.get("required", True)),
                "value": f.get("value", ""),
                "placeholder": f.get("placeholder", ""),
                # SMART TEMPLATES: preserve the prefill metadata — this is the editor's field-save
                # path (POST /api/mysign/agreements/{aid}/fields), so dropping these would silently
                # erase the prefill toggle/prompt on every save and self-destruct detected fields.
                "prefill": 1 if f.get("prefill") else 0,
                "prompt": str(f.get("prompt", "") or ""),
                "field_key": str(f.get("field_key", "") or ""),
            }
            resolved.append(rf)
            rep = {
                "type": ftype,
                "signer_id": sid,
                "page": page,
                "x": rf["x"],
                "y": rf["y"],
                "w": rf["w"],
                "h": rf["h"],
                "placed": True,
            }
            if f.get("anchor"):
                rep["anchor"] = str(f["anchor"])
            report.append(rep)
    except PlaceError as ex:
        return {"ok": False, "error": ex.code, "field": ex.field, "detail": ex.detail}

    set_fields(agreement_id, resolved)  # replace-all, normalized
    # Surface the DB-assigned field ids to API/SDK callers. set_fields does a delete-then-insert
    # in list order, so the ids returned in id order line up 1:1 with `report` (and `resolved`).
    # Without this, a developer placing fields over the API has no id to prefill/submit against
    # and must issue a second GET — the signer page gets ids from the token payload, but the
    # authoring API should too.
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT id FROM agreement_fields WHERE agreement_id=? ORDER BY id",
            (agreement_id,),
        ).fetchall()
    finally:
        conn.close()
    for rep, row in zip(report, rows):
        rep["id"] = row[0]
    return {"ok": True, "count": len(resolved), "fields": report}


# --- reusable templates (esign-templates cluster) --------------------------------
# A *template* is a named, persisted, reusable layout: the blank source PDF plus the signer
# ROLES and placed FIELD layout, captured as JSON. Instantiating one creates a normal agreement
# via the existing create_agreement / set_signers / set_fields path — the agreements /
# agreement_signers / agreement_fields tables are never altered. This replaces (well, augments)
# the auto-derived "templates" gallery that inferred templates from past envelope names.
def _tpl_snapshot_signers(agr: dict) -> tuple[list[dict], dict[int, int]]:
    """Snapshot an agreement's signer roles as reusable role rows + an id->index map so field
    signer references can be re-pointed at instantiation. PII (name/email) is retained so a
    template can carry default parties, but recipients passed to instantiate override them."""
    signers: list[dict] = []
    id_to_idx: dict[int, int] = {}
    for i, s in enumerate(agr.get("signers", []) or []):
        if s.get("id") is not None:
            id_to_idx[s["id"]] = i
        signers.append(
            {
                "name": s.get("name", "") or "",
                "email": s.get("email", "") or "",
                "role": s.get("role", "signer") or "signer",
                "order": int(s.get("sign_order", i + 1) or (i + 1)),
                "is_consumer": bool(s.get("is_consumer")),
                "auth": s.get("auth_method", "email") or "email",
            }
        )
    return signers, id_to_idx


def create_template(
    name: str | None = None,
    source_agreement_id: int | None = None,
    layout: dict | None = None,
    created_by: str = "Will",
    owner_account_id: int | None = None,
) -> dict:
    """Create a named, persisted template. Two modes:
      - from an existing agreement (source_agreement_id): snapshot its blank source PDF, signer
        roles and field layout.
      - from name + explicit `layout` = {signers:[...], fields:[...], source_doc_id?, source_agreement_id?}.
        The layout's fields use `signer_index` into its `signers` list.
    owner_account_id stamps the owning tenant (NULL = admin/Will). When set, the source agreement
    (either mode) MUST belong to that owner — snapshotting another tenant's agreement (its signer
    PII + layout) is blocked via get_agreement_owned. Returns {ok, id} or {ok:False, error}."""
    layout = layout or {}
    # SIGN-TENANT: the company-doc library (documents table) is a GLOBAL admin resource with no
    # owner column. A tenant must NEVER build a template from a source_doc_id — it would snapshot
    # admin/other-tenant PDF bytes (email attachments, PII) into a template the tenant then owns and
    # can download. Tenant templates source ONLY from an agreement they own (source_agreement_id).
    if owner_account_id and layout.get("source_doc_id"):
        return {"ok": False, "error": "source document not allowed"}
    signers: list[dict] = []
    fields: list[dict] = []
    source_doc_id: int | None = None
    src_agr_id: int | None = None
    pdf_bytes: bytes | None = None

    def _resolve_source_agreement(agr_id: int) -> dict | None:
        # Owner-scoped read when a tenant is creating — never snapshot another tenant's agreement.
        if owner_account_id:
            return get_agreement_owned(int(agr_id), owner_account_id)
        return get_agreement(int(agr_id))

    if source_agreement_id:
        agr = _resolve_source_agreement(int(source_agreement_id))
        if not agr:
            return {"ok": False, "error": "agreement not found"}
        name = (name or agr.get("name") or "Untitled template").strip()
        source_doc_id = agr.get("source_doc_id")
        src_agr_id = int(source_agreement_id)
        signers, id_to_idx = _tpl_snapshot_signers(agr)
        for f in agr.get("fields", []) or []:
            fields.append(
                {
                    "signer_index": id_to_idx.get(f.get("signer_id"), 0),
                    "type": f.get("type", "text") or "text",
                    "page": int(f.get("page", 0) or 0),
                    "x": float(f.get("x", 0) or 0),
                    "y": float(f.get("y", 0) or 0),
                    "w": float(f.get("w", 0) or 0),
                    "h": float(f.get("h", 0) or 0),
                    "required": bool(f.get("required", 1)),
                    "value": f.get("value", "") or "",
                    "placeholder": f.get("placeholder", "") or "",
                    "prefill": bool(f.get("prefill")),
                    "prompt": f.get("prompt", "") or "",
                    "field_key": f.get("field_key", "") or "",
                }
            )
        try:
            pdf_bytes = _source_bytes(agr)
        except Exception:
            pdf_bytes = None
    else:
        name = (name or layout.get("name") or "Untitled template").strip()
        signers = list(layout.get("signers") or [])
        fields = list(layout.get("fields") or [])
        if layout.get("source_doc_id"):
            # Company-doc ingestion was an estate-only feature (a host document library). The
            # standalone engine builds templates ONLY from uploaded PDF bytes or an agreement it
            # owns (source_agreement_id) — there is no external doc store to read from.
            raise ValueError("doc_id ingestion is not supported in standalone")
        elif layout.get("source_agreement_id"):
            src_agr_id = int(layout["source_agreement_id"])
            agr = _resolve_source_agreement(src_agr_id)
            if not agr:
                return {"ok": False, "error": "agreement not found"}
            try:
                pdf_bytes = _source_bytes(agr)
            except Exception:
                pdf_bytes = None

    if not name:
        name = "Untitled template"
    conn = db.connect()
    try:
        page_n = 0
        if pdf_bytes:
            try:
                page_n = pdf_edit.page_count(pdf_bytes)
            except Exception:
                page_n = 0
        tid = db.insert_returning(
            conn,
            "INSERT INTO esign_templates(name,created_by,source_doc_id,source_agreement_id,"
            "signers_json,fields_json,page_n,created_at,owner_account_id) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                name,
                created_by or "Will",
                source_doc_id,
                src_agr_id,
                json.dumps(signers),
                json.dumps(fields),
                page_n,
                time.time(),
                owner_account_id,
            ),
        )
        if pdf_bytes:
            p = ESIGN_DIR / f"tpl_{tid}_source.pdf"
            p.write_bytes(pdf_bytes)
            conn.execute(
                "UPDATE esign_templates SET source_path=?, doc_hash=? WHERE id=?",
                (str(p), pdf_edit.sha256(pdf_bytes), tid),
            )
        conn.commit()
        return {"ok": True, "id": tid}
    finally:
        conn.close()


def _tpl_row_out(r: dict) -> dict:
    try:
        signers = json.loads(r.get("signers_json") or "[]")
    except Exception:
        signers = []
    try:
        fields = json.loads(r.get("fields_json") or "[]")
    except Exception:
        fields = []
    return {
        "id": r["id"],
        "name": r.get("name") or "Untitled template",
        "created_by": r.get("created_by", "") or "",
        "created_at": r.get("created_at"),
        "archived_at": r.get("archived_at"),
        "page_n": int(r.get("page_n") or 0),
        "signer_n": len(signers),
        "field_n": len(fields),
        "signers": signers,
        "fields": fields,
        "has_source": bool(r.get("source_path") or r.get("source_doc_id")),
        "source_doc_id": r.get("source_doc_id"),
        "doc_hash": r.get("doc_hash", "") or "",
        "owner_account_id": r.get("owner_account_id"),
    }


def list_templates(include_archived: bool = False) -> list[dict]:
    """Named templates, newest first. Archived ones excluded unless include_archived.
    UNSCOPED — admin-global surface only (/api/sign/templates). Tenants use *_for_owner."""
    conn = db.connect()
    try:
        q = "SELECT * FROM esign_templates"
        if not include_archived:
            q += " WHERE archived_at IS NULL"
        q += " ORDER BY id DESC"
        return [_tpl_row_out(r) for r in _rows(conn.execute(q))]
    finally:
        conn.close()


def list_templates_for_owner(owner_account_id: int, include_archived: bool = False) -> list[dict]:
    """SIGN-TENANT: a tenant's own templates, newest first. NULL-owner (admin/Will) rows never
    match the owner filter, so they stay invisible. Returns [] for a falsy owner."""
    if not owner_account_id:
        return []
    conn = db.connect()
    try:
        q = "SELECT * FROM esign_templates WHERE owner_account_id=?"
        if not include_archived:
            q += " AND archived_at IS NULL"
        q += " ORDER BY id DESC"
        return [_tpl_row_out(r) for r in _rows(conn.execute(q, (int(owner_account_id),)))]
    finally:
        conn.close()


def get_template(template_id: int) -> dict | None:
    """UNSCOPED read (admin surface). Tenant routes MUST use get_template_owned."""
    conn = db.connect()
    try:
        r = conn.execute("SELECT * FROM esign_templates WHERE id=?", (int(template_id),)).fetchone()
        return _tpl_row_out(dict(r)) if r else None
    finally:
        conn.close()


def get_template_owned(template_id: int, owner_account_id: int) -> dict | None:
    """SIGN-TENANT IDOR CHOKE-POINT for templates (mirrors get_agreement_owned). Returns None
    (→ 404 at the route) for a falsy owner, a missing template, OR a wrong/NULL-owner row. Every
    /api/mysign/templates/{tid}/* handler MUST pass through here before mutating/instantiating."""
    if not owner_account_id:
        return None
    conn = db.connect()
    try:
        r = conn.execute("SELECT * FROM esign_templates WHERE id=?", (int(template_id),)).fetchone()
    finally:
        conn.close()
    if not r:
        return None
    t = dict(r)
    if t.get("owner_account_id") != owner_account_id:
        return None
    return _tpl_row_out(t)


def archive_template(template_id: int) -> bool:
    """Soft-archive (never DROP). UNSCOPED (admin). Idempotent — True only when it actually flipped."""
    conn = db.connect()
    try:
        cur = conn.execute(
            "UPDATE esign_templates SET archived_at=? WHERE id=? AND archived_at IS NULL",
            (time.time(), int(template_id)),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def archive_template_owned(template_id: int, owner_account_id: int) -> bool:
    """Owner-scoped soft-archive. Returns True only when a row owned by THIS account flipped, so a
    tenant can never archive another tenant's (or admin's NULL-owner) template."""
    if not owner_account_id:
        return False
    conn = db.connect()
    try:
        cur = conn.execute(
            "UPDATE esign_templates SET archived_at=? "
            "WHERE id=? AND owner_account_id=? AND archived_at IS NULL",
            (time.time(), int(template_id), int(owner_account_id)),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def instantiate_agreement_from_template(
    template_id: int,
    recipients: list[dict] | None = None,
    name: str | None = None,
    created_by: str = "Will",
    owner_account_id: int | None = None,
    answers: dict | None = None,
) -> dict:
    """Create a fresh DRAFT agreement from a template via the normal create path. `recipients`
    (list of {name,email,role?,is_consumer?,auth?}) override the template's signer roles by
    position; extra recipients beyond the template's roles are appended. `answers` pre-fills the
    template's prefill fields — keyed by each field's `field_key` (the API-friendly way,
    {"company":"Acme"}) or by its positional index; field_key wins. When owner_account_id is set,
    the template MUST belong to that owner (404-style otherwise) and the new draft is stamped with
    that owner. Returns {ok,id}."""
    conn = db.connect()
    try:
        r = conn.execute("SELECT * FROM esign_templates WHERE id=?", (int(template_id),)).fetchone()
    finally:
        conn.close()
    if not r:
        return {"ok": False, "error": "template not found"}
    t = dict(r)
    # SIGN-TENANT choke-point: a tenant may only instantiate its OWN template. A wrong-owner or
    # NULL-owner (admin/Will) template is reported as not-found — never a 403 oracle.
    if owner_account_id and t.get("owner_account_id") != owner_account_id:
        return {"ok": False, "error": "template not found"}
    try:
        tpl_signers = json.loads(t.get("signers_json") or "[]")
    except Exception:
        tpl_signers = []
    try:
        tpl_fields = json.loads(t.get("fields_json") or "[]")
    except Exception:
        tpl_fields = []

    # Resolve the blank source PDF from the engine-owned snapshot file. (The estate build also
    # fell back to a linked company-doc; that external store does not exist in standalone, so a
    # template with no snapshot simply reports no source.)
    pdf_bytes: bytes | None = None
    sp = t.get("source_path")
    if sp and Path(sp).exists():
        pdf_bytes = Path(sp).read_bytes()
    if not pdf_bytes:
        return {"ok": False, "error": "template has no source document"}

    aname = (name or t.get("name") or "Agreement").strip() or "Agreement"
    aid = create_agreement(
        aname, pdf_bytes, "", created_by or "Will", t.get("source_doc_id"), owner_account_id
    )

    recipients = recipients or []
    signers: list[dict] = []
    n = max(len(tpl_signers), len(recipients))
    for i in range(n):
        base = tpl_signers[i] if i < len(tpl_signers) else {}
        rec = recipients[i] if i < len(recipients) else {}
        signers.append(
            {
                "name": rec.get("name") or base.get("name", "") or "",
                "email": rec.get("email") or base.get("email", "") or "",
                "role": rec.get("role") or base.get("role", "signer") or "signer",
                "order": int(base.get("order", i + 1) or (i + 1)),
                "is_consumer": bool(
                    rec.get("is_consumer")
                    if "is_consumer" in rec
                    else base.get("is_consumer", False)
                ),
                "auth": rec.get("auth") or base.get("auth", "email") or "email",
            }
        )
    idx_to_id: dict[int, int] = {}
    if signers:
        set_signers(aid, signers)
        # Deterministic index->new-id map: set_signers DELETEs then INSERTs in list order, so
        # ascending id == our input order (ORDER BY sign_order can tie on parallel signers).
        c2 = db.connect()
        try:
            rows = _rows(
                c2.execute(
                    "SELECT id FROM agreement_signers WHERE agreement_id=? ORDER BY id", (aid,)
                )
            )
        finally:
            c2.close()
        idx_to_id = {i: rows[i]["id"] for i in range(len(rows))}

    answers = answers or {}
    fields: list[dict] = []
    for i, f in enumerate(tpl_fields):
        si = int(f.get("signer_index", 0) or 0)
        value = f.get("value", "") or ""
        # SMART TEMPLATES: a prefill field's value comes from the answers map, overriding the
        # template default. Answers may be keyed by the field's stable `field_key` (the API-friendly
        # way — "answers":{"company":"Acme"}) OR by its positional index (the UI questionnaire's key).
        # field_key wins when both are present.
        if f.get("prefill"):
            fk = f.get("field_key") or ""
            if fk and fk in answers:
                value = str(answers[fk] or "")
            elif str(i) in answers:
                value = str(answers[str(i)] or "")
        fields.append(
            {
                "signer_id": idx_to_id.get(si),
                "type": f.get("type", "text") or "text",
                "page": int(f.get("page", 0) or 0),
                "x": float(f.get("x", 0) or 0),
                "y": float(f.get("y", 0) or 0),
                "w": float(f.get("w", 0) or 0),
                "h": float(f.get("h", 0) or 0),
                "required": bool(f.get("required", True)),
                "value": value,
                "placeholder": f.get("placeholder", "") or "",
                "prefill": bool(f.get("prefill")),
                "prompt": f.get("prompt", "") or "",
                "field_key": f.get("field_key", "") or "",
            }
        )
    if fields:
        set_fields(aid, fields)
    return {"ok": True, "id": aid, "template_id": int(template_id)}


# --- read ------------------------------------------------------------------------
def list_agreements(limit: int | None = None, offset: int = 0) -> list[dict]:
    """Newest envelopes first. With no limit, returns every agreement (back-compat).
    Signer rows + field counts are fetched in two grouped queries (not per-row) to
    avoid the previous N+1 as the envelope count grows."""
    conn = db.connect()
    try:
        q = "SELECT * FROM agreements ORDER BY id DESC"
        params: list = []
        if limit is not None:
            q += " LIMIT ? OFFSET ?"
            params = [int(limit), int(offset)]
        out = _rows(conn.execute(q, params))
        if not out:
            return out
        ids = [a["id"] for a in out]
        placeholders = ",".join("?" for _ in ids)
        # one grouped query for signers across the whole page
        signers_by: dict[int, list] = {a["id"]: [] for a in out}
        for s in _rows(
            conn.execute(
                # viewed_at/signed_at feed the admin Audit event stream (design-medium
                # 106) — without them the stream could only show terminal statuses.
                f"SELECT agreement_id,name,email,status,color,viewed_at,signed_at "
                f"FROM agreement_signers "
                f"WHERE agreement_id IN ({placeholders}) ORDER BY agreement_id, sign_order",
                ids,
            )
        ):
            signers_by.setdefault(s["agreement_id"], []).append(s)
        # one grouped query for field count + max page across the whole page
        fields_by: dict[int, tuple[int, int | None]] = {}
        for fr in _rows(
            conn.execute(
                f"SELECT agreement_id, COUNT(*) AS n, MAX(page) AS mp FROM agreement_fields "
                f"WHERE agreement_id IN ({placeholders}) GROUP BY agreement_id",
                ids,
            )
        ):
            fields_by[fr["agreement_id"]] = (int(fr["n"] or 0), fr["mp"])
        for a in out:
            sg = [
                {k: v for k, v in s.items() if k != "agreement_id"}
                for s in signers_by.get(a["id"], [])
            ]
            a["signers"] = sg
            a["signed_n"] = sum(1 for s in sg if s["status"] == "signed")
            a["signer_n"] = len(sg)
            n, mp = fields_by.get(a["id"], (0, None))
            a["field_n"] = n
            # real lower-bound page count = highest field page index + 1 (0 when no placed fields)
            a["page_n"] = (int(mp) + 1) if mp is not None else 0
        return out
    finally:
        conn.close()


def count_agreements() -> int:
    conn = db.connect()
    try:
        return int(conn.execute("SELECT COUNT(*) FROM agreements").fetchone()[0])
    finally:
        conn.close()


# --- LiftedSign tenant-scoped read surface (SIGN-TENANT-1) -----------------------
# These are owner-filtered SIBLINGS of the admin functions above; the admin engine
# functions (get_agreement/list_agreements/count_agreements) stay UNSCOPED because the
# public signer/envelope flow reuses them. A /api/mysign/* route NEVER calls the admin
# functions — it calls these + get_agreement_owned, so a NULL-owner (admin/Will) row and
# any other tenant's row are invisible (NULL/other-id never satisfy owner_account_id=?).
def list_agreements_for_owner(
    owner_account_id: int, limit: int | None = None, offset: int = 0
) -> list[dict]:
    if not owner_account_id:
        return []  # fail-closed: never run the query with a NULL/0 owner (would leak NULL rows on IS-NULL logic mistakes)
    conn = db.connect()
    try:
        q = "SELECT * FROM agreements WHERE owner_account_id=? ORDER BY id DESC"
        params: list = [int(owner_account_id)]
        if limit is not None:
            q += " LIMIT ? OFFSET ?"
            params += [int(limit), int(offset)]
        out = _rows(conn.execute(q, params))
        if not out:
            return out
        ids = [a["id"] for a in out]
        placeholders = ",".join("?" for _ in ids)
        signers_by: dict[int, list] = {a["id"]: [] for a in out}
        for s in _rows(
            conn.execute(
                f"SELECT agreement_id,name,email,status,color,viewed_at,signed_at "
                f"FROM agreement_signers "
                f"WHERE agreement_id IN ({placeholders}) ORDER BY agreement_id, sign_order",
                ids,
            )
        ):
            signers_by.setdefault(s["agreement_id"], []).append(s)
        fields_by: dict[int, tuple[int, int | None]] = {}
        for fr in _rows(
            conn.execute(
                f"SELECT agreement_id, COUNT(*) AS n, MAX(page) AS mp FROM agreement_fields "
                f"WHERE agreement_id IN ({placeholders}) GROUP BY agreement_id",
                ids,
            )
        ):
            fields_by[fr["agreement_id"]] = (int(fr["n"] or 0), fr["mp"])
        for a in out:
            sg = [
                {k: v for k, v in s.items() if k != "agreement_id"}
                for s in signers_by.get(a["id"], [])
            ]
            a["signers"] = sg
            a["signed_n"] = sum(1 for s in sg if s["status"] == "signed")
            a["signer_n"] = len(sg)
            n, mp = fields_by.get(a["id"], (0, None))
            a["field_n"] = n
            a["page_n"] = (int(mp) + 1) if mp is not None else 0
        return out
    finally:
        conn.close()


def count_agreements_for_owner(owner_account_id: int) -> int:
    if not owner_account_id:
        return 0
    conn = db.connect()
    try:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM agreements WHERE owner_account_id=?",
                (int(owner_account_id),),
            ).fetchone()[0]
        )
    finally:
        conn.close()


def owner_status_counts(owner_account_id: int) -> dict[str, int]:
    """Owner-scoped agreement counts broken out by lifecycle status.

    Returns ``{total, sent, completed}`` for one sign account. ``sent`` = out for signature
    (status='sent'), ``completed`` = executed (status='completed'). Owner-filtered like its
    siblings above — a NULL/0 owner yields all-zero (never leaks admin/NULL-owner rows)."""
    zero = {"total": 0, "sent": 0, "completed": 0}
    if not owner_account_id:
        return dict(zero)
    conn = db.connect()
    try:
        out = dict(zero)
        for r in conn.execute(
            "SELECT status, COUNT(*) AS n FROM agreements WHERE owner_account_id=? GROUP BY status",
            (int(owner_account_id),),
        ).fetchall():
            n = int(r["n"] or 0)
            out["total"] += n
            st = r["status"] or ""
            if st == "sent":
                out["sent"] += n
            elif st == "completed":
                out["completed"] += n
        return out
    finally:
        conn.close()


def delete_agreements_for_owner(owner_account_id: int) -> int:
    """Hard-delete every agreement (and its signer/field/event child rows) owned by a sign
    account. Operator-only, used by server/sign_ops.purge() to clear a test tenant. Owner-
    scoped so it can NEVER touch admin/NULL-owner or another tenant's envelopes. Returns the
    number of agreements deleted."""
    if not owner_account_id:
        return 0
    conn = db.connect()
    try:
        ids = [
            int(r["id"])
            for r in conn.execute(
                "SELECT id FROM agreements WHERE owner_account_id=?",
                (int(owner_account_id),),
            ).fetchall()
        ]
        if not ids:
            return 0
        placeholders = ",".join("?" for _ in ids)
        for tbl in ("agreement_events", "agreement_fields", "agreement_signers"):
            conn.execute(f"DELETE FROM {tbl} WHERE agreement_id IN ({placeholders})", ids)
        conn.execute(f"DELETE FROM agreements WHERE id IN ({placeholders})", ids)
        conn.commit()
        return len(ids)
    finally:
        conn.close()


def delete_draft_owned(agreement_id: int, owner_account_id) -> dict:
    """Hard-delete a DRAFT agreement (+ its child rows and source files) owned by this account.
    Owner-scoped (get_agreement_owned is the 404 IDOR choke-point) and DRAFT-ONLY — a sent or
    completed envelope is a legal record and can only be voided, never deleted. Idempotent-ish:
    a missing/unowned id returns not_found; a non-draft returns locked."""
    agr = get_agreement_owned(agreement_id, owner_account_id)
    if not agr:
        return {"ok": False, "error": "not_found"}
    if (agr.get("status") or "draft") != "draft":
        return {"ok": False, "error": "locked"}  # sent/completed → void, don't delete
    # best-effort remove the stored PDFs (source/frozen/executed) before the rows
    for key in ("source_path", "frozen_path", "executed_path"):
        p = agr.get(key)
        if p:
            try:
                Path(p).unlink(missing_ok=True)
            except OSError:
                pass
    conn = db.connect()
    try:
        for tbl in ("agreement_events", "agreement_fields", "agreement_signers"):
            conn.execute(f"DELETE FROM {tbl} WHERE agreement_id=?", (agreement_id,))
        conn.execute("DELETE FROM agreements WHERE id=?", (agreement_id,))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


def set_order_mode_owned(agreement_id: int, owner_account_id, mode: str) -> dict:
    """Set the signing order_mode ('sequential' | 'parallel') on a DRAFT agreement owned by this
    account. Owner-scoped (get_agreement_owned = the IDOR 404 choke-point) and DRAFT-ONLY — send()
    reads order_mode to decide who is notified first, so it's only meaningful before send; a
    sent/completed envelope is frozen. `_is_sequential` already enforces the order at send."""
    if mode not in ("sequential", "parallel"):
        return {"ok": False, "error": "bad_mode"}
    agr = get_agreement_owned(agreement_id, owner_account_id)
    if not agr:
        return {"ok": False, "error": "not_found"}
    if (agr.get("status") or "draft") != "draft":
        return {"ok": False, "error": "locked"}
    conn = db.connect()
    try:
        conn.execute("UPDATE agreements SET order_mode=? WHERE id=?", (mode, agreement_id))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "order_mode": mode}


def get_agreement_owned(
    agreement_id: int, owner_account_id: int, full: bool = False
) -> dict | None:
    """SIGN-TENANT-1 IDOR CHOKE-POINT. Resolve an agreement ONLY if it belongs to this owner.
    Returns None (→ 404 at the route) for a wrong owner OR a NULL-owner (admin/Will) row. Every
    /api/mysign/{aid}/* handler MUST pass through here before touching the engine mutators."""
    if not owner_account_id:
        return None
    a = get_agreement(agreement_id, full=full)
    if not a:
        return None
    if a.get("owner_account_id") != owner_account_id:
        return None
    return a


def get_agreement(agreement_id: int, full: bool = False) -> dict | None:
    conn = db.connect()
    try:
        row = conn.execute("SELECT * FROM agreements WHERE id=?", (agreement_id,)).fetchone()
        if not row:
            return None
        a = dict(row)
        # CHAL-7 / PII-2: strip per-signer challenge secrets from every serialized payload.
        # esign_access reads the hash/salt via its own raw query, never via get_agreement.
        a["signers"] = [
            _strip_signer_secrets(s)
            for s in _rows(
                conn.execute(
                    "SELECT * FROM agreement_signers WHERE agreement_id=? ORDER BY sign_order",
                    (agreement_id,),
                )
            )
        ]
        a["fields"] = _rows(
            conn.execute("SELECT * FROM agreement_fields WHERE agreement_id=?", (agreement_id,))
        )
        if full:
            a["events"] = _rows(
                conn.execute(
                    "SELECT * FROM agreement_events WHERE agreement_id=? ORDER BY at",
                    (agreement_id,),
                )
            )
        return a
    finally:
        conn.close()


# --- server-internal raw accessors (secrets included) — esign_access.py ONLY ----
def _signer_row_raw(conn, signer_id: int) -> dict | None:
    r = conn.execute("SELECT * FROM agreement_signers WHERE id=?", (signer_id,)).fetchone()
    return dict(r) if r else None


def envelopes_for_email(email_lc: str) -> list[dict]:
    """Every envelope where `email_lc` is a signer — METADATA ONLY (no secrets), newest first.
    Powers the envelope return-page 'inbox' so a returning signer can see and choose from all
    documents addressed to their (already-verified) email. `locked` flags an envelope that still
    has an unmet sender access-challenge for that signer (its contents stay gated until passed)."""
    email_lc = (email_lc or "").strip().lower()
    if not email_lc:
        return []
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT a.envelope_id, a.name, a.status, a.created_at, a.completed_at, "
            "       s.id AS signer_id, s.status AS signer_status, s.challenge_type, s.challenge_passed_at "
            "FROM agreement_signers s JOIN agreements a ON a.id=s.agreement_id "
            "WHERE LOWER(s.email)=? AND a.status NOT IN ('draft') "
            "ORDER BY COALESCE(a.completed_at, a.created_at) DESC",
            (email_lc,),
        ).fetchall()
        out = []
        for r in rows:
            ct = r["challenge_type"] or "none"
            out.append(
                {
                    "envelope_id": r["envelope_id"],
                    "name": r["name"] or "Document",
                    "status": r["status"] or "pending",
                    "created_at": r["created_at"],
                    "completed_at": r["completed_at"],
                    "signer_status": r["signer_status"] or "pending",
                    "locked": ct != "none" and not r["challenge_passed_at"],
                }
            )
        return out
    finally:
        conn.close()


def signer_for_envelope(envelope_id: str, signer_id: int) -> dict | None:
    """Resolve a signer ONLY if it belongs to the agreement whose envelope_id matches.
    Returns the FULL row (secrets included) — server-internal use by esign_access only."""
    conn = db.connect()
    try:
        r = conn.execute(
            "SELECT s.* FROM agreement_signers s JOIN agreements a ON a.id=s.agreement_id "
            "WHERE a.envelope_id=? AND s.id=?",
            (envelope_id, signer_id),
        ).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def agreement_by_envelope(envelope_id: str, full: bool = False) -> dict | None:
    """Resolve an agreement (signer secrets stripped) by its opaque envelope_id."""
    conn = db.connect()
    try:
        row = conn.execute(
            "SELECT id FROM agreements WHERE envelope_id=?", (envelope_id,)
        ).fetchone()
        return get_agreement(int(row["id"]), full=full) if row else None
    finally:
        conn.close()


def signer_by_token_public(token: str) -> dict | None:
    """Non-secret challenge metadata for the signing-page gate (CHAL-4) — id + type +
    prompt + passed-marker ONLY. Never returns the hash/salt."""
    conn = db.connect()
    try:
        r = conn.execute(
            "SELECT id, agreement_id, challenge_type, challenge_prompt, challenge_passed_at "
            "FROM agreement_signers WHERE token=?",
            (token,),
        ).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def mark_challenge_passed(token: str) -> bool:
    """CHAL-4: record that the signing-page challenge was passed for this signer's token."""
    conn = db.connect()
    try:
        cur = conn.execute(
            "UPDATE agreement_signers SET challenge_passed_at=? WHERE token=?",
            (time.time(), token),
        )
        conn.commit()
        return bool(getattr(cur, "rowcount", 0))
    finally:
        conn.close()


def page_render(agreement_id: int, page: int, dpi: int = 144) -> bytes | None:
    agr = get_agreement(agreement_id)
    if not agr or not agr.get("source_path"):
        return None
    try:
        return pdf_edit.render_page(_presented_bytes(agr), page, dpi=dpi)
    except Exception:
        return None


def page_info(agreement_id: int) -> list[dict]:
    # L-21: render page dims from the SAME bytes signers see — the frozen snapshot once the
    # agreement is past draft, the live source while still a draft (editing). Keeps the admin
    # preview from diverging from what was actually sent/signed.
    agr = get_agreement(agreement_id)
    if not agr:
        return []
    return pdf_edit.page_dims(_presented_bytes(agr))


# --- send / sign -----------------------------------------------------------------
def _is_sequential(agr: dict) -> bool:
    """L-19: signing-order enforcement is active only when order_mode == 'sequential'.
    Default ('parallel') notifies/accepts all signers at once (legacy behavior)."""
    return (agr.get("order_mode") or "parallel") == "sequential"


def _next_order_to_notify(agr: dict) -> int | None:
    """L-19: in sequential mode, the lowest sign_order among signers who haven't yet signed.
    That whole order-group is who may sign / should be emailed next. None => everyone done."""
    pending = [
        int(s.get("sign_order") or 1) for s in agr.get("signers", []) if s.get("status") != "signed"
    ]
    return min(pending) if pending else None


def send(agreement_id: int, base_url: str = "") -> dict:
    agr = get_agreement(agreement_id)
    if not agr:
        return {"ok": False, "error": "not found"}
    if not agr["signers"]:
        return {"ok": False, "error": "add at least one signer"}
    # SEND-GATE: send() is first-dispatch only (draft -> out_for_signature). Re-invoking it on an
    # already-sent or terminal agreement would rotate every token (404-ing live links) and reset
    # status='signed' signers back to 'sent', destroying executed state. In-flight re-notification
    # is remind(); there is no legitimate re-send.
    if (agr.get("status") or "draft") not in ("draft", ""):
        return {
            "ok": False,
            "error": f"already sent — this agreement is {agr['status']}; use Remind to re-notify pending signers",
        }
    # Freeze-on-send (EDITOR-1 / ATTRIB-2): snapshot the exact presented bytes into an
    # immutable artifact and hash it. The signer page renders from this frozen copy and
    # finalize stamps onto it, so signed bytes == presented bytes.
    # L-22: a freeze failure is FATAL — without the immutable snapshot the post-send
    # immutability guarantee is lost, so abort the send rather than proceeding silently.
    frozen_path, frozen_hash = "", ""
    try:
        src = _source_bytes(agr)
        # SEND-TIME FLATTEN (integrity): any page that received an in-place TEXT EDIT is
        # rasterized into the frozen snapshot, so the sent legal PDF's visible text == its
        # extracted text — closing the vector cover+redraw remanence (the old glyph bytes stay
        # in the draft content stream under the cover rect; flattening bakes them into pixels and
        # destroys the extractable text layer). FAIL-CLOSED with the freeze: a flatten failure
        # aborts the send rather than shipping a document with recoverable hidden text.
        edited = _edited_page_list(agr)
        if edited:
            # FAIL-CLOSED: an edited index outside the current page range means edited_pages
            # desynced from the PDF (a page-op remap gap). flatten_pages would silently SKIP it
            # and ship the covered pre-edit text recoverably. Abort the send instead.
            npages = pdf_ops.page_count(src)
            if any(not (0 <= i < npages) for i in edited):
                return {
                    "ok": False,
                    "error": "couldn't freeze the document for sending: edited-page tracking is inconsistent; re-open the editor and re-save before sending",
                }
            src = pdf_edit.flatten_pages(src, edited)
        fp = ESIGN_DIR / f"agr_{agreement_id}_frozen.pdf"
        fp.write_bytes(src)
        frozen_path, frozen_hash = str(fp), pdf_edit.sha256(src)
    except Exception as e:  # noqa: BLE001
        return {
            "ok": False,
            "error": f"couldn't freeze the document for sending: {str(e)[:120]}",
        }
    conn = db.connect()
    try:
        links = []
        for s in agr["signers"]:
            tok = secrets.token_urlsafe(18)
            conn.execute(
                "UPDATE agreement_signers SET token=?, status='sent' WHERE id=?",
                (tok, s["id"]),
            )
            _event(conn, agreement_id, "sent", signer_id=s["id"], detail=f"to {s['email']}")
            # ATTRIB-1: the tokenized single-use email link is the authentication factor.
            _event(
                conn,
                agreement_id,
                "SIGNER_AUTHENTICATED",
                signer_id=s["id"],
                detail=f"auth={s.get('auth_method') or 'email'} · single-use token link to {s['email']}",
            )
            links.append(
                {
                    "signer_id": s["id"],
                    "name": s["name"],
                    "email": s["email"],
                    "token": tok,
                    "url": f"{base_url}/sign/{tok}",
                }
            )
        if frozen_path:
            conn.execute(
                "UPDATE agreements SET frozen_path=?, frozen_hash=? WHERE id=?",
                (frozen_path, frozen_hash, agreement_id),
            )
            _event(conn, agreement_id, "DOC_FROZEN", detail=frozen_hash)
        now = time.time()
        conn.execute(
            "UPDATE agreements SET status='out_for_signature', sent_at=?, expires_at=? WHERE id=?",
            (now, now + ESIGN_EXPIRY_DAYS * 86400, agreement_id),
        )
        conn.commit()
    finally:
        conn.close()
    # Outbound webhook: envelope.sent. Lazy import + guarded so a webhook fault NEVER affects signing.
    try:
        from . import webhooks

        webhooks.emit(
            webhooks.EVENT_ENVELOPE_SENT,
            {
                "agreement_id": agreement_id,
                "envelope_id": agr.get("envelope_id", ""),
                "status": "out_for_signature",
            },
            agr.get("owner_account_id"),
        )
    except Exception:  # noqa: BLE001 — webhook isolation: never perturb the signing flow
        log.exception("webhook emit (envelope.sent) failed for agreement %s", agreement_id)
    # Email each signer their link (network — outside the DB transaction).
    # L-19: in sequential mode, only the first order-group is notified now; later
    # signers are emailed by submit_signature as each prior group completes.
    seq = _is_sequential(agr)
    notify_order = _next_order_to_notify(agr) if seq else None
    order_by_signer = {s["id"]: int(s.get("sign_order") or 1) for s in agr["signers"]}
    emailed, errors = 0, []
    try:
        from . import mailer

        for link in links:
            if not (link.get("email") or "").strip():
                continue
            if seq and order_by_signer.get(link["signer_id"]) != notify_order:
                continue  # gated: not this signer's turn yet
            html = mailer.invite_html(
                link["name"] or link["email"],
                agr["name"],
                agr.get("message") or "",
                link["url"],
            )
            r = mailer.send_html(link["email"], f"Signature requested: {agr['name']}", html)
            if r.get("ok"):
                emailed += 1
            else:
                errors.append(r.get("error", "send failed"))
    except Exception as e:  # noqa: BLE001
        errors.append(str(e)[:120])
    if emailed:
        c2 = db.connect()
        try:
            _event(
                c2,
                agreement_id,
                "emailed",
                detail=f"{emailed} signing invite(s) emailed",
            )
            c2.commit()
        finally:
            c2.close()
    return {"ok": True, "links": links, "emailed": emailed, "email_errors": errors}


def self_sign_link(agreement_id: int, signer_id: int, base_url: str = "") -> dict:
    """Owner self-sign: mint this signer's token WITHOUT emailing anyone, open the agreement
    for signing. The signer signs via the normal hosted page (IP + viewed/signed timestamps
    recorded, certificate generated) — just no invite email."""
    conn = db.connect()
    try:
        s = conn.execute(
            "SELECT * FROM agreement_signers WHERE id=? AND agreement_id=?",
            (signer_id, agreement_id),
        ).fetchone()
        if not s:
            return {"ok": False, "error": "signer not found"}
        s = dict(s)
        if s.get("status") == "signed":
            return {"ok": False, "error": "already signed"}
        tok = s.get("token") or secrets.token_urlsafe(18)
        conn.execute(
            "UPDATE agreement_signers SET token=?, status=CASE WHEN status IN ('draft','') THEN 'sent' ELSE status END WHERE id=?",
            (tok, signer_id),
        )
        conn.execute(
            "UPDATE agreements SET status='out_for_signature', sent_at=COALESCE(sent_at, ?) WHERE id=? AND status='draft'",
            (time.time(), agreement_id),
        )
        _event(
            conn,
            agreement_id,
            "self_sign",
            signer_id=signer_id,
            detail=f"{s.get('email') or s.get('name')} self-signing (no email)",
        )
        conn.commit()
        return {"ok": True, "url": f"{base_url}/sign/{tok}", "token": tok}
    finally:
        conn.close()


def remind(agreement_id: int, base_url: str = "") -> dict:
    """Re-email the signing invite to signers who haven't signed yet — same link, no token
    reset, signed signers untouched."""
    agr = get_agreement(agreement_id)
    if not agr:
        return {"ok": False, "error": "not found"}
    if agr["status"] in ("voided", "cancelled", "completed", "draft", "expired"):
        return {"ok": False, "error": f"can't remind — agreement is {agr['status']}"}
    pending = [
        s
        for s in agr["signers"]
        if s.get("status") != "signed" and (s.get("email") or "").strip() and s.get("token")
    ]
    if not pending:
        return {"ok": False, "error": "no pending signers to remind"}

    emailed, errors = 0, []
    conn = db.connect()
    try:
        for s in pending:
            url = f"{base_url}/sign/{s['token']}"
            msg = (agr.get("message") or "").strip()
            name = s["name"] or s["email"]
            # Dedicated reminder template (B5) when available; fall back to the invite.
            if hasattr(mailer, "reminder_html"):
                html = mailer.reminder_html(name, agr["name"], msg, url)
            else:
                msg2 = (
                    msg + "\n\n" if msg else ""
                ) + "Reminder: your signature is still needed on this document."
                html = mailer.invite_html(name, agr["name"], msg2, url)
            r = mailer.send_html(s["email"], f"Reminder — signature requested: {agr['name']}", html)
            if r.get("ok"):
                emailed += 1
                _event(
                    conn,
                    agreement_id,
                    "reminded",
                    signer_id=s["id"],
                    detail=f"reminder to {s['email']}",
                )
            else:
                errors.append(r.get("error", "send failed"))
        conn.commit()
    finally:
        conn.close()
    return {
        "ok": emailed > 0,
        "emailed": emailed,
        "pending": len(pending),
        "errors": errors,
    }


def _signer_by_token(conn, token: str) -> dict | None:
    r = conn.execute("SELECT * FROM agreement_signers WHERE token=?", (token,)).fetchone()
    return dict(r) if r else None


def _challenge_unmet(signer: dict | None) -> bool:
    """CHAL-4 fail-closed gate for the token ACTION routes (page render / consent / submit /
    finalize). The sender access-lock (challenge_type != 'none') was previously enforced ONLY
    on the GET metadata fetch (sign_token_payload), so a direct API caller holding a leaked
    token could render pages, consent, sign, and seal the document without ever passing it.
    A signer whose required challenge has no challenge_passed_at is blocked on every route.
    Callers resolve + None-check the signer first, so None here means 'don't mask a 404'."""
    if not signer:
        return False
    return (signer.get("challenge_type") or "none") != "none" and not signer.get(
        "challenge_passed_at"
    )


def signing_payload(token: str, ip: str = "", ua: str = "") -> dict | None:
    """What the signing page needs; logs a 'viewed' event (first view stamps the signer)."""
    conn = db.connect()
    try:
        s = _signer_by_token(conn, token)
        if not s:
            return None
        agr = get_agreement(s["agreement_id"])
        if not agr:
            return None
        if agr["status"] in ("voided", "cancelled", "declined"):
            return {
                "ok": False,
                "error": "This document has been voided by the sender and can no longer be signed.",
            }
        # EXPIRY: an envelope the sweep marked expired refuses new signing actions (a signer who
        # already signed / a completed envelope still renders its done screen — same as the TTL gate).
        if s["status"] != "signed" and agr["status"] == "expired":
            return {
                "ok": False,
                "error": "This signing request has expired. Please ask the sender to send a new request.",
            }
        # L-20: reject a stale/leaked token's NEW signing actions once past the TTL. A signer
        # who already signed (or a completed envelope) is unaffected so the done/download
        # screen still renders.
        if s["status"] != "signed" and agr["status"] != "completed" and _token_expired(agr):
            return {
                "ok": False,
                "error": "This signing link has expired. Please ask the sender to send a new request.",
            }
        if s["status"] in ("sent", "viewed"):
            if not s["viewed_at"]:
                conn.execute(
                    "UPDATE agreement_signers SET status='viewed', viewed_at=?, ip=?, user_agent=? WHERE id=?",
                    (time.time(), ip, ua[:300], s["id"]),
                )
            _event(conn, s["agreement_id"], "viewed", signer_id=s["id"], ip=ip, ua=ua)
            conn.commit()
        my_fields = [f for f in agr["fields"] if f.get("signer_id") == s["id"]]
        is_consumer = bool(s.get("is_consumer"))
        has_consent = bool(s.get("consent")) and not s.get("consent_withdrawn_at")
        disc = esign_disclosure.disclosure(is_consumer)
        status = "viewed" if s["status"] == "sent" else s["status"]
        return {
            "ok": True,
            "agreement": {
                "id": agr["id"],
                "name": agr["name"],
                "message": agr["message"],
                "status": agr["status"],
            },
            "signer": {
                "id": s["id"],
                "name": s["name"],
                "email": s["email"],
                "status": status,
                "color": s["color"],
                "is_consumer": is_consumer,
                "consent": has_consent,
                "consent_version": disc["version"],
            },
            "pages": pdf_edit.page_dims(_presented_bytes(agr)),
            "fields": my_fields,
            "brand": _BRAND,
            "disclosure": {
                "version": disc["version"],
                "text": disc["text"],
                "text_hash": disc["text_hash"],
                "consumer": is_consumer,
                "hardware_software": disc["hardware_software"],
            },
            "consent_required": not has_consent,
            "decline_allowed": True,
            # token-scoped; only actionable post-completion (page shows it on the done screen)
            "download_url": f"/api/sign/token/{token}/download",
            "consent_url": f"/api/sign/token/{token}/consent",
            "withdraw_url": f"/api/sign/token/{token}/withdraw-consent",
        }
    finally:
        conn.close()


def submit_signature(
    token: str,
    values: dict,
    consent: bool,
    ip: str = "",
    ua: str = "",
    field_meta: dict | None = None,
) -> dict:
    """values: {field_id: text-or-dataURL}. Records the signer's input, marks signed,
    and finalizes the agreement once every signer has signed.

    field_meta: optional {field_id: {adopted_at, method}} per-field adoption evidence
    (INTENT-1). method ∈ {draw, type, reuse}. Missing → back-compat behavior."""
    if not consent:
        return {"ok": False, "error": "consent required"}
    field_meta = field_meta or {}
    conn = db.connect()
    try:
        s = _signer_by_token(conn, token)
        if not s:
            return {"ok": False, "error": "invalid link"}
        if _challenge_unmet(s):  # CHAL-4: sender access-lock not passed — cannot sign
            return {
                "ok": False,
                "error": "Access verification required",
                "challenge_required": True,
            }
        st = conn.execute(
            "SELECT status, doc_hash, frozen_hash, created_at, sent_at FROM agreements WHERE id=?",
            (s["agreement_id"],),
        ).fetchone()
        if st and st[0] in ("voided", "cancelled", "declined"):
            return {
                "ok": False,
                "error": "This document is no longer available for signing.",
            }
        # EXPIRY: a swept envelope cannot be signed even if the link-TTL window hasn't elapsed.
        if st and st[0] == "expired":
            return {
                "ok": False,
                "error": "This signing request has expired. Please ask the sender to send a new request.",
            }
        # L-20: reject a stale/leaked token's signing action once past the TTL (measured from send,
        # not draft creation). A re-POST by an already-signed signer is handled idempotently below.
        if (
            st
            and st[0] != "completed"
            and _token_expired({"created_at": st["created_at"], "sent_at": st["sent_at"]})
        ):
            return {
                "ok": False,
                "error": "This signing link has expired. Please ask the sender to send a new request.",
            }
        if s.get("consent_withdrawn_at") or s["status"] == "declined":
            return {
                "ok": False,
                "error": "consent was withdrawn — this document cannot be signed electronically.",
            }
        if s["status"] == "signed":
            # FINALIZE-RETRY: this signer already signed (durable), but if a transient failure in
            # finalize() left the envelope un-sealed (all signed yet status != completed), re-drive
            # finalize on this idempotent re-POST so the doc can't be permanently stranded. This
            # branch has issued only SELECTs, so conn holds no write lock; finalize opens its own.
            completed = False
            agr_status = st[0] if st else ""
            if agr_status not in ("completed", "voided", "cancelled", "declined"):
                unsigned = conn.execute(
                    "SELECT COUNT(*) FROM agreement_signers WHERE agreement_id=? AND status!='signed'",
                    (s["agreement_id"],),
                ).fetchone()[0]
                if unsigned == 0:
                    completed = finalize(s["agreement_id"])
            return {"ok": True, "already": True, "completed": completed}
        # L-19: sequential signing-order enforcement. A signer cannot submit until every
        # prior-order signer has completed. Resolve order from the agreement (secrets stripped).
        agr_seq = get_agreement(s["agreement_id"])
        if agr_seq and _is_sequential(agr_seq):
            my_order = int(s.get("sign_order") or 1)
            ahead_unsigned = any(
                int(o.get("sign_order") or 1) < my_order and o.get("status") != "signed"
                for o in agr_seq.get("signers", [])
            )
            if ahead_unsigned:
                return {
                    "ok": False,
                    "error": "It's not your turn yet — an earlier signer must sign first.",
                }
        # CONSENT-1: server-side gate — a consumer signer must have recorded ESIGN consent
        # (via /consent) BEFORE signing. B2B relies on the page-level checkbox (consent=True).
        if s.get("is_consumer") and not s.get("consent_at"):
            return {"ok": False, "error": "consent required"}
        # REQFIELD-1: server-side required-field gate. Browser JS is advisory only — a raw
        # POST (missing/empty values) must NOT mark the signer signed, and must never let a
        # blank required field seal into the irreversible executed PDF. Every required field
        # owned by THIS signer must carry a non-empty value; signature/initials must be a
        # parseable image data-URL (not whitespace or a truncated/empty data URI).
        req_fields = conn.execute(
            "SELECT id, type FROM agreement_fields WHERE agreement_id=? AND signer_id=? AND required=1",
            (s["agreement_id"], s["id"]),
        ).fetchall()
        for rf in req_fields:
            rid, rtype = rf[0], (rf[1] or "").lower()
            raw = (values or {}).get(str(rid))
            if raw is None:
                raw = (values or {}).get(rid)
            val_r = raw.strip() if isinstance(raw, str) else raw
            if not val_r:
                return {
                    "ok": False,
                    "error": "Please complete all required fields before submitting.",
                }
            if rtype in ("signature", "initials"):
                # Must be a REAL image (not merely base64-decodable) — otherwise insert_image
                # raises at seal, stamp_fields swallows it, and a blank field seals as "signed".
                if not pdf_edit.is_valid_image(pdf_edit._png_from_data_url(val_r)):
                    return {
                        "ok": False,
                        "error": "A required signature or initials field is missing or invalid.",
                    }
            elif rtype == "checkbox":
                # A required checkbox must be actually CHECKED, not just a non-empty string
                # (a crafted "false" would otherwise pass and seal the box unchecked).
                if not pdf_edit._is_checked(raw):
                    return {
                        "ok": False,
                        "error": "Please check all required boxes before submitting.",
                    }
        doc_hash_ref = (
            st["frozen_hash"] if st and st["frozen_hash"] else (st["doc_hash"] if st else "")
        ) or ""
        _ADOPT = {"draw", "type", "reuse"}
        adopted_imgs = set()
        for fid, val in (values or {}).items():
            meta = field_meta.get(str(fid)) or field_meta.get(fid) or {}
            method = str(meta.get("method") or "").lower()
            method = method if method in _ADOPT else ""
            adopted_at = meta.get("adopted_at")
            conn.execute(
                "UPDATE agreement_fields SET value=?, adopted_at=?, sign_method=? WHERE id=? AND agreement_id=? AND signer_id=?",
                (val, adopted_at, method, int(fid), s["agreement_id"], s["id"]),
            )
            # type of this field (only signature/initials emit adoption + per-field signed events)
            ftype = conn.execute(
                "SELECT type FROM agreement_fields WHERE id=? AND agreement_id=?",
                (int(fid), s["agreement_id"]),
            ).fetchone()
            ft = (ftype[0] if ftype else "") or ""
            if ft in ("signature", "initials"):
                _event(
                    conn,
                    s["agreement_id"],
                    "FIELD_SIGNED",
                    signer_id=s["id"],
                    ip=ip,
                    ua=ua,
                    detail=f"field={fid} doc={doc_hash_ref[:16]} method={method or 'n/a'}",
                )
                if val and val not in adopted_imgs:
                    adopted_imgs.add(val)
                    _event(
                        conn,
                        s["agreement_id"],
                        "SIGNATURE_ADOPTED",
                        signer_id=s["id"],
                        ip=ip,
                        ua=ua,
                        detail=f"method={method or 'n/a'}",
                    )
        conn.execute(
            "UPDATE agreement_signers SET status='signed', signed_at=?, ip=?, user_agent=?, consent=1, signature_id=? WHERE id=?",
            (time.time(), ip, ua[:300], _signature_id(), s["id"]),
        )
        _event(
            conn,
            s["agreement_id"],
            "signed",
            signer_id=s["id"],
            ip=ip,
            ua=ua,
            detail=f"{len(values or {})} field(s)",
        )
        conn.commit()
        remaining = conn.execute(
            "SELECT COUNT(*) FROM agreement_signers WHERE agreement_id=? AND status!='signed'",
            (s["agreement_id"],),
        ).fetchone()[0]
    finally:
        conn.close()
    # Outbound webhook: signer.signed. Lazy import + guarded so a webhook fault NEVER affects signing.
    try:
        from . import webhooks

        _owner = (get_agreement(s["agreement_id"]) or {}).get("owner_account_id")
        webhooks.emit(
            webhooks.EVENT_SIGNER_SIGNED,
            {"agreement_id": s["agreement_id"], "signer_id": s["id"], "status": "signed"},
            _owner,
        )
    except Exception:  # noqa: BLE001 — webhook isolation: never perturb the signing flow
        log.exception("webhook emit (signer.signed) failed for signer %s", s["id"])
    completed = False
    if remaining == 0:
        completed = finalize(s["agreement_id"])
    else:
        # L-19: sequential cascade — once this signer completes, email the next order-group.
        _notify_next_sequential(s["agreement_id"])
    return {"ok": True, "completed": completed}


def _notify_next_sequential(agreement_id: int) -> None:
    """L-19: in sequential mode, email the now-active next order-group their signing link.
    Best-effort, network-only; a parallel agreement is a no-op (everyone was emailed at send)."""
    agr = get_agreement(agreement_id)
    if (
        not agr
        or not _is_sequential(agr)
        or agr.get("status") in ("voided", "cancelled", "completed")
    ):
        return
    nxt = _next_order_to_notify(agr)
    if nxt is None:
        return
    base = (
        (_cfg.local().get("esign", {}) or {}).get("public_base") or _cfg.PUBLIC_BASE_URL
    ).rstrip("/")
    conn = db.connect()
    try:
        for s in agr["signers"]:
            if int(s.get("sign_order") or 1) != nxt or s.get("status") == "signed":
                continue
            email = (s.get("email") or "").strip()
            tok = s.get("token")
            if not email or not tok:
                continue
            url = f"{base}/sign/{tok}"
            html = mailer.invite_html(
                s.get("name") or email, agr["name"], agr.get("message") or "", url
            )
            r = mailer.send_html(email, f"Signature requested: {agr['name']}", html)
            if (r or {}).get("ok"):
                _event(
                    conn,
                    agreement_id,
                    "emailed",
                    signer_id=s["id"],
                    detail=f"sequential turn — invite to {email}",
                )
        conn.commit()
    finally:
        conn.close()


def record_consent(token: str, body: dict, ip: str = "", ua: str = "") -> dict:
    """ESIGN consent capture BEFORE signing (CONSENT-1/2/3). Idempotent."""
    body = body or {}
    if not body.get("agreed"):
        return {"ok": False, "error": "consent required"}
    conn = db.connect()
    try:
        s = _signer_by_token(conn, token)
        if not s:
            return {"ok": False, "error": "invalid link"}
        if _challenge_unmet(s):  # CHAL-4: sender access-lock not passed — cannot consent
            return {
                "ok": False,
                "error": "Access verification required",
                "challenge_required": True,
            }
        st = conn.execute(
            "SELECT status FROM agreements WHERE id=?", (s["agreement_id"],)
        ).fetchone()
        if st and st[0] in ("voided", "cancelled", "declined"):
            return {
                "ok": False,
                "error": "This document has been voided and can no longer be signed.",
            }
        # Idempotent: re-POST returns the prior consent timestamp without double-writing.
        if s.get("consent_at"):
            return {"ok": True, "consent_at": s["consent_at"], "already": True}
        now = time.time()
        dv = str(body.get("disclosure_version") or "")
        dh = str(body.get("disclosure_text_hash") or "")
        access_demo = 1 if body.get("access_demonstrated") else 0
        access_method = str(body.get("access_method") or "")
        conn.execute(
            "UPDATE agreement_signers SET consent=1, consent_at=?, consent_ip=?, disclosure_version=?, "
            "disclosure_text_hash=?, access_demonstrated=?, access_method=? WHERE id=?",
            (now, ip, dv, dh, access_demo, access_method, s["id"]),
        )
        _event(
            conn,
            s["agreement_id"],
            "ECONSENT_ACCEPTED",
            signer_id=s["id"],
            ip=ip,
            ua=ua,
            detail=f"{dv} · {access_method or 'consent'}",
        )
        if access_demo:
            _event(
                conn,
                s["agreement_id"],
                "RECORDS_ACCESS_DEMONSTRATED",
                signer_id=s["id"],
                ip=ip,
                ua=ua,
                detail=access_method or "viewed electronic record",
            )
        conn.commit()
        return {"ok": True, "consent_at": now}
    finally:
        conn.close()


def withdraw_consent(token: str, reason: str = "", ip: str = "", ua: str = "") -> dict:
    """CONSENT-4: operable consent withdrawal. Before completion this declines the signer
    (routes to paper per the disclosure); after completion it is record-only."""
    conn = db.connect()
    try:
        s = _signer_by_token(conn, token)
        if not s:
            return {"ok": False, "error": "invalid link"}
        if _challenge_unmet(s):  # CHAL-4: sender access-lock not passed — cannot withdraw (M-2)
            return {
                "ok": False,
                "error": "Access verification required",
                "challenge_required": True,
            }
        if s.get("consent_withdrawn_at"):
            return {
                "ok": True,
                "withdrawn_at": s["consent_withdrawn_at"],
                "already": True,
            }
        now = time.time()
        st = conn.execute(
            "SELECT status FROM agreements WHERE id=?", (s["agreement_id"],)
        ).fetchone()
        completed = bool(st and st[0] == "completed")
        conn.execute(
            "UPDATE agreement_signers SET consent_withdrawn_at=? WHERE id=?",
            (now, s["id"]),
        )
        _event(
            conn,
            s["agreement_id"],
            "ECONSENT_WITHDRAWN",
            signer_id=s["id"],
            ip=ip,
            ua=ua,
            detail=reason or "",
        )
        if not completed:
            conn.execute("UPDATE agreement_signers SET status='declined' WHERE id=?", (s["id"],))
            conn.execute(
                "UPDATE agreements SET status='declined' WHERE id=? AND status NOT IN ('completed','voided','cancelled')",
                (s["agreement_id"],),
            )
        conn.commit()
        return {"ok": True, "withdrawn_at": now}
    finally:
        conn.close()


def signer_download(token: str) -> dict:
    """Signer-facing executed-PDF download (RETAIN-2). Only after completion, only for a
    signer of this envelope. Returns {ok, bytes, filename} or {ok:False,...}. Emits
    COMPLETED_COPY_DELIVERED once per signer."""
    conn = db.connect()
    try:
        s = _signer_by_token(conn, token)
        if not s:
            return {"ok": False, "error": "invalid"}
        agr = get_agreement(s["agreement_id"])
        if not agr:
            return {"ok": False, "error": "invalid"}
        if agr.get("status") != "completed":
            return {"ok": False, "error": "not yet completed"}
        p = agr.get("executed_path")
        if not (p and Path(p).exists()):
            return {"ok": False, "error": "not yet completed"}
        data = Path(p).read_bytes()
        base = re.sub(r"\.pdf$", "", agr.get("name", "") or "", flags=re.I)
        base = re.sub(r'[\\/:*?"<>|\r\n]+', "", base).strip() or f"agreement-{agr['id']}"
        fn = f"{base}-SIGNED.pdf"[:90]
        # Emit the delivery event once per signer (dedupe on existing event).
        seen = conn.execute(
            "SELECT 1 FROM agreement_events WHERE agreement_id=? AND signer_id=? AND type='COMPLETED_COPY_DELIVERED' LIMIT 1",
            (s["agreement_id"], s["id"]),
        ).fetchone()
        if not seen:
            _event(
                conn,
                s["agreement_id"],
                "COMPLETED_COPY_DELIVERED",
                signer_id=s["id"],
                detail="signer download",
            )
            conn.commit()
        return {"ok": True, "bytes": data, "filename": fn}
    finally:
        conn.close()


def signer_download_by_id(agreement_id: int, signer_id: int) -> dict:
    """Envelope-page executed-PDF download (ENV-6), keyed by agreement+session signer
    (not a token). Mirrors signer_download: completed-only, emits COMPLETED_COPY_DELIVERED
    once per signer. The caller (route) has already proven the session via require_env_session."""
    conn = db.connect()
    try:
        s = conn.execute(
            "SELECT id FROM agreement_signers WHERE id=? AND agreement_id=?",
            (signer_id, agreement_id),
        ).fetchone()
        if not s:
            return {"ok": False, "error": "invalid"}
        agr = get_agreement(agreement_id)
        if not agr or agr.get("status") != "completed":
            return {"ok": False, "error": "not yet completed"}
        p = agr.get("executed_path")
        if not (p and Path(p).exists()):
            return {"ok": False, "error": "not yet completed"}
        data = Path(p).read_bytes()
        base = re.sub(r"\.pdf$", "", agr.get("name", "") or "", flags=re.I)
        base = re.sub(r'[\\/:*?"<>|\r\n]+', "", base).strip() or f"agreement-{agr['id']}"
        fn = f"{base}-SIGNED.pdf"[:90]
        seen = conn.execute(
            "SELECT 1 FROM agreement_events WHERE agreement_id=? AND signer_id=? AND type='COMPLETED_COPY_DELIVERED' LIMIT 1",
            (agreement_id, signer_id),
        ).fetchone()
        if not seen:
            _event(
                conn,
                agreement_id,
                "COMPLETED_COPY_DELIVERED",
                signer_id=signer_id,
                detail="envelope download",
            )
            conn.commit()
        return {"ok": True, "bytes": data, "filename": fn}
    finally:
        conn.close()


def decline(token: str, reason: str = "", ip: str = "", ua: str = "") -> dict:
    conn = db.connect()
    try:
        s = _signer_by_token(conn, token)
        if not s:
            return {"ok": False, "error": "invalid link"}
        if _challenge_unmet(s):  # CHAL-4: sender access-lock not passed — cannot decline (M-2)
            return {
                "ok": False,
                "error": "Access verification required",
                "challenge_required": True,
            }
        # Single-use semantics: a signer who already signed (or whose envelope is finished)
        # cannot retroactively decline; don't clobber a completed/voided agreement status.
        if s.get("status") == "signed":
            return {"ok": False, "error": "already signed"}
        st = conn.execute(
            "SELECT status FROM agreements WHERE id=?", (s["agreement_id"],)
        ).fetchone()
        if st and st[0] in ("completed", "voided", "cancelled"):
            return {
                "ok": False,
                "error": f"document is {st[0]} and can no longer be declined",
            }
        conn.execute("UPDATE agreement_signers SET status='declined' WHERE id=?", (s["id"],))
        conn.execute(
            "UPDATE agreements SET status='declined' WHERE id=? AND status NOT IN ('completed','voided','cancelled')",
            (s["agreement_id"],),
        )
        _event(
            conn,
            s["agreement_id"],
            "declined",
            signer_id=s["id"],
            ip=ip,
            ua=ua,
            detail=reason,
        )
        conn.commit()
        agr = get_agreement(s["agreement_id"])
        decliner = s.get("name") or s.get("email") or "A signer"
    finally:
        conn.close()
    # Notify the sender (outside the DB transaction; best-effort like finalize).
    try:
        from . import mailer

        sender_email = _sender_email(agr)  # L-23: resolve from agreement, not hardcoded
        if agr and hasattr(mailer, "declined_html"):
            html = mailer.declined_html(
                agr.get("name", ""), decliner, reason or "", agr.get("envelope_id", "")
            )
            mailer.send_html(sender_email, f"Declined: {agr.get('name', '')}", html)
    except Exception:
        pass
    # Outbound webhook: envelope.declined. Lazy import + guarded so a webhook fault NEVER affects signing.
    try:
        from . import webhooks

        webhooks.emit(
            webhooks.EVENT_ENVELOPE_DECLINED,
            {
                "agreement_id": s["agreement_id"],
                "signer_id": s["id"],
                "status": "declined",
                "reason": reason,
            },
            (agr or {}).get("owner_account_id"),
        )
    except Exception:  # noqa: BLE001 — webhook isolation: never perturb the signing flow
        log.exception("webhook emit (envelope.declined) failed for signer %s", s["id"])
    return {"ok": True}


def sweep_expired(now: float | None = None) -> int:
    """Background sweep: flip every out_for_signature envelope past its expires_at to status
    'expired', record expired_at, log an 'expired' event, and notify the SENDER only (never the
    signers). Idempotent + race-safe: the UPDATE's `status='out_for_signature'` guard means a
    concurrent finalize ('sealing'/'completed') or void is never clobbered. This is a SYSTEM actor
    and is intentionally NOT owner-scoped — it queries across all tenants. Returns the count expired."""
    now = time.time() if now is None else now
    expired_ids: list[int] = []
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT id FROM agreements WHERE status='out_for_signature' "
            "AND expires_at IS NOT NULL AND expires_at<=?",
            (now,),
        ).fetchall()
        for r in rows:
            aid = r[0]
            changed = conn.execute(
                "UPDATE agreements SET status='expired', expired_at=? "
                "WHERE id=? AND status='out_for_signature'",
                (now, aid),
            ).rowcount
            if changed:
                _event(conn, aid, "expired", detail="auto-expired: signing window elapsed")
                expired_ids.append(aid)
        conn.commit()
    finally:
        conn.close()
    # Notify each sender (outside the txn; best-effort like decline/finalize). Signers are NOT emailed.
    for aid in expired_ids:
        try:
            from . import mailer

            agr = get_agreement(aid)
            if not agr:
                continue
            # Outbound webhook: envelope.expired (per-agreement owner; NULL-owner legacy rows emit 0).
            try:
                from . import webhooks

                webhooks.emit(
                    webhooks.EVENT_ENVELOPE_EXPIRED,
                    {"agreement_id": aid, "status": "expired"},
                    agr.get("owner_account_id"),
                )
            except Exception:  # noqa: BLE001 — webhook isolation: never perturb the sweep
                log.exception("webhook emit (envelope.expired) failed for agreement %s", aid)
            if hasattr(mailer, "expired_html"):
                html = mailer.expired_html(agr.get("name", ""), agr.get("envelope_id", ""))
            else:
                html = (
                    f'Your signing request "{agr.get("name", "")}" has expired and can no longer '
                    "be signed. Create a new envelope to send it again."
                )
            mailer.send_html(_sender_email(agr), f"Expired: {agr.get('name', '')}", html)
        except Exception:
            pass
    return len(expired_ids)


def _load_signing_material(es: dict) -> tuple[bytes | None, bytes | None]:
    """Resolve the PAdES signing cert + key from the esign config block.

    The private key MUST live OUTSIDE the git worktree — either inline PEM supplied
    via the SIGN_PADES_*_PEM environment variables or a path (SIGN_PADES_*_PATH) that
    resolves under a gitignored / non-repo directory. Returns (cert_pem, key_pem) as bytes, or
    (None, None) when no usable material is configured (→ AES fallback). Never raises.
    """
    if not es:
        return None, None

    def _resolve(inline_key: str, path_key: str) -> bytes | None:
        inline = es.get(inline_key)
        if isinstance(inline, str) and inline.strip():
            return inline.encode("utf-8")
        p = es.get(path_key)
        if isinstance(p, str) and p.strip():
            try:
                path = Path(p)
                if not path.is_absolute():
                    # relative → install root (e.g. state/esign/…, which is gitignored)
                    path = _cfg.REPO_ROOT / p
                if path.exists():
                    return path.read_bytes()
            except OSError:
                return None
        return None

    cert = _resolve("signing_cert_pem", "signing_cert_path")
    key = _resolve("signing_key_pem", "signing_key_path")
    if cert and key:
        return cert, key
    return None, None


def ensure_signing_material() -> None:
    """Provision a self-signed PAdES cert+key on first boot when none is configured.

    So a zero-config install seals completed documents with a REAL PKCS#7/PAdES certification
    signature (validate() → valid+certified+not-tampered) instead of the AES-only fallback that
    validate() cannot attest to. Idempotent: writes the pair once, into the gitignored data dir
    (0600 key), and never overwrites explicit SIGN_PADES_* material or an existing pair. A no-op
    when SIGN_PADES_AUTOCERT=false or the operator supplied their own cert/key.
    """
    if not _cfg.PADES_AUTOCERT:
        return
    cert_path, key_path = _cfg.AUTOCERT_CERT, _cfg.AUTOCERT_KEY
    # Respect any explicitly-configured material. _esign_block() points signing_cert_path at the
    # autocert file ONLY when no explicit SIGN_PADES_* is set, so inline PEM, or a resolved path
    # that is not our autocert path, means the operator supplied their own — don't shadow it.
    es = _cfg.local().get("esign", {}) or {}
    if es.get("signing_cert_pem") or es.get("signing_key_pem"):
        return
    resolved = es.get("signing_cert_path") or ""
    if resolved and resolved != str(cert_path):
        return
    if cert_path.exists() and key_path.exists():
        return
    try:
        cert_pem, key_pem = pdf_sign.generate_self_signed()
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)
        try:  # best-effort private-key lockdown (POSIX; no-op semantics on Windows)
            key_path.chmod(0o600)
        except OSError:
            pass
    except Exception:
        # Never block startup on provisioning — the engine falls back to the AES seal.
        return


def finalize(agreement_id: int) -> bool:
    """Stamp field values, append the certificate, store the executed copy. Idempotent +
    race-safe: an already-completed envelope returns True without re-sealing/re-emailing, and an
    atomic 'sealing' claim ensures two concurrent last-signer submits can't both seal (which would
    double-email and write a divergent sealed_hash). On seal failure the claim is RELEASED so the
    retry path can re-seal — the envelope is never stranded in 'sealing'."""
    agr = get_agreement(agreement_id, full=True)
    if not agr:
        return False
    if agr.get("status") == "completed":
        return True  # idempotent — already sealed; no re-seal, no duplicate completion emails
    # CHAL-4 defense-in-depth: never seal a document where any signer's required sender
    # access-lock was bypassed. The per-route gates should make this unreachable, but a
    # sealed legal doc is irreversible, so refuse here as the last line.
    if any(_challenge_unmet(s) for s in agr["signers"]):
        return False
    # Atomically CLAIM the seal so two concurrent last-signer submits can't both run the seal
    # (double executed-file write + duplicate emails + divergent sealed_hash). Only the winner
    # proceeds; a loser bails and reports the completed status. The claim also RECLAIMS an
    # abandoned seal — a 'sealing' row whose sealing_at is stale (the sealer died out-of-band
    # before completing/releasing) — so an interrupted seal self-heals instead of stranding
    # forever. Terminal statuses are excluded (defense-in-depth; callers already block them).
    # Reset target on seal failure: a doc is 'out_for_signature' before sealing, so reclaiming a
    # stale 'sealing' (or a legacy blank) resets to that — never back to 'sealing' (would re-strand).
    prior_status = (
        "out_for_signature" if agr.get("status") in ("sealing", "", None) else agr["status"]
    )
    now = time.time()
    _cc = db.connect()
    try:
        claimed = (
            _cc.execute(
                "UPDATE agreements SET status='sealing', sealing_at=? "
                "WHERE id=? AND status NOT IN ('completed','voided','cancelled','declined','expired') "
                "AND (status!='sealing' OR sealing_at IS NULL OR sealing_at < ?)",
                (now, agreement_id, now - _SEAL_STALE_S),
            ).rowcount
            == 1
        )
        _cc.commit()
    finally:
        _cc.close()
    if not claimed:
        cur = get_agreement(agreement_id, full=True)
        return bool(cur and cur.get("status") == "completed")
    try:
        return _seal_and_complete(agreement_id, agr)
    except Exception:
        # CRITICAL: release the claim so submit_signature's retry path can re-seal — without
        # this a mid-seal crash would strand the envelope in 'sealing' forever (a new stuck bug).
        try:
            _rc = db.connect()
            _rc.execute(
                "UPDATE agreements SET status=? WHERE id=? AND status='sealing'",
                (prior_status, agreement_id),
            )
            _rc.commit()
            _rc.close()
        except Exception:
            pass
        raise


def _seal_and_complete(agreement_id: int, agr: dict) -> bool:
    """The seal body: stamp fields, append certificate, seal, store, email. Called only by
    finalize() under the atomic 'sealing' claim. Its final commit flips status → completed."""
    # Stamp onto the FROZEN presented bytes so signed == presented (ATTRIB-2 / EDITOR-1).
    src = _presented_bytes(agr)
    env = agr.get("envelope_id", "")
    # Did any signer consent under a consumer disclosure? Embed that exact text in the cert.
    consumer_signer = any(s.get("is_consumer") for s in agr["signers"])
    disc = esign_disclosure.disclosure(consumer_signer)
    smap = {s["id"]: s for s in agr["signers"]}
    # map fields → stamp dicts (value text or signature image data-url already stored)
    stamp = []
    for f in agr["fields"]:
        if (f.get("value") or "").strip():
            d = {k: f[k] for k in ("type", "page", "x", "y", "w", "h")}
            if f["type"] in ("signature", "initials"):
                d["image"] = f["value"]
                s = smap.get(f.get("signer_id")) or {}
                d["stamp_meta"] = {
                    "name": s.get("name") or s.get("email") or "",
                    "ip": s.get("ip") or "",
                    "when": _fmt_signed(s.get("signed_at")),
                    "sig_id": s.get("signature_id") or "",
                    "env": env,
                }
            else:
                d["value"] = f["value"]
            stamp.append(d)
    stamped = pdf_edit.stamp_fields(src, stamp)
    agr["status"] = "completed"  # cert reflects the final state it's certifying
    # TAMPER-1: hash the stamped (pre-seal) bytes.
    preseal_hash = pdf_edit.sha256(stamped)
    sig_map: dict = {}
    for f in agr["fields"]:
        if (
            f["type"] in ("signature", "initials")
            and f.get("value")
            and f.get("signer_id") not in sig_map
        ):
            sig_map[f["signer_id"]] = f["value"]
    # Surface the seal hashes to the certificate renderer (B2 reads them off the agreement).
    agr["preseal_hash"] = preseal_hash
    # Decide the seal method BEFORE rendering the certificate so the cert wording is
    # truthful. PAdES certification signature when a signing cert/key is configured AND
    # parses + is currently valid (pdf_sign.material_ok); else the AES-256 fallback.

    _es = _cfg.local().get("esign", {}) or {}
    _cert_pem, _key_pem = _load_signing_material(_es)
    _passphrase = (_es.get("signing_key_passphrase") or "").encode("utf-8") or None
    seal_method = "pades" if pdf_sign.material_ok(_cert_pem, _key_pem, _passphrase) else "aes"

    def _render_cert(method: str) -> bytes:
        # L-39: make_certificate's signature is stable (all evidence args are optional
        # kwargs), so the old try/except TypeError fallback is removed — a TypeError here
        # is now a genuine renderer bug and is allowed to propagate.
        return pdf_edit.make_certificate(
            agr,
            agr["signers"],
            agr["events"],
            preseal_hash,
            signatures=sig_map,
            pages=pdf_edit.page_count(src),
            fields_n=len(agr["fields"]),
            disclosure_text=disc["text"],
            disclosure_version=disc["version"],
            seal_method=method,
        )

    cert = _render_cert(seal_method)
    executed = pdf_edit.append_pdf(stamped, cert)
    if seal_method == "pades":
        # Signing must be the LAST byte op: sanitize (scrub+subset+flatten, NO encryption)
        # first — any re-serialization after certify_pdf invalidates the signature.
        sanitized = pdf_edit.sanitize_pdf(executed)
        try:
            executed = pdf_sign.certify_pdf(
                sanitized,
                _cert_pem,
                _key_pem,
                key_passphrase=_passphrase,
                reason=f"Certified executed copy of envelope {env} — no changes permitted",
            )
        except Exception:
            # material_ok passed, so this is genuinely unexpected. FAIL-HONEST (R5.2):
            # never ship an AES-sealed file carrying "certified" wording — re-render the
            # cert with AES wording, re-seal with AES, and record the degrade.
            log.exception(
                "esign.finalize: PAdES certification failed; degrading to AES seal (agr=%s)",
                agreement_id,
            )
            seal_method = "aes"
            cert = _render_cert("aes")
            executed = pdf_edit.append_pdf(stamped, cert)
            executed = pdf_edit.secure_pdf(executed)
    else:
        log.info(
            "esign.finalize: no signing cert configured; using AES fallback seal (agr=%s)",
            agreement_id,
        )
        executed = pdf_edit.secure_pdf(executed)  # AES-256 + flatten seal (fallback)
    sealed_hash = pdf_edit.sha256(executed)  # TAMPER-1: post-seal hash
    out = ESIGN_DIR / f"agr_{agreement_id}_executed.pdf"
    out.write_bytes(executed)
    conn = db.connect()
    try:
        conn.execute(
            "UPDATE agreements SET status='completed', completed_at=?, executed_path=?, doc_hash=?, "
            "preseal_hash=?, sealed_hash=?, seal_method=? WHERE id=?",
            (
                time.time(),
                str(out),
                sealed_hash,
                preseal_hash,
                sealed_hash,
                seal_method,
                agreement_id,
            ),
        )
        _event(
            conn,
            agreement_id,
            "DOC_SEALED",
            detail=f"method={seal_method} preseal={preseal_hash[:16]} sealed={sealed_hash[:16]}",
        )
        # R5.2: a configured cert that we intended to sign with but couldn't (degraded to
        # AES) is recorded as a distinct, alertable audit event — the seal is weaker than
        # provisioned and Will should re-provision.
        if _cert_pem and _key_pem and seal_method != "pades":
            _event(
                conn,
                agreement_id,
                "DOC_SEAL_DEGRADED",
                detail="signing cert configured but PAdES certification failed; sealed with AES fallback",
            )
        _event(
            conn,
            agreement_id,
            "completed",
            detail="executed copy + certificate generated",
        )
        conn.commit()
    finally:
        conn.close()
    # RETAIN-2: email the fully-executed copy (+ certificate) to every signer AND the sender.
    try:
        from . import mailer

        recips = {
            (s.get("email") or "").strip() for s in agr["signers"] if (s.get("email") or "").strip()
        }
        recips.add(_sender_email(agr))  # L-23: sender copy → agreement creator, not hardcoded
        if recips:
            env_id_ = agr.get("envelope_id", "")
            _eb = (_cfg.local().get("esign", {}) or {}).get("public_base") or _cfg.PUBLIC_BASE_URL
            env_url = f"{_eb.rstrip('/')}/envelope/{env_id_}" if env_id_ else ""
            html = mailer.completed_html(agr["name"], env_id_, env_url, seal_method=seal_method)
            base = re.sub(r"\.pdf$", "", agr["name"], flags=re.I).strip() or "Document"
            att = [(f"{base}-SIGNED.pdf"[:90], executed)]
            c3 = db.connect()
            try:
                for to in recips:
                    r = mailer.send_html(
                        to, f"Completed & signed: {agr['name']}", html, attachments=att
                    )
                    if (r or {}).get("ok"):
                        sid = next(
                            (
                                s["id"]
                                for s in agr["signers"]
                                if (s.get("email") or "").strip().lower() == to.lower()
                            ),
                            None,
                        )
                        _event(
                            c3,
                            agreement_id,
                            "COMPLETED_COPY_DELIVERED",
                            signer_id=sid,
                            detail=f"emailed to {to}",
                        )
                c3.commit()
            finally:
                c3.close()
    except Exception:
        pass
    # Outbound webhook: envelope.completed. Fires exactly once at the single completion point (under
    # the atomic seal claim). Lazy import + guarded so a webhook fault NEVER affects signing.
    try:
        from . import webhooks

        webhooks.emit(
            webhooks.EVENT_ENVELOPE_COMPLETED,
            {
                "agreement_id": agreement_id,
                "envelope_id": agr.get("envelope_id", ""),
                "status": "completed",
            },
            agr.get("owner_account_id"),
        )
    except Exception:  # noqa: BLE001 — webhook isolation: never perturb the signing flow
        log.exception("webhook emit (envelope.completed) failed for agreement %s", agreement_id)
    return True


def executed_bytes(agreement_id: int) -> bytes | None:
    agr = get_agreement(agreement_id)
    if not agr:
        return None
    p = agr.get("executed_path") or agr.get("source_path")
    return Path(p).read_bytes() if p and Path(p).exists() else None


def presented_bytes(agreement_id: int) -> bytes | None:
    """Raw bytes exactly as page_render/page_info source them — the frozen snapshot once sent,
    else the live draft source. The editor's PDF.js canvas fetches this so it matches the PNG
    render pixel-for-pixel (both go through _presented_bytes). Owner check is the caller's job."""
    agr = get_agreement(agreement_id)
    if not agr:
        return None
    try:
        return _presented_bytes(agr)
    except Exception:
        return None


def certificate_bytes(agreement_id: int) -> bytes | None:
    """Re-render ONLY the Certificate of Completion PDF (separate from the bundled executed
    copy) for admin preview — read-only, sourced from the stored agreement + events. Does
    NOT re-stamp or re-seal; reuses the persisted hash chain (preseal_hash/sealed_hash) so the
    certificate it shows is identical in content to the one embedded in the executed copy.

    Returns the certificate bytes, or None when the agreement isn't completed (404 at the
    route)."""
    agr = get_agreement(agreement_id, full=True)
    if not agr or agr.get("status") != "completed":
        return None
    # Embed the same disclosure that any consumer signer consented under.
    consumer_signer = any(s.get("is_consumer") for s in agr["signers"])
    disc = esign_disclosure.disclosure(consumer_signer)
    # Reuse the stored hash chain (no re-seal); pages/fields counts from the presented bytes.
    preseal = agr.get("preseal_hash") or ""
    sealed = agr.get("sealed_hash") or agr.get("doc_hash") or ""
    try:
        pages = pdf_edit.page_count(_presented_bytes(agr))
    except Exception:
        pages = 0
    sig_map: dict = {}
    for f in agr["fields"]:
        if (
            f["type"] in ("signature", "initials")
            and f.get("value")
            and f.get("signer_id") not in sig_map
        ):
            sig_map[f["signer_id"]] = f["value"]
    # The cert renderer reads preseal/sealed off the agreement and via kwargs.
    agr["preseal_hash"] = preseal
    agr["sealed_hash"] = sealed
    kwargs = dict(
        signatures=sig_map,
        pages=pages,
        fields_n=len(agr["fields"]),
        disclosure_text=disc["text"],
        disclosure_version=disc["version"],
        preseal_hash=preseal,
        sealed_hash=sealed,
        # Re-render with the SAME seal method the executed copy used, so the standalone
        # cert preview states exactly what the embedded one does (default 'aes' for legacy
        # rows sealed before this column existed).
        seal_method=(agr.get("seal_method") or "aes"),
    )
    # The seal hash arg (doc_hash positional) is the pre-seal hash the cert certifies.
    # L-39: signature is stable; the try/except TypeError fallback was removed so a
    # genuine renderer TypeError propagates instead of being masked as back-compat.
    return pdf_edit.make_certificate(agr, agr["signers"], agr["events"], preseal, **kwargs)


def void(agreement_id: int, reason: str = "") -> bool:
    conn = db.connect()
    try:
        # TRAN-2: voiding bumps the env-session epoch so any live envelope session is revoked.
        conn.execute(
            "UPDATE agreements SET status='voided', "
            "env_session_epoch=COALESCE(env_session_epoch,0)+1 WHERE id=?",
            (agreement_id,),
        )
        _event(conn, agreement_id, "voided", detail=reason)
        conn.commit()
        # Outbound webhook: envelope.voided. Lazy import + guarded so a webhook fault NEVER affects
        # signing. The row still resolves post-void with owner_account_id intact.
        try:
            from . import webhooks

            _owner = (get_agreement(agreement_id) or {}).get("owner_account_id")
            webhooks.emit(
                webhooks.EVENT_ENVELOPE_VOIDED,
                {"agreement_id": agreement_id, "status": "voided", "reason": reason},
                _owner,
            )
        except Exception:  # noqa: BLE001 — webhook isolation: never perturb the signing flow
            log.exception("webhook emit (envelope.voided) failed for agreement %s", agreement_id)
        return True
    finally:
        conn.close()


def set_signer_challenge(
    agreement_id: int,
    signer_id: int,
    ctype: str,
    prompt: str,
    salt: str,
    wrapped_hash: str,
    iters: int,
) -> bool:
    """CHAL-7: persist (or clear when ctype=='none') a signer's access-lock challenge.
    The caller (route, admin-gated) derives salt/wrapped_hash/iters via esign_access.hash_challenge;
    the raw value NEVER reaches this function. Emits ACCESS_CHALLENGE_CONFIGURED (type only)."""
    conn = db.connect()
    try:
        s = conn.execute(
            "SELECT id FROM agreement_signers WHERE id=? AND agreement_id=?",
            (signer_id, agreement_id),
        ).fetchone()
        if not s:
            return False
        if ctype == "none":
            conn.execute(
                "UPDATE agreement_signers SET challenge_type='none', challenge_prompt='', "
                "challenge_salt='', challenge_hash='', challenge_iters=0, challenge_passed_at=NULL "
                "WHERE id=?",
                (signer_id,),
            )
        else:
            conn.execute(
                "UPDATE agreement_signers SET challenge_type=?, challenge_prompt=?, "
                "challenge_salt=?, challenge_hash=?, challenge_iters=?, challenge_passed_at=NULL "
                "WHERE id=?",
                (ctype, prompt or "", salt, wrapped_hash, int(iters), signer_id),
            )
        _event(
            conn,
            agreement_id,
            ACCESS_CHALLENGE_CONFIGURED,
            signer_id=signer_id,
            detail=f"type={ctype}",
        )
        conn.commit()
    finally:
        conn.close()
    # L-26: a mid-session challenge change must not leave an existing envelope session (whose
    # chal_ok was frozen at mint) with open access. Bump the epoch so require_env_session()
    # invalidates any live session for this agreement — the established TRAN-2 mechanism.
    bump_env_session_epoch(agreement_id)
    return True


def bump_env_session_epoch(agreement_id: int) -> int:
    """TRAN-2: revoke all live envelope sessions for this agreement by bumping the epoch.
    Returns the new epoch."""
    conn = db.connect()
    try:
        conn.execute(
            "UPDATE agreements SET env_session_epoch=COALESCE(env_session_epoch,0)+1 WHERE id=?",
            (agreement_id,),
        )
        row = conn.execute(
            "SELECT env_session_epoch FROM agreements WHERE id=?", (agreement_id,)
        ).fetchone()
        conn.commit()
        return int(row["env_session_epoch"]) if row else 0
    finally:
        conn.close()
