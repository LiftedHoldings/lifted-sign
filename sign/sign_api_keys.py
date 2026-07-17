"""Developer API keys for Lifted Sign accounts.

A sign account can mint Bearer API keys (`sk_live_…` / `sk_test_…`) so a third-party backend can
call the `/api/mysign/*` API programmatically instead of driving the interactive cookie login.
A key resolves to exactly one account and flows through the SAME `_require_owned` IDOR choke-point
as the session cookie — keys grant no authority a logged-in user doesn't already have.

Security posture (mirrors sign_accounts password handling):
  * The full key is shown ONCE at creation and never stored — only a PBKDF2 hash + a short,
    non-secret prefix (for O(1) lookup) are persisted. A DB leak cannot recover a usable key.
  * Lookup by indexed `key_prefix`, then constant-time verify against `key_hash`.
  * Revocation is a row flag (revoked_at) — instant, no epoch bump needed.
  * A key for a suspended/deleted account resolves to nothing (fail-closed).
"""

from __future__ import annotations

import secrets
import time

from . import db, sign_accounts

_PREFIX_LEN = 14  # "sk_live_" (8) + 6 token chars — non-secret, indexed; verify disambiguates
_SCHEMA = """
CREATE TABLE IF NOT EXISTS sign_api_keys (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id   INTEGER NOT NULL,
  label        TEXT DEFAULT '',
  key_prefix   TEXT NOT NULL,
  key_hash     TEXT NOT NULL,
  mode         TEXT DEFAULT 'live',
  created_at   REAL,
  last_used_at REAL,
  revoked_at   REAL
);
CREATE INDEX IF NOT EXISTS idx_sign_api_keys_acct ON sign_api_keys(account_id);
CREATE INDEX IF NOT EXISTS idx_sign_api_keys_prefix ON sign_api_keys(key_prefix);
"""


def ensure_tables() -> None:
    conn = db.connect()
    try:
        for stmt in _SCHEMA.strip().split(";"):
            if stmt.strip():
                conn.execute(stmt)
        conn.commit()
    finally:
        conn.close()


def _row(r) -> dict | None:
    if r is None:
        return None
    return dict(r) if not isinstance(r, dict) else r


def _public(row: dict) -> dict:
    """Safe-to-return metadata (never the hash)."""
    return {
        "id": row["id"],
        "label": row.get("label") or "",
        "prefix": row.get("key_prefix") or "",
        "mode": row.get("mode") or "live",
        "created_at": row.get("created_at"),
        "last_used_at": row.get("last_used_at"),
        "revoked": bool(row.get("revoked_at")),
    }


def issue(account_id: int, label: str = "", mode: str = "live") -> tuple[str, dict]:
    """Mint a new key. Returns (raw_key, public_meta). The raw key is shown ONCE — only the
    prefix + PBKDF2 hash are stored."""
    mode = "test" if str(mode) == "test" else "live"
    raw = "sk_" + mode + "_" + secrets.token_urlsafe(24)
    prefix = raw[:_PREFIX_LEN]
    conn = db.connect()
    try:
        rid = db.insert_returning(
            conn,
            "INSERT INTO sign_api_keys(account_id,label,key_prefix,key_hash,mode,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (
                int(account_id),
                str(label or "")[:80],
                prefix,
                sign_accounts.hash_password(raw),
                mode,
                time.time(),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return raw, {
        "id": rid,
        "label": str(label or "")[:80],
        "prefix": prefix,
        "mode": mode,
        "created_at": time.time(),
        "last_used_at": None,
        "revoked": False,
    }


def resolve(bearer: str) -> dict | None:
    """Bearer `sk_live_…` -> the owning, active sign_account (or None). Fail-closed."""
    if not bearer or not isinstance(bearer, str) or not bearer.startswith("sk_"):
        return None
    prefix = bearer[:_PREFIX_LEN]
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT * FROM sign_api_keys WHERE key_prefix=? AND revoked_at IS NULL", (prefix,)
        ).fetchall()
        for r in rows:
            row = _row(r)
            if sign_accounts.verify_password(bearer, row["key_hash"]):
                acct = sign_accounts.account_by_id(row["account_id"])
                if acct and (acct.get("status") or "active") == "active":
                    try:
                        conn.execute(
                            "UPDATE sign_api_keys SET last_used_at=? WHERE id=?",
                            (time.time(), row["id"]),
                        )
                        conn.commit()
                    except Exception:  # noqa: BLE001 — last_used_at is best-effort telemetry
                        pass
                    return acct
                return None  # key valid but account suspended/gone -> deny
    finally:
        conn.close()
    return None


def list_for_account(account_id: int) -> list[dict]:
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT * FROM sign_api_keys WHERE account_id=? AND revoked_at IS NULL"
            " ORDER BY created_at DESC",
            (int(account_id),),
        ).fetchall()
        return [_public(_row(r)) for r in rows]
    finally:
        conn.close()


def revoke(key_id: int, account_id: int) -> bool:
    """Owner-scoped revoke — the account_id filter is the IDOR guard (can't revoke another
    account's key). Idempotent."""
    conn = db.connect()
    try:
        cur = conn.execute(
            "UPDATE sign_api_keys SET revoked_at=? WHERE id=? AND account_id=? AND revoked_at IS NULL",
            (time.time(), int(key_id), int(account_id)),
        )
        conn.commit()
        return (cur.rowcount or 0) > 0
    finally:
        conn.close()


ensure_tables()
