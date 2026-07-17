"""Operator-console data layer for ``/api/sign-ops/*``.

Standalone reimplementation of the host application's ``server/sign_ops`` module
(referenced by :mod:`sign.routers.ops` and by the docstrings in :mod:`sign.esign`),
which was not carried across in the extraction. It provides the small set of
all-accounts operator operations the console calls: list every account with its
owned-document count, a rollup summary, suspend/unsuspend, and a test-tenant purge.

Authorization is NOT enforced here — the router (:mod:`sign.routers.ops`) gates every
route on ``config.ADMIN_EMAILS`` before any of these run. This module is a thin layer
over :mod:`sign.sign_accounts` (the sole mutator of the accounts table) and
:mod:`sign.esign` (owner-scoped agreement counts / purge), so no table is touched
directly and every delete stays owner-scoped.
"""

from __future__ import annotations

from . import esign, sign_accounts

# Emails whose local-part carries one of these prefixes are throwaway rows created by
# the isolation / P2 test suites — the only accounts ``purge_test_rows`` will remove.
_TEST_PREFIXES = ("isotest-", "p2test-")


def _plan_monthly() -> float:
    """Monthly plan price as a float, parsed from ``sign_accounts.PLAN['price']``
    (e.g. ``"$29.99/mo"`` → ``29.99``) so the MRR rollup never drifts from the plan
    definition. Returns 0.0 if the price string carries no number."""
    raw = str(sign_accounts.PLAN.get("price") or "")
    digits = ""
    for ch in raw:
        if ch.isdigit() or ch == ".":
            digits += ch
        elif digits:
            break
    try:
        return float(digits) if digits else 0.0
    except ValueError:
        return 0.0


def _account_view(acct: dict) -> dict:
    """Operator-safe projection of one account plus its owned-document count.

    Built on ``sign_accounts.public_view`` (never exposes pw_hash / totp_secret) and
    augmented with the operator-only fields the console renders."""
    aid = acct.get("id")
    view = sign_accounts.public_view(acct)
    view["created_at"] = acct.get("created_at")
    view["last_login_at"] = acct.get("last_login_at")
    view["docs"] = esign.count_agreements_for_owner(int(aid)) if aid else 0
    return view


def list_accounts() -> list[dict]:
    """Every sign account (newest first) with its owned-document count."""
    return [_account_view(a) for a in sign_accounts.list_accounts()]


def summary() -> dict:
    """Portfolio rollup: totals + a hypothetical MRR (subscribed accounts × plan price)."""
    accts = sign_accounts.list_accounts()
    total = len(accts)
    active = sum(1 for a in accts if (a.get("status") or "active") == "active")
    suspended = sum(1 for a in accts if (a.get("status") or "") == "suspended")
    subscribed = sum(1 for a in accts if (a.get("sub_status") or "") == "active")
    return {
        "total": total,
        "active": active,
        "suspended": suspended,
        "subscribed": subscribed,
        "mrr": round(subscribed * _plan_monthly(), 2),
        "plan_price": sign_accounts.PLAN.get("price", ""),
    }


def set_status(aid: int, suspended: bool) -> dict:
    """Suspend (``suspended=True``) or reinstate a single account.

    Suspending also bumps the session version so the account's live sessions are
    invalidated immediately. Returns ``{"ok": False, "error": "not_found"}`` for an
    unknown id so the router can map it to a 404."""
    acct = sign_accounts.account_by_id(aid)
    if not acct:
        return {"ok": False, "error": "not_found"}
    new_status = "suspended" if suspended else "active"
    sign_accounts._update(int(aid), status=new_status)
    if suspended:
        sign_accounts.bump_session_version(int(aid))
    return {"ok": True, "id": int(aid), "status": new_status}


def purge_test_rows() -> dict:
    """Delete leftover test tenants (email local-part beginning ``isotest-`` / ``p2test-``)
    and every agreement they own.

    Owner-scoped throughout: agreements are removed via ``esign.delete_agreements_for_owner``
    (which can never touch admin/NULL-owner or another tenant's rows) and the account via
    ``sign_accounts.delete_account``. A real tenant is never matched."""
    removed: list[str] = []
    docs_removed = 0
    for a in sign_accounts.list_accounts():
        email = (a.get("email") or "").strip().lower()
        local = email.split("@", 1)[0]
        if not local.startswith(_TEST_PREFIXES):
            continue
        aid = a.get("id")
        if not aid:
            continue
        docs_removed += esign.delete_agreements_for_owner(int(aid))
        if sign_accounts.delete_account(int(aid)):
            removed.append(email)
    return {
        "ok": True,
        "accounts_removed": len(removed),
        "docs_removed": docs_removed,
        "emails": removed,
    }
