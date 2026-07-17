"""Developer API-key resolution, fail-closed denial, and owner-scoped revocation.

``sign_api_keys`` is the Bearer-token authn path for the programmatic ``/api/mysign/*`` API. The
golden-path lifecycle (issue → list → revoke → 401) is covered elsewhere; these tests pin the
security-critical *edges* of ``resolve()`` and ``revoke()`` that a leaked or stale key must not slip
through:

  * a non-``sk_`` / empty / wrong-secret bearer resolves to nothing (fail-closed),
  * a key whose account is suspended resolves to nothing even though the key row is still un-revoked
    (the account-status gate, not just the revoked flag),
  * a successful resolve stamps ``last_used_at`` (telemetry the console shows),
  * revoke is owner-scoped (an IDOR guard: you cannot revoke another account's key) and idempotent,
  * ``list_for_account`` hides revoked keys, and test/live modes carry distinct prefixes.
"""

from __future__ import annotations

from sign import sign_accounts, sign_api_keys, sign_ops


def test_resolve_rejects_non_bearer_and_garbage(client, account_factory):
    auth = account_factory()
    raw, _ = sign_api_keys.issue(auth.id, "k", "live")
    # None / empty / non-string / wrong scheme all fail closed without touching the DB path.
    assert sign_api_keys.resolve(None) is None
    assert sign_api_keys.resolve("") is None
    assert sign_api_keys.resolve(123) is None  # type: ignore[arg-type]
    assert sign_api_keys.resolve("Bearer " + raw) is None  # scheme prefix, not the bare key
    assert sign_api_keys.resolve("pk_live_" + raw[8:]) is None  # not an sk_ key
    # A real, un-tampered key still resolves (control).
    assert (sign_api_keys.resolve(raw) or {}).get("id") == auth.id


def test_resolve_wrong_secret_same_prefix_denied(client, account_factory):
    """The 14-char prefix is a non-secret lookup key; authority comes from the constant-time
    hash verify. A string sharing the prefix but not the secret must be denied."""
    auth = account_factory()
    raw, _ = sign_api_keys.issue(auth.id, "k", "live")
    # Keep the indexed prefix identical, corrupt only the secret tail → hash verify must fail.
    tampered = raw[:14] + ("A" if raw[14] != "A" else "B") + raw[15:]
    assert tampered[:14] == raw[:14]
    assert sign_api_keys.resolve(tampered) is None


def test_resolve_suspended_account_fail_closed(client, account_factory):
    """A valid, un-revoked key for a SUSPENDED account must resolve to nothing — the status gate
    is independent of the revoked flag, so suspending an account instantly kills its API keys."""
    auth = account_factory()
    raw, _ = sign_api_keys.issue(auth.id, "k", "live")
    assert sign_api_keys.resolve(raw) is not None  # active → resolves
    sign_ops.set_status(auth.id, True)  # suspend
    assert sign_api_keys.resolve(raw) is None  # suspended → denied even though key not revoked
    sign_ops.set_status(auth.id, False)  # reinstate → works again
    assert (sign_api_keys.resolve(raw) or {}).get("id") == auth.id


def test_resolve_stamps_last_used_at(client, account_factory):
    auth = account_factory()
    raw, meta = sign_api_keys.issue(auth.id, "k", "live")
    kid = meta["id"]
    before = next(k for k in sign_api_keys.list_for_account(auth.id) if k["id"] == kid)
    assert before["last_used_at"] is None
    assert sign_api_keys.resolve(raw) is not None
    after = next(k for k in sign_api_keys.list_for_account(auth.id) if k["id"] == kid)
    assert after["last_used_at"] is not None


def test_revoke_is_owner_scoped_and_idempotent(client, account_factory):
    a, b = account_factory(), account_factory()
    raw, meta = sign_api_keys.issue(a.id, "k", "live")
    kid = meta["id"]
    # Another account cannot revoke A's key (IDOR guard) — and the key still works.
    assert sign_api_keys.revoke(kid, b.id) is False
    assert sign_api_keys.resolve(raw) is not None
    # Owner revokes → first call flips it, re-revoke is a no-op, and the key stops authenticating.
    assert sign_api_keys.revoke(kid, a.id) is True
    assert sign_api_keys.revoke(kid, a.id) is False
    assert sign_api_keys.resolve(raw) is None


def test_list_hides_revoked_and_modes_have_distinct_prefixes(client, account_factory):
    auth = account_factory()
    raw_live, live = sign_api_keys.issue(auth.id, "live-key", "live")
    raw_test, test = sign_api_keys.issue(auth.id, "test-key", "test")
    assert raw_live.startswith("sk_live_") and live["mode"] == "live"
    assert raw_test.startswith("sk_test_") and test["mode"] == "test"
    # An unrecognized mode string is coerced to "live" (fail-safe default, never a third bucket).
    raw_other, other = sign_api_keys.issue(auth.id, "weird", "staging")
    assert raw_other.startswith("sk_live_") and other["mode"] == "live"

    ids = {k["id"] for k in sign_api_keys.list_for_account(auth.id)}
    assert {live["id"], test["id"]} <= ids
    sign_api_keys.revoke(test["id"], auth.id)
    ids_after = {k["id"] for k in sign_api_keys.list_for_account(auth.id)}
    assert test["id"] not in ids_after  # revoked keys are hidden from the listing
    assert live["id"] in ids_after


def test_resolve_after_account_deleted_denied(client, account_factory):
    """A key whose account row is gone resolves to nothing (account_by_id → None branch)."""
    auth = account_factory()
    raw, _ = sign_api_keys.issue(auth.id, "k", "live")
    assert sign_accounts.delete_account(auth.id) is True
    assert sign_api_keys.resolve(raw) is None
