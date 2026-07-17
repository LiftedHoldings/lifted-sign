"""Persistence layer — SQLite bootstrap, round-trips, additive migration seam, rate/lock helpers.

The zero-config default is SQLite; a fresh boot must create every table (the extraction blocker),
core inserts/selects must round-trip through the hybrid row shim, ``db._columns`` must drive the
additive-migration path (never a raw PRAGMA), and the auth rate-limit / lockout primitives that
gate every login must behave.
"""

from __future__ import annotations

import time

import pytest


@pytest.fixture(scope="module", autouse=True)
def _tables(client):
    # `client` runs the app lifespan → db.ensure_tables() + every sibling ensure_tables().
    yield


def test_fresh_db_creates_core_tables(client):
    from sign import db

    conn = db.connect()
    try:
        names = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
    finally:
        conn.close()
    for t in (
        "settings",
        "auth_limits",
        "auth_rate_limits",
        "agreements",
        "agreement_signers",
        "agreement_fields",
        "agreement_events",
        "sign_accounts",
        "sign_api_keys",
    ):
        assert t in names, (t, sorted(names))


def test_settings_round_trip(client):
    from sign import db

    db.set_setting("t_key", {"a": 1, "b": "two"})
    assert db.get_setting("t_key") == {"a": 1, "b": "two"}
    # scalar + default paths
    db.set_setting("t_scalar", 42)
    assert int(db.get_setting("t_scalar")) == 42
    assert db.get_setting("missing_key", "fallback") == "fallback"


def test_insert_returning_and_select(client):
    from sign import db

    conn = db.connect()
    try:
        aid = db.insert_returning(
            conn,
            "INSERT INTO agreements(name,status,created_at) VALUES(?,?,?)",
            ("RoundTrip", "draft", time.time()),
        )
        conn.commit()
        row = conn.execute("SELECT name,status FROM agreements WHERE id=?", (aid,)).fetchone()
    finally:
        conn.close()
    assert aid > 0
    # hybrid row supports both index and key access
    assert row[0] == "RoundTrip"
    assert row["status"] == "draft"


def test_columns_lists_schema_additively(client):
    from sign import db

    conn = db.connect()
    try:
        cols = db._columns(conn, "sign_accounts")
    finally:
        conn.close()
    assert "email" in cols and "email_verified" in cols and "totp_secret" in cols
    # a non-existent table returns an empty list, never raises
    conn = db.connect()
    try:
        assert db._columns(conn, "no_such_table_xyz") == []
    finally:
        conn.close()


def test_auth_rate_allowed_enforces_window(client):
    from sign import db

    key = f"unit:rate:{time.time()}"
    # first N within the window pass, N+1 is throttled
    assert all(db.auth_rate_allowed(key, 3, 3600) for _ in range(3))
    assert db.auth_rate_allowed(key, 3, 3600) is False


def test_auth_limit_lockout(client):
    from sign import db

    key = f"unit:lock:{time.time()}"
    assert db.auth_limit_locked(key) is False
    # record failures up to the cap → locks
    for _ in range(5):
        db.auth_limit_record(key, ok=False, fail_limit=5, lock_seconds=900)
    assert db.auth_limit_locked(key) is True
    # a success clears the counter/lock
    db.auth_limit_record(key, ok=True, fail_limit=5, lock_seconds=900)
    assert db.auth_limit_locked(key) is False


def test_use_pg_false_on_sqlite_default(client):
    from sign import db

    assert db._use_pg() is False
    assert isinstance(db.now(), float)
