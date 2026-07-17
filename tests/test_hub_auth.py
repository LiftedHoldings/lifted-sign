"""Optional Google Sign-In OAuth engine (``sign.hub_auth``).

Exercised with the Google env configured and the token exchange + id-token verification
monkeypatched, so the authorization-URL build, the code→email exchange, nonce binding, and the
``email_verified`` gate are covered without contacting Google.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def google_env(monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "client-123.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "secret-abc")
    monkeypatch.setenv("GOOGLE_OAUTH_REDIRECT", "https://sign.example.com/cb")


def test_configured_and_login_url(google_env):
    from sign import hub_auth

    assert hub_auth.configured() is True
    url = hub_auth.google_login_url("state-1", nonce="nonce-1")
    assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert "client_id=client-123" in url
    assert "state=state-1" in url and "nonce=nonce-1" in url


def test_login_url_empty_when_unconfigured(monkeypatch):
    from sign import hub_auth

    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_ID", raising=False)
    assert hub_auth.google_login_url("s") == ""
    assert hub_auth.configured() is False


def test_login_url_empty_without_redirect(monkeypatch):
    from sign import hub_auth

    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "sec")
    monkeypatch.delenv("GOOGLE_OAUTH_REDIRECT", raising=False)
    assert hub_auth.google_login_url("s", redirect_uri="") == ""


class _FakeTokenResp:
    def __init__(self, id_token):
        self._idt = id_token

    def raise_for_status(self):
        return None

    def json(self):
        return {"id_token": self._idt}


def test_exchange_code_returns_verified_email(google_env, monkeypatch):
    from sign import hub_auth

    monkeypatch.setattr(hub_auth.httpx, "post", lambda *a, **k: _FakeTokenResp("idt-xyz"))
    monkeypatch.setattr(
        hub_auth,
        "_verify_google_id_token",
        lambda idt, cid: {"email": "user@example.com", "email_verified": True, "nonce": "n1"},
    )
    assert hub_auth.exchange_code("code", expected_nonce="n1") == "user@example.com"


def test_exchange_code_rejects_nonce_mismatch(google_env, monkeypatch):
    from sign import hub_auth

    monkeypatch.setattr(hub_auth.httpx, "post", lambda *a, **k: _FakeTokenResp("idt"))
    monkeypatch.setattr(
        hub_auth,
        "_verify_google_id_token",
        lambda idt, cid: {"email": "u@example.com", "email_verified": True, "nonce": "wrong"},
    )
    assert hub_auth.exchange_code("code", expected_nonce="expected") is None


def test_exchange_code_rejects_unverified_email(google_env, monkeypatch):
    from sign import hub_auth

    monkeypatch.setattr(hub_auth.httpx, "post", lambda *a, **k: _FakeTokenResp("idt"))
    monkeypatch.setattr(
        hub_auth,
        "_verify_google_id_token",
        lambda idt, cid: {"email": "u@example.com", "email_verified": False},
    )
    assert hub_auth.exchange_code("code") is None


def test_exchange_code_none_when_unconfigured(monkeypatch):
    from sign import hub_auth

    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_SECRET", raising=False)
    assert hub_auth.exchange_code("code") is None


def test_verify_id_token_guards(monkeypatch):
    from sign import hub_auth

    # missing token / client id → None without importing google-auth
    assert hub_auth._verify_google_id_token("", "cid") is None
    assert hub_auth._verify_google_id_token("idt", "") is None
