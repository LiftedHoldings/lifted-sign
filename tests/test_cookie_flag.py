"""SIGN_INSECURE_COOKIES flips the __Host- prefix + Secure attribute together.

Secure default: cookies are ``__Host-<name>`` + Secure (require HTTPS). With the opt-in flag set
(trusted-LAN / plain-http dev), the prefix and Secure are BOTH dropped so login works over http.
The two must always move in lockstep — a ``__Host-`` cookie without Secure is rejected by browsers.
"""

from __future__ import annotations

from sign import config


def test_secure_default(monkeypatch):
    monkeypatch.setattr(config, "INSECURE_COOKIES", False)
    assert config.cookie_secure() is True
    assert config.cookie_name("ls_sign") == "__Host-ls_sign"
    assert config.cookie_name("ls_env") == "__Host-ls_env"


def test_insecure_flag_drops_prefix_and_secure(monkeypatch):
    monkeypatch.setattr(config, "INSECURE_COOKIES", True)
    assert config.cookie_secure() is False
    assert config.cookie_name("ls_sign") == "ls_sign"
    assert config.cookie_name("ls_env") == "ls_env"


def test_prefix_and_secure_move_together(monkeypatch):
    """A __Host- name must never ship without Secure (browsers reject it), and vice versa."""
    monkeypatch.setattr(config, "INSECURE_COOKIES", False)
    assert config.cookie_name("x").startswith("__Host-") and config.cookie_secure()
    monkeypatch.setattr(config, "INSECURE_COOKIES", True)
    assert not config.cookie_name("x").startswith("__Host-") and not config.cookie_secure()
