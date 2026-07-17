"""Webhook delivery SSRF guard — internal/metadata addresses are refused by default.

The suite as a whole runs with ``SIGN_WEBHOOK_ALLOW_INTERNAL=true`` (conftest) so the
monkeypatched-transport delivery tests can use non-resolving example hostnames and a self-hoster
can target loopback. These tests flip the guard back *on* (the secure default) and assert that a
tenant-supplied URL pointing at loopback, private, link-local, or cloud-metadata space is rejected
at registration time — the core defense for the multi-tenant hosted tier.
"""

from __future__ import annotations

import pytest

from sign import webhooks


@pytest.fixture
def guard_on(monkeypatch):
    """Enable the SSRF guard (the production default) for one test."""
    monkeypatch.setattr(webhooks.config, "WEBHOOK_ALLOW_INTERNAL", False)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/hook",
        "http://127.0.0.1:9000/hook",
        "http://localhost/hook",
        "http://10.0.0.5/hook",
        "http://192.168.1.10/hook",
        "http://172.16.0.9/hook",
        "http://169.254.169.254/latest/meta-data/",  # AWS/GCP metadata
        "http://[::1]/hook",
        "http://0.0.0.0/hook",
    ],
)
def test_internal_urls_rejected_when_guard_on(guard_on, url):
    with pytest.raises(ValueError):
        webhooks._validate_url(url)


def test_non_http_scheme_always_rejected(guard_on):
    for url in ("file:///etc/passwd", "gopher://x/1", "ftp://host/x", "not-a-url"):
        with pytest.raises(ValueError):
            webhooks._validate_url(url)


def test_public_hostname_allowed_when_guard_on(guard_on):
    # A real, resolvable, public host passes the guard (no exception).
    assert webhooks._validate_url("https://example.com/hook") == "https://example.com/hook"


def test_guard_off_allows_loopback(monkeypatch):
    monkeypatch.setattr(webhooks.config, "WEBHOOK_ALLOW_INTERNAL", True)
    # Opt-in self-host path: loopback receiver is permitted.
    assert webhooks._validate_url("http://127.0.0.1:9000/hook") == "http://127.0.0.1:9000/hook"
