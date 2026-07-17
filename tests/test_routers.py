"""HTTP router surface — public pages, health, signer/envelope token behavior, CSRF, hardening.

Asserts the middleware allowlist, the security headers stamped on every response, the CSRF
Origin defense on mutating API calls, and the public token surfaces' fail-closed behavior on bad
tokens.
"""

from __future__ import annotations


def test_health_endpoints_public(client):
    # /health is the back-compat liveness alias; /healthz is now owned by the meta router.
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "service": "lifted-sign"}
    # meta router: /healthz liveness, /readyz readiness, /version — all public, no auth.
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "checks": {"db": True}}
    r = client.get("/version")
    assert r.status_code == 200
    assert r.json()["name"] == "lifted-sign"


def test_security_headers_on_every_response(client):
    r = client.get("/healthz")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "content-security-policy" in r.headers


def test_landing_and_app_shells_render(client):
    for path in ("/", "/app", "/signapp", "/privacy", "/terms"):
        r = client.get(path)
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]


def test_landing_substitutes_operator_tokens(client):
    # {{OPERATOR_NAME}} / {{PUBLIC_HOST}} must be replaced, never shipped raw to the browser.
    body = client.get("/").text
    assert "{{OPERATOR_NAME}}" not in body
    assert "{{PUBLIC_BASE_URL}}" not in body


def test_methods_and_disclosure_public(client):
    assert client.get("/api/sign-portal/auth/methods").status_code == 200
    d = client.get("/api/sign/disclosure").json()
    assert d["version"].startswith("ERSD-")


def test_signer_token_bad_token_404(client):
    r = client.get("/api/sign/token/definitely-not-a-real-token")
    assert r.status_code == 404
    assert r.json()["error"] == "invalid or expired link"


def test_signer_page_shell_served(client):
    r = client.get("/sign/anytoken")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert r.headers["cache-control"].startswith("no-store")


def test_developers_docs_and_openapi(client):
    assert client.get("/developers").status_code == 200
    spec = client.get("/developers/openapi.json")
    assert spec.status_code == 200
    body = spec.json()
    assert body.get("openapi", "").startswith("3.")


def test_csrf_rejects_foreign_origin_on_mutation(client, account_factory):
    auth = account_factory()
    hdrs = dict(auth.headers)
    hdrs["origin"] = "https://evil.example.net"
    r = client.post(
        "/api/mysign/agreements",
        headers=hdrs,
        files={"file": ("x.pdf", b"%PDF-1.4", "application/pdf")},
    )
    assert r.status_code == 403
    assert r.json()["error"] == "bad origin"


def test_csrf_allows_same_origin(client, account_factory):
    from sign import config

    auth = account_factory()
    hdrs = dict(auth.headers)
    hdrs["origin"] = config.PUBLIC_BASE_URL
    # our own origin passes the CSRF gate (bad-PDF then fails validation, not CSRF)
    r = client.post(
        "/api/mysign/agreements",
        headers=hdrs,
        files={"file": ("x.pdf", b"not a pdf", "application/pdf")},
    )
    assert r.status_code == 400  # reached the handler, rejected by PDF validation not CSRF


def test_token_prefix_csrf_exempt(client):
    # public token submit carries no session + a foreign origin, yet is CSRF-exempt (token-authed)
    r = client.post(
        "/api/sign/token/badtoken/submit",
        json={"values": {}, "consent": True},
        headers={"origin": "https://someclient.example.com"},
    )
    # not a CSRF 403 — the handler runs and reports the invalid link
    assert r.status_code == 200
    assert r.json()["ok"] is False


def test_ops_console_closed_without_admin_emails(client, account_factory):
    # ADMIN_EMAILS empty by default → operator console is 403 for every signed-in account
    auth = account_factory()
    r = client.get("/api/sign-ops/accounts", headers=auth.headers)
    assert r.status_code == 403
    assert r.json()["error"] == "forbidden"


def test_bad_pdf_upload_rejected(client, account_factory):
    auth = account_factory()
    r = client.post(
        "/api/mysign/agreements",
        headers=auth.headers,
        files={"file": ("x.pdf", b"this is not a pdf", "application/pdf")},
    )
    assert r.status_code == 400
    assert r.json()["ok"] is False
