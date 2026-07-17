"""``/developers`` — the public developer API reference.

* ``GET /developers`` (and ``/developers/``) — the rendered docs page (web/developers.html), which
  loads the OpenAPI spec below plus the vendored Scalar viewer, Postman collection, SDK, and the
  step-by-step guides. All of those assets are served by the ``/static`` mount
  (``/static/ds/vendor/...``), so no per-file passthrough route is required.
* ``GET /developers/openapi.json`` — the OpenAPI 3.1 spec as JSON (single source of truth for
  tooling/codegen), transcoded from the vendored YAML.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from .. import config
from ..http_helpers import WEB_DIR

router = APIRouter()

_DOCS_HEADERS = {
    "Cache-Control": "no-store, must-revalidate",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

# The vendored OpenAPI spec lives alongside the rest of the developer assets under the web root.
_OPENAPI_YAML = WEB_DIR / "ds" / "vendor" / "openapi.yaml"


@router.get("/developers")
@router.get("/developers/")
async def developers_docs() -> HTMLResponse:
    """Public developer API reference (web/developers.html renders the inlined OpenAPI spec).

    Served through the same operator/base-URL token substitution as the marketing shells
    (see app._page): the page carries ``{{PUBLIC_BASE_URL}}`` / ``{{PUBLIC_HOST}}`` /
    ``{{OPERATOR_NAME}}`` / ``{{OPERATOR_URL}}`` so canonical/OG URLs, the curl/SDK snippets, and
    the footer resolve to THIS install — never a hardcoded ``example.com`` / ``[Operator Name]``.
    Substitution is a plain str.replace of the fixed token set, so a page with no tokens is
    served verbatim.
    """
    try:
        html = (WEB_DIR / "developers.html").read_text(encoding="utf-8")
    except OSError:
        return PlainTextResponse("Not found", status_code=404)
    for token, value in config.page_tokens().items():
        if token in html:
            html = html.replace(token, value)
    return HTMLResponse(html, headers=_DOCS_HEADERS)


@router.get("/developers/openapi.json")
async def developers_openapi() -> Any:
    """The Lifted Sign OpenAPI 3.1 spec as JSON (single source of truth for tooling/codegen)."""
    import json as _json

    import yaml as _yaml

    try:
        spec = _yaml.safe_load(_OPENAPI_YAML.read_text(encoding="utf-8"))
    except Exception:
        return JSONResponse({"error": "spec unavailable"}, status_code=503)
    return Response(
        _json.dumps(spec),
        media_type="application/json",
        headers={"Cache-Control": "public, max-age=300", "Access-Control-Allow-Origin": "*"},
    )
