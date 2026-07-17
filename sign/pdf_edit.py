"""Lifted Sign PDF engine — thin facade over the permissive modules.

This module used to be the fitz (PyMuPDF, AGPL) implementation. It is now a delegation
facade: every capability is provided by permissive-licensed modules and this file imports
NO AGPL code. The public API is unchanged, so every caller (esign.py, app.py, tests) keeps
working:

- render / inspect  -> server.pdf_render  (pypdfium2 BSD, pikepdf MPL, pdfplumber MIT, Pillow HPND)
- stamp / add-text  -> server.pdf_stamp   (reportlab BSD, pypdf BSD, fontTools MIT)
- redaction         -> server.pdf_redact  (pypdfium2 + Pillow + reportlab + pypdf — rasterize)
- certificate/seal  -> server.pdf_cert    (reportlab + pikepdf + pypdf)

Coordinates everywhere are NORMALIZED 0..1, origin top-left, in the page's visual (rotated)
frame — the same convention the SPA editor and the field model use.
"""

from __future__ import annotations

import hashlib
import logging

from . import pdf_cert, pdf_editext, pdf_redact, pdf_render, pdf_stamp

log = logging.getLogger(__name__)

# ---- render / inspection (pdf_render) --------------------------------------------------
_MAX_RENDER_PX = pdf_render._MAX_RENDER_PX
page_count = pdf_render.page_count
page_dims = pdf_render.page_dims
validate_source = pdf_render.validate_source
render_page = pdf_render.render_page
is_valid_image = pdf_render.is_valid_image
page_text_spans = pdf_render.page_text_spans

# ---- stamping / add-text (pdf_stamp) ---------------------------------------------------
stamp_fields = pdf_stamp.stamp_fields
unsupported_chars = pdf_stamp.unsupported_chars

# ---- in-place text replacement / edit-existing-text (pdf_editext) ----------------------
replace_runs = pdf_editext.replace_runs
flatten_pages = pdf_editext.flatten_pages
EditError = pdf_editext.EditError

# ---- certificate + seal post-ops (pdf_cert) --------------------------------------------
sha256 = pdf_cert.sha256
make_certificate = pdf_cert.make_certificate
sanitize_pdf = pdf_cert.sanitize_pdf
secure_pdf = pdf_cert.secure_pdf
append_pdf = pdf_cert.append_pdf


# ---- pure helpers kept for external callers (fitz-free) --------------------------------
_CHECK_TRUE = {"1", "true", "yes", "on", "x", "checked", "✓"}


def _png_from_data_url(s: str) -> bytes | None:
    """Decode the base64 payload of a data-URL (or a bare base64 string). Used by esign to
    pull the stored signature bytes before validating them with is_valid_image."""
    if not s:
        return None
    if s.startswith("data:"):
        s = s.split(",", 1)[-1]
    try:
        import base64

        return base64.b64decode(s)
    except Exception:
        return None


def _is_checked(v) -> bool:
    """Truthy test for a checkbox field value — tolerant of strings, ints and bools."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    return str(v or "").strip().lower() in _CHECK_TRUE


def _font_alias(prefix: str, key: str) -> str:
    """Deterministic, effectively collision-free PDF font alias for `key`. Stable SHA-1 digest
    (NOT Python's per-process-salted hash()) so the same font maps to the same alias every run."""
    return prefix + hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


# ---- apply_edits orchestrator (text + redact/whiteout) ---------------------------------
def apply_edits(data: bytes, edits: list[dict]) -> bytes:
    """Apply author edits to a PDF and return the new bytes.

    Supported kinds:
      {kind:'text',     page, x, y, text, size?, color?, font?}  -> add author text (pdf_stamp)
      {kind:'whiteout', page, x, y, w, h}                        -> TRUE remove, white fill
      {kind:'redact',   page, x, y, w, h}                        -> TRUE remove, black bar

    Redactions are applied FIRST (each redacted page is rasterized + flattened so nothing
    extractable survives — safe even when a secret hides in a Form XObject), then author text
    is stamped ON TOP, matching the legacy ordering (added text survives redaction). Unknown
    kinds (e.g. the retired 'edittext') are ignored. add-text preserves its fail-closed
    off-page guard: it raises ValueError when a block runs past the page bottom, so the caller
    returns a 400 and writes nothing rather than silently dropping lines.
    """
    edits = edits or []
    regions = [e for e in edits if e.get("kind") in ("redact", "whiteout")]
    texts = [e for e in edits if e.get("kind", "text") == "text"]
    out = data
    if regions:
        out = pdf_redact.redact_regions(out, regions)
    if texts:
        out = pdf_stamp.add_text(out, texts)  # may raise ValueError (off-page) — propagate
    return out
