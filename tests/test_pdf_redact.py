"""True content redaction (``sign.pdf_redact``) — text under the box is destroyed."""

from __future__ import annotations

import io

import pytest


def _pdf_with_secret(secret: str = "TOPSECRETVALUE") -> bytes:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(72, 720, "Header visible")
    c.drawString(72, 700, secret)
    c.drawString(72, 680, "Footer visible")
    c.showPage()
    c.save()
    return buf.getvalue()


def _extract_text(data: bytes) -> str:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    return "\n".join((page.extract_text() or "") for page in reader.pages)


def test_redact_regions_removes_secret_text_from_extractable_content():
    from sign import pdf_redact

    secret = "TOPSECRETVALUE"
    src = _pdf_with_secret(secret)
    assert secret in _extract_text(src)

    out = pdf_redact.redact_regions(
        src,
        [{"page": 0, "x": 0.05, "y": 0.08, "w": 0.9, "h": 0.08, "kind": "redact"}],
    )
    # Flattened redacted page has no extractable text objects for the secret.
    extracted = _extract_text(out)
    assert secret not in extracted
    assert out.startswith(b"%PDF")
    assert len(out) > 500


def test_redact_regions_noop_when_no_regions():
    from sign import pdf_redact

    src = _pdf_with_secret()
    out = pdf_redact.redact_regions(src, [])
    assert out == src


def test_redact_regions_empty_data_raises():
    from sign import pdf_redact

    with pytest.raises(ValueError, match="no PDF data"):
        pdf_redact.redact_regions(b"", [{"page": 0, "x": 0, "y": 0, "w": 0.5, "h": 0.5}])
