"""Low-level PDF engine units — page algebra (``pdf_ops``) and rendering/inspection (``pdf_render``).

These permissive-licensed modules back every editor operation; exercised directly here on real
reportlab PDFs so merge/split/extract/reorder/rotate/delete/scrub/encrypt and render/dims/validate
are covered without routing through the whole agreement flow.
"""

from __future__ import annotations

import io

import pytest


def _pdf(text="Page", pages=1):
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    for i in range(pages):
        c.drawString(72, 720, f"{text} {i}")
        c.showPage()
    c.save()
    return buf.getvalue()


def test_page_count_and_validate_index():
    from sign import pdf_ops

    data = _pdf(pages=3)
    assert pdf_ops.page_count(data) == 3
    with pytest.raises(ValueError):
        pdf_ops._open(b"")
    with pytest.raises(IndexError):
        pdf_ops._validate_index(9, 3)
    with pytest.raises(ValueError):
        pdf_ops._validate_index("x", 3)


def test_merge_split_extract():
    from sign import pdf_ops

    a, b = _pdf("A", 1), _pdf("B", 2)
    merged = pdf_ops.merge([a, b])
    assert pdf_ops.page_count(merged) == 3
    parts = pdf_ops.split(merged)
    assert len(parts) == 3 and all(pdf_ops.page_count(p) == 1 for p in parts)
    ext = pdf_ops.extract_pages(merged, [(0, 1)])
    assert pdf_ops.page_count(ext) == 2


def test_reorder_rotate_delete():
    from sign import pdf_ops

    data = _pdf(pages=3)
    assert pdf_ops.page_count(pdf_ops.reorder_pages(data, [2, 1, 0])) == 3
    assert pdf_ops.page_count(pdf_ops.rotate_pages(data, {0: 90, 1: 180})) == 3
    assert pdf_ops.page_count(pdf_ops.delete_pages(data, [1])) == 2


def test_scrub_and_encrypt():
    from sign import pdf_ops

    data = _pdf(pages=1)
    scrubbed = pdf_ops.scrub_metadata(data)
    assert scrubbed[:5] == b"%PDF-"
    enc = pdf_ops.encrypt(data, owner_pw="owner", user_pw="", aes=256)
    assert enc[:5] == b"%PDF-"
    # the encrypted output is a different byte stream than the source
    assert enc != data


def test_pdf_render_dims_and_validate():
    from sign import pdf_render

    data = _pdf(pages=2)
    assert pdf_render.page_count(data) == 2
    dims = pdf_render.page_dims(data)
    assert len(dims) == 2 and dims[0]["w"] > 0 and dims[0]["h"] > 0
    # validate_source accepts a real PDF, rejects junk
    pdf_render.validate_source(data)
    with pytest.raises(ValueError):
        pdf_render.validate_source(b"not a pdf")


def test_pdf_render_page_to_png():
    from sign import pdf_render

    png = pdf_render.render_page(_pdf(pages=1), 0, dpi=72)
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    # a second page renders too (multi-page path)
    two = pdf_render.render_page(_pdf(pages=2), 1, dpi=72)
    assert two[:8] == b"\x89PNG\r\n\x1a\n"


def test_is_valid_image_gate():
    from PIL import Image

    from sign import pdf_render

    buf = io.BytesIO()
    Image.new("RGBA", (10, 10), (0, 0, 0, 255)).save(buf, "PNG")
    assert pdf_render.is_valid_image(buf.getvalue()) is True
    assert pdf_render.is_valid_image(b"nope") is False
    assert pdf_render.is_valid_image(None) is False
