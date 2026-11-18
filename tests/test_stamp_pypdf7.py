"""pypdf 7 removed merging onto a page still owned by its reader, so stamping raised
DeprecationError ("replace_contents() for pages not assigned to a writer"). pypdf 6 only warns;
treating that warning as an error makes this fail on the old code under either version."""

import io
import warnings

import pytest
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas

from sign import pdf_stamp


def _two_pages(rotate: int) -> bytes:
    b = io.BytesIO()
    c = canvas.Canvas(b, pagesize=(612, 792))
    c.drawString(72, 720, "page one")
    c.showPage()
    c.drawString(72, 720, "page two")
    c.save()
    w = PdfWriter(clone_from=PdfReader(io.BytesIO(b.getvalue())))
    for p in w.pages:
        p.rotate(rotate)
    out = io.BytesIO()
    w.write(out)
    return out.getvalue()


@pytest.mark.parametrize("rotate", [0, 90])
def test_stamp_never_merges_onto_a_reader_owned_page(rotate):
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        out = pdf_stamp.stamp_fields(
            _two_pages(rotate),
            [{"type": "text", "page": 1, "x": 0.1, "y": 0.1, "w": 0.4, "h": 0.05, "value": "Stamped value"}],
        )
    r = PdfReader(io.BytesIO(out))
    assert len(r.pages) == 2
    assert "Stamped value" in r.pages[1].extract_text()
    assert "Stamped value" not in r.pages[0].extract_text()
    assert "page one" in r.pages[0].extract_text()
