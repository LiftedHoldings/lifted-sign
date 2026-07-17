"""True, data-safe PDF redaction WITHOUT PyMuPDF/MuPDF (AGPL-free).

The e-sign engine must be able to permanently DELETE content from a page — not merely
paint over it. A drawn rectangle leaves the underlying bytes fully recoverable
(``pdfplumber``/``pypdf`` extract them; a raw byte scan finds them), which is a
data-breach-class bug for a legal signing product.

MuPDF's ``apply_redactions`` (true, content-aware character/vector removal) has no
permissive equivalent: ``pikepdf``/``qpdf`` deliberately do not offer it, and content-stream
surgery LEAKS on real-world PDFs (a secret one level down in a Form XObject survives a
page-level parser — proven, disqualified). So this module takes the only construction that
is data-safe by definition, the same one Adobe Acrobat / DocuSign-grade redaction uses:

    render the page to a raster (pypdfium2) -> paint opaque boxes on the pixels (Pillow) ->
    replace the whole page with that single flattened image (reportlab -> pypdf).

A redacted page therefore has NO text objects, NO vector operators and NO embedded image
XObjects at all: every glyph/vector/image is baked into pixels, and the box pixels
physically overwrite the secret pixels. Nothing extractable can survive on a redacted page.
Pages WITHOUT any region are passed through UNTOUCHED and keep their selectable text layer.

Permissive stack only: pypdfium2 (BSD-3/Apache-2.0, PDFium), Pillow (HPND), reportlab (BSD),
pypdf (BSD). No AGPL. Coordinates match ``pdf_edit``: normalized 0..1, origin TOP-LEFT, in
the page's VISUAL (rotation-applied) frame — pdfium renders that exact frame, so painting in
normalized coords is automatically rotation-correct with no derotation math.
"""

from __future__ import annotations

import io

import pypdfium2 as pdfium
from PIL import ImageDraw
from pypdf import PdfReader, PdfWriter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas as _rl_canvas

# Raster resolution for a redacted (flattened) page. 200 dpi keeps signed contracts crisp
# for print while bounding memory; matches the proven prototype.
_REDACT_DPI = 200

# Opaque fill per redaction kind. redact -> black bar (visible censor); whiteout -> white
# fill (blends into the page). Both fully opaque so no secret pixel shows through.
_FILL = {"redact": (0, 0, 0), "whiteout": (255, 255, 255)}


def _clamp01(v: float) -> float:
    return 0.0 if v < 0 else 1.0 if v > 1 else v


def _group_by_page(
    regions: list[dict],
) -> dict[int, list[tuple[tuple[float, float, float, float], str]]]:
    """regions -> {page_index: [((x0,y0,x1,y1) normalized 0..1 top-left, kind), ...]}.

    Malformed regions are skipped rather than aborting the pass (one bad rect must not corrupt
    the redaction of every other region). Zero-area rects are dropped."""
    out: dict[int, list[tuple[tuple[float, float, float, float], str]]] = {}
    for r in regions or []:
        try:
            pi = int(r.get("page", 0))
        except (TypeError, ValueError):
            continue
        kind = str(r.get("kind", "redact")).lower()
        if kind not in _FILL:
            kind = "redact"
        try:
            x = _clamp01(float(r.get("x", 0)))
            y = _clamp01(float(r.get("y", 0)))
            w = float(r.get("w", 0))
            h = float(r.get("h", 0))
        except (TypeError, ValueError):
            continue
        x0, y0 = x, y
        x1, y1 = _clamp01(x + w), _clamp01(y + h)
        if x1 <= x0 or y1 <= y0:
            continue  # zero / negative area
        out.setdefault(pi, []).append(((x0, y0, x1, y1), kind))
    return out


def _raster_page(page: "pdfium.PdfPage", rects, dpi: int) -> tuple["ImageDraw.Image", float, float]:
    """Render one pdfium page to RGB pixels, paint each opaque box (normalized 0..1 top-left),
    and return (PIL image, page_width_pt, page_height_pt). The returned image's pixels are the
    ONLY surviving representation of the page, with secret pixels overwritten by the boxes."""
    scale = dpi / 72.0
    pil = page.render(scale=scale).to_pil().convert("RGB")
    px_w, px_h = pil.size
    draw = ImageDraw.Draw(pil)
    for (x0, y0, x1, y1), kind in rects:
        box = [x0 * px_w, y0 * px_h, x1 * px_w, y1 * px_h]
        draw.rectangle(box, fill=_FILL[kind])
    w_pt, h_pt = page.get_size()  # rotation-applied, matches the rendered visual frame
    return pil, float(w_pt), float(h_pt)


def _image_to_page_pdf(pil, w_pt: float, h_pt: float) -> io.BytesIO:
    """Wrap a flattened PIL image as a one-page PDF (bytes) at the exact page point size, via
    reportlab. The page's only content operator is the full-bleed image — no text, no vectors."""
    buf = io.BytesIO()
    c = _rl_canvas.Canvas(buf, pagesize=(w_pt, h_pt))
    c.drawImage(ImageReader(pil), 0, 0, width=w_pt, height=h_pt)
    c.showPage()
    c.save()
    buf.seek(0)
    return buf


def redact_regions(data: bytes, regions: list[dict]) -> bytes:
    """Permanently remove content under each region and return the new PDF bytes.

    ``regions``: ``[{"page": int, "x": f, "y": f, "w": f, "h": f, "kind": "redact"|"whiteout"}]``
    with x/y/w/h NORMALIZED 0..1, origin TOP-LEFT, in the page's visual frame (same convention
    as ``pdf_edit._rect``). ``redact`` paints a black bar; ``whiteout`` paints a white fill.

    Behavior:
      * Only pages that HAVE at least one region are rasterized + replaced by a flattened image;
        every glyph/vector/image on such a page is destroyed (baked to pixels, boxes overwrite
        the secret pixels) — nothing extractable survives.
      * Pages WITHOUT any region are passed through byte-for-byte and keep their text layer.
      * Empty/no-op ``regions`` returns the input unchanged.

    Raises ``ValueError`` on unreadable input so a corrupt upload fails closed instead of
    silently returning un-redacted bytes.
    """
    if not data:
        raise ValueError("no PDF data to redact")
    by_page = _group_by_page(regions)
    if not by_page:
        return data  # nothing to remove

    try:
        reader = PdfReader(io.BytesIO(data))
    except Exception as e:  # noqa: BLE001 — any open failure = unusable input
        raise ValueError("corrupt or unreadable PDF") from e

    from .pdf_render import _RENDER_LOCK

    # PDFium is NOT re-entrant — every pdfium call in the app serializes on this ONE lock
    # (shared with pdf_render.render_page + mail_thumbs), or concurrent renders crash the worker.
    with _RENDER_LOCK:
        pdf = pdfium.PdfDocument(data)
        try:
            writer = PdfWriter()
            for i, page in enumerate(reader.pages):
                rects = by_page.get(i)
                if not rects:
                    writer.add_page(page)  # no region here — keep the page + its selectable text
                    continue
                # FAIL CLOSED: a page that HAS a redaction region but can't be rendered must NOT
                # pass through un-redacted (that would leave the secret). Abort the whole redaction.
                if not (0 <= i < len(pdf)):
                    raise ValueError(f"cannot render page {i} to redact it")
                pil, w_pt, h_pt = _raster_page(pdf[i], rects, _REDACT_DPI)
                writer.append(_image_to_page_pdf(pil, w_pt, h_pt))
            out = io.BytesIO()
            writer.write(out)
            return out.getvalue()
        finally:
            pdf.close()
