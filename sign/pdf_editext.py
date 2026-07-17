"""In-place text replacement ("edit existing text") for Lifted Sign — PERMISSIVE only.

This is the orchestrator for editing existing text on an uploaded PDF. It is SERVER-
AUTHORITATIVE: the caller supplies only ``{page, bbox, new text}``; this module RE-EXTRACTS
the original run's exact bbox, font, size, colour and baseline from the pristine PDF with
pdfplumber (never trusting a client for styling), samples the local background colour, and
then draws a vector cover+redraw via :func:`server.pdf_stamp.replace_runs` — keeping the rest
of the page vector and selectable.

Backgrounds that are not solid (uniformity < ``_UNIFORM_MIN``) escalate that page to a raster
flatten so the cover blends into the pixels instead of showing a seam; the send/seal path
flattens every edited page anyway, closing the vector-cover remanence for the legal artifact.

Runs that can't be reproduced identically are REFUSED with a typed :class:`EditError` whose
``code`` maps to the frontend contract: ``rotated`` (non-identity text matrix — skew/rotation),
``no_run`` (no extractable text under the bbox — e.g. a scanned/image area), ``too_long`` (the
replacement can't fit the run box even shrink-to-fit within reason), ``empty`` (blank text) and
``unsupported:<chars>`` (glyphs no available font covers — enforced upstream in esign).

Permissive stack only: pdfplumber (MIT), pypdf (BSD), pypdfium2 (BSD/Apache), Pillow (HPND),
reportlab (BSD) via pdf_stamp/pdf_redact. No PyMuPDF/AGPL, no Adobe.
"""

from __future__ import annotations

import io

from pypdf import PdfReader, PdfWriter

from . import fontmap, pdf_render, pdf_stamp

# A run whose background is at least this uniform is covered with a flat vector rect
# (invisible, page stays vector); below it, the page is escalated to a raster flatten.
_UNIFORM_MIN = 0.85
# Shrink-to-fit floor for the too_long check: we allow the redraw to shrink to this fraction
# of the original size, but no further — below that the replacement reads visibly smaller than
# its neighbours, so we refuse it instead.
_SHRINK_FLOOR = 0.75
_WIDTH_TOL_PT = 1.0  # slack (pt) absorbing metric rounding on the width fit


class EditError(Exception):
    """A per-item refusal whose ``code`` is one of the frontend contract error codes
    (rotated / no_run / too_long / empty / unsupported:...). ``item`` is the 0-based index of
    the offending edit in the batch (filled in by :func:`replace_runs` when known)."""

    def __init__(self, code: str, item: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.item = item


def _extract_run(data: bytes, page_index: int, bbox) -> dict:
    """Re-extract the ORIGINAL run under ``bbox`` (normalized 0..1 top-left, [x0,y0,x1,y1]) with
    pdfplumber so the server never trusts the client's font/size/colour/baseline.

    Returns ``{x0,y0,x1,y1 (norm TL), baseline (norm TL), orig_font, size, color(#rrggbb),
    text, pw, ph}``. Raises :class:`EditError`:
      * ``no_run`` — the bbox is off-page or covers no extractable characters.
      * ``rotated`` — any char under the bbox has a non-identity text matrix (rotation / skew /
        mirror). We refuse rather than mis-place the redraw; deferred to a later CTM-aware pass."""
    import pdfplumber

    x0n, y0n, x1n, y1n = (float(v) for v in bbox)
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        if page_index < 0 or page_index >= len(pdf.pages):
            raise EditError("no_run")
        pg = pdf.pages[page_index]
        W = float(pg.width) or 1.0
        H = float(pg.height) or 1.0
        px0, py0, px1, py1 = x0n * W, y0n * H, x1n * W, y1n * H
        hits = [
            c
            for c in (pg.chars or [])
            if px0 - 1 <= (c["x0"] + c["x1"]) / 2 <= px1 + 1
            and py0 - 1 <= (c["top"] + c["bottom"]) / 2 <= py1 + 1
        ]
        if not hits:
            raise EditError("no_run")
        # Refuse rotated / skewed / mirrored runs: for upright, unscaled-direction text the text
        # matrix has b≈c≈0 and a,d>0. pdfminer bakes the font size into a/d, so we test the
        # DIRECTION (off-diagonal magnitude relative to scale), not the raw values.
        for c in hits:
            m = c.get("matrix")
            if m and len(m) >= 4:
                a, b, cc, d = (float(m[k]) for k in range(4))
                scale = max(abs(a), abs(b), abs(cc), abs(d)) or 1.0
                if abs(b) / scale > 1e-3 or abs(cc) / scale > 1e-3 or a <= 0 or d <= 0:
                    raise EditError("rotated")
        hits.sort(key=lambda c: c["x0"])
        first = hits[0]
        rx0 = min(c["x0"] for c in hits)
        rx1 = max(c["x1"] for c in hits)
        rtop = min(c["top"] for c in hits)
        rbot = max(c["bottom"] for c in hits)
        m = first.get("matrix")
        # baseline = text-matrix ty in top-left points (same derivation as _char_baseline_top)
        base = (H - float(m[5])) if (m and len(m) >= 6) else rbot
        return {
            "x0": rx0 / W,
            "y0": rtop / H,
            "x1": rx1 / W,
            "y1": rbot / H,
            "baseline": base / H,
            "orig_font": first.get("fontname", "") or "",
            "size": round(float(first.get("size", 11) or 11), 1),
            "color": pdf_render._color_hex(first.get("non_stroking_color")),
            "text": "".join(c["text"] for c in hits),
            "pw": W,
            "ph": H,
        }


def flatten_pages(data: bytes, pages) -> bytes:
    """Rasterize each page index in ``pages`` to a flattened 200-dpi image (reusing the proven
    pdf_redact rasterizer) and pass every other page through byte-for-byte. Used both by the bg
    escalation and by the send-time integrity flatten: after a cover+redraw, rasterizing the
    edited page bakes the (already covered) old glyphs into pixels and destroys the extractable
    text layer, so the sent PDF's visible text == its extracted text. Serialized on the shared
    pdfium lock."""
    want = {int(p) for p in (pages or [])}
    if not want:
        return data
    import pypdfium2 as pdfium

    from . import pdf_redact
    from .pdf_render import _RENDER_LOCK

    reader = PdfReader(io.BytesIO(data))
    with _RENDER_LOCK:
        pdf = pdfium.PdfDocument(data)
        try:
            writer = PdfWriter()
            for i, page in enumerate(reader.pages):
                if i in want and 0 <= i < len(pdf):
                    # rects=[] -> render the page to an image with no boxes painted; the cover
                    # rect drawn earlier is already part of what pdfium renders.
                    pil, w_pt, h_pt = pdf_redact._raster_page(pdf[i], [], pdf_redact._REDACT_DPI)
                    writer.append(pdf_redact._image_to_page_pdf(pil, w_pt, h_pt))
                else:
                    writer.add_page(page)
            out = io.BytesIO()
            writer.write(out)
            return out.getvalue()
        finally:
            pdf.close()


def replace_runs(data: bytes, edits: list[dict]) -> bytes:
    """Replace existing text runs in place and return the new PDF bytes.

    ``edits``: ``[{page, bbox:[x0,y0,x1,y1] (norm TL), text (NEW), size?, color?, idx?}]``.
    Per edit the server re-extracts the original run, samples the background, checks the fit,
    and collects a resolved run for the vector cover+redraw. Any page whose sampled background
    is not solid (uniformity < ``_UNIFORM_MIN``) is escalated to a raster flatten so the cover
    blends in. Raises :class:`EditError` (with the item index) on the first refusable edit —
    fail-closed, so nothing is written when any edit can't be reproduced identically."""
    runs: list[dict] = []
    flatten: set[int] = set()
    for e in edits or []:
        idx = e.get("idx")
        try:
            pi = int(e["page"])
            bbox = e["bbox"]
            text = str(e.get("text", ""))
            if not text.strip():
                raise EditError("empty")
            orig = _extract_run(data, pi, bbox)
            bg, uni = pdf_render.sample_bg_color(
                data, pi, (orig["x0"], orig["y0"], orig["x1"], orig["y1"])
            )
            size = float(e.get("size") or orig["size"])
            # too_long: measure the NEW text in the width-matched clone; if it overflows the run
            # box even after shrinking to the floor, refuse rather than collide with neighbours.
            buf, _fam, _metric = fontmap.resolve(orig["orig_font"], 0, text)
            box_w_pt = (orig["x1"] - orig["x0"]) * orig["pw"]
            if buf:
                w = fontmap.text_width(buf, text, size * _SHRINK_FLOOR)
            else:
                # fontmap couldn't resolve a clone (non-latin / unknown face) → the draw path uses
                # a base-14 fallback, so measure with base-14 rather than skip the guard (else an
                # overlong non-latin replacement would draw below the shrink floor and overflow).
                from reportlab.pdfbase.pdfmetrics import stringWidth

                w = stringWidth(text, "Helvetica", size * _SHRINK_FLOOR)
            if w > box_w_pt + _WIDTH_TOL_PT:
                raise EditError("too_long")
            runs.append(
                {
                    "page": pi,
                    "x0": orig["x0"],
                    "y0": orig["y0"],
                    "x1": orig["x1"],
                    "y1": orig["y1"],
                    "baseline": orig["baseline"],
                    "text": text,
                    "orig_font": orig["orig_font"],
                    "flags": 0,
                    "size": size,
                    "color": e.get("color") or orig["color"],
                    "bg": bg,
                }
            )
            if uni < _UNIFORM_MIN:
                flatten.add(pi)
        except EditError as ex:
            if ex.item is None:
                ex.item = idx
            raise

    out = pdf_stamp.replace_runs(data, runs)
    if flatten:
        out = flatten_pages(out, flatten)
    return out
