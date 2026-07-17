"""Read-only PDF rendering + inspection for the native e-sign engine — PERMISSIVE-LICENSE.

This module is the fitz/PyMuPDF-FREE replacement for the read/inspect half of
``pdf_edit.py``. It imports NO AGPL code: every capability is provided by a
permissively-licensed library —

  * ``pypdfium2``  (BSD-3 / Apache-2.0, PDFium) — page raster (``render_page``)
  * ``pikepdf``    (MPL-2.0, qpdf)              — open/count/dims/validate
  * ``pdfplumber`` (MIT, pdfminer.six)          — per-char text spans
  * ``Pillow``     (HPND/MIT-CMU)               — image validation

Coordinates match ``pdf_edit``: everything is NORMALIZED to the page — x, y, w, h
in 0..1 of the page's width/height, origin top-left — so fields align regardless
of zoom/DPI and the values are drop-in compatible with the editor + signing canvas.

Behaviour is a byte-for-byte port of the corresponding ``pdf_edit`` functions
(verified empirically against PyMuPDF): ``page_dims`` applies /Rotate so 90/270
swap w/h to match ``fitz.Page.rect``; ``render_page`` clamps the longest side to
``_MAX_RENDER_PX`` (4000) and honours /Rotate; ``validate_source`` raises the same
user-safe ``ValueError`` messages and still ALLOWS owner-password-only PDFs
(our own sealed output); ``page_text_spans`` emits the same dict shape.

THREAD-SAFETY: PDFium (pypdfium2) is NOT re-entrant. Every pdfium call in this
module is serialized behind a single module-level ``threading.Lock``
(``_PDFIUM_LOCK``) — PyMuPDF hid this for us on the public token page-image route.
pikepdf/qpdf and pdfminer/pdfplumber each work on independent objects and need no
global lock.
"""

from __future__ import annotations

import io
import logging
import threading

import pikepdf
import pypdfium2 as pdfium

_log = logging.getLogger(__name__)

# Cap the longest rendered side (px). A huge MediaBox at 144 dpi can otherwise demand a
# multi-GB pixmap and OOM-kill the container from the PUBLIC token page-image route.
# Identical value + semantics to pdf_edit._MAX_RENDER_PX.
_MAX_RENDER_PX = 4000

# PDFium is not fully re-entrant: serialize ALL pdfium access (open + render) behind one
# process-wide lock so concurrent public page-image requests can't corrupt shared state.
_PDFIUM_LOCK = threading.Lock()
# Canonical name for the single PDFium render lock. Every module that calls pdfium (render_page
# here, pdf_redact.redact_regions, mail_thumbs) imports and holds this, so all pdfium work across
# the app serializes on ONE lock — PDFium is not re-entrant and concurrent calls crash the worker.
_RENDER_LOCK = _PDFIUM_LOCK


# --------------------------------------------------------------------------------------
# pikepdf helpers: open / count / dims / validate
# --------------------------------------------------------------------------------------
def _rect_wh(box) -> tuple[float, float]:
    """(width, height) from a PDF rectangle array [llx, lly, urx, ury], order-robust."""
    x0, y0, x1, y1 = (float(v) for v in box)
    return abs(x1 - x0), abs(y1 - y0)


def _page_rotation(pg: pikepdf.Page) -> int:
    """Effective /Rotate for a page (0..270), inheritance-resolved, normalized to %360."""
    try:
        rot = int(pg.rotation)  # pikepdf resolves inherited /Rotate
    except Exception:
        try:
            rot = int(pg.obj.get("/Rotate", 0) or 0)
        except Exception:
            rot = 0
    return rot % 360


def page_count(data: bytes) -> int:
    """Number of pages in the PDF (pikepdf)."""
    with pikepdf.open(io.BytesIO(data)) as pdf:
        return len(pdf.pages)


def page_dims(data: bytes) -> list[dict[str, float]]:
    """Per-page {"w","h"} in points, ROTATION-APPLIED (90/270 swap w/h) so the result
    matches ``fitz.Page.rect``. Uses the CropBox when present (falling back to MediaBox),
    matching PyMuPDF's visible-page rectangle."""
    out: list[dict[str, float]] = []
    with pikepdf.open(io.BytesIO(data)) as pdf:
        for pg in pdf.pages:
            try:
                box = pg.cropbox  # inheritance-resolved; falls back to mediabox
            except Exception:
                box = pg.mediabox
            w, h = _rect_wh(box)
            if _page_rotation(pg) in (90, 270):
                w, h = h, w
            out.append({"w": w, "h": h})
    return out


def validate_source(data: bytes) -> None:
    """Fully open an uploaded PDF and reject anything the engine can't render/seal BEFORE a
    file or DB row is written. Encrypted-with-user-password / 0-page / corrupt PDFs otherwise
    slip past the %PDF magic-byte gate, create a black-hole envelope, then 500 on every
    downstream op. Owner-password-only PDFs (empty user pw — incl. our own sealed output)
    open fine and are ALLOWED. Raises ValueError with a user-safe message on rejection."""
    if not data or data[:4] != b"%PDF":
        raise ValueError("not a PDF")
    try:
        pdf = pikepdf.open(io.BytesIO(data))
    except pikepdf.PasswordError as e:
        # User-password-protected: qpdf can't open without the password. Owner-only
        # (empty user pw) does NOT raise here — it opens — so this is the real reject.
        raise ValueError("password-protected PDFs are not supported") from e
    except Exception as e:  # noqa: BLE001 — any other open failure = unusable upload
        raise ValueError("corrupt or unreadable PDF") from e
    try:
        if len(pdf.pages) <= 0:
            raise ValueError("PDF has no pages")
    finally:
        pdf.close()


# --------------------------------------------------------------------------------------
# pypdfium2: page -> PNG raster
# --------------------------------------------------------------------------------------
def render_page(data: bytes, page_index: int, dpi: int = 144) -> bytes:
    """Render one page to PNG bytes (pypdfium2 / PDFium).

    Clamps the longest side to ``_MAX_RENDER_PX`` (an absurd MediaBox at 144 dpi could
    otherwise allocate GBs and OOM the container), honours /Rotate (pdfium renders the
    visual frame), and clamps an out-of-range ``page_index`` to the nearest real page so a
    bad index renders a page instead of surfacing as a 500. Serialized behind the pdfium
    lock — pdfium is not re-entrant."""
    with _PDFIUM_LOCK:
        pdf = pdfium.PdfDocument(data)
        try:
            n = len(pdf)
            if n <= 0:
                raise ValueError("PDF has no pages")
            # Clamp a client-supplied (possibly out-of-range) index to a valid page.
            if page_index < 0:
                page_index = 0
            elif page_index >= n:
                page_index = n - 1
            page = pdf[page_index]
            w, h = page.get_size()  # rotation-applied (visual dims), in points
            scale = dpi / 72.0
            longest = max(w, h) * scale
            if longest > _MAX_RENDER_PX:
                scale *= _MAX_RENDER_PX / longest
            pil = page.render(scale=scale).to_pil()  # honours /Rotate by default
            buf = io.BytesIO()
            pil.save(buf, "PNG")
            return buf.getvalue()
        finally:
            pdf.close()


# --------------------------------------------------------------------------------------
# pypdfium2: background-colour sampling (for invisible in-place text replacement)
# --------------------------------------------------------------------------------------
def sample_bg_color(
    data: bytes,
    page: int,
    bbox: tuple[float, float, float, float],
    dpi: int = 150,
) -> tuple[tuple[float, float, float], float]:
    """Sample the page background just OUTSIDE a run's bbox, for cover-rect colouring.

    Rasterizes the page (pdfium, under ``_RENDER_LOCK``), reads a thin band along the top and
    bottom edges immediately outside ``bbox`` (normalized 0..1 top-left, VISUAL frame — the
    band avoids the glyph ink and the run's own neighbours), and returns
    ``((r,g,b) in 0..1, uniformity)`` where uniformity ∈ 0..1 is the fraction of band pixels
    within a tight tolerance of the median colour. A uniformity near 1.0 means a solid
    background the caller can cover with a flat vector rect invisibly; a low score means a
    textured/gradient/near-neighbour background where a flat rect would show a seam and the
    caller should escalate to a raster flatten.

    FAIL-SAFE: any error (bad page, render failure, empty band) returns ``((1,1,1), 1.0)`` —
    a white, "uniform" answer — so a sampling glitch never blocks or mis-colours an edit."""
    try:
        import statistics

        x0, y0, x1, y1 = (float(v) for v in bbox)
        with _RENDER_LOCK:
            pdf = pdfium.PdfDocument(data)
            try:
                n = len(pdf)
                if n <= 0:
                    return ((1.0, 1.0, 1.0), 1.0)
                pi = 0 if page < 0 else (n - 1 if page >= n else int(page))
                pg = pdf[pi]
                w, h = pg.get_size()
                scale = dpi / 72.0
                longest = max(w, h) * scale
                if longest > _MAX_RENDER_PX:
                    scale *= _MAX_RENDER_PX / longest
                pil = pg.render(scale=scale).to_pil().convert("RGB")
            finally:
                pdf.close()
        W, H = pil.size
        if W <= 0 or H <= 0:
            return ((1.0, 1.0, 1.0), 1.0)
        px = pil.load()
        m = max(2, int(0.006 * max(W, H)))  # band thickness ~ a few px
        bx0, by0 = int(x0 * W), int(y0 * H)
        bx1, by1 = int(x1 * W), int(y1 * H)
        samples: list[tuple[int, int, int]] = []
        for xx in range(max(0, bx0 - m), min(W, bx1 + m)):
            for yy in (by0 - m, by1 + m - 1):  # a hair above the top and below the bottom edge
                if 0 <= yy < H:
                    samples.append(px[xx, yy])
        if not samples:
            return ((1.0, 1.0, 1.0), 1.0)
        med = tuple(statistics.median(c[i] for c in samples) for i in range(3))
        tol = 18
        uni = sum(1 for c in samples if all(abs(c[i] - med[i]) <= tol for i in range(3))) / len(
            samples
        )
        return (tuple(v / 255.0 for v in med), uni)
    except Exception:  # noqa: BLE001 — fail safe to solid white so sampling never blocks an edit
        return ((1.0, 1.0, 1.0), 1.0)


# --------------------------------------------------------------------------------------
# Pillow: image validation
# --------------------------------------------------------------------------------------
def is_valid_image(data: bytes | None) -> bool:
    """True if ``data`` is an image the seal can actually place (real PNG/JPEG/etc.).

    Mirrors what ``pdf_edit.stamp_fields`` places via ``insert_image`` — a signature that
    merely base64-DECODES (e.g. a crafted "AAAA") but is not a real image must be rejected,
    otherwise the seal swallows the insert error and stamps a blank 'completed' record. Gate
    on decodable-as-an-image, not on decodable-as-bytes."""
    if not data:
        return False
    try:
        from PIL import Image

        Image.open(io.BytesIO(data)).verify()
        return True
    except Exception:  # noqa: BLE001 — any decode failure = not a placeable image
        return False


# --------------------------------------------------------------------------------------
# pdfplumber: existing text as editable spans
# --------------------------------------------------------------------------------------
def _color_hex(c) -> str:
    """A pdfplumber ``non_stroking_color`` -> "#rrggbb". Accepts None (black default),
    a scalar/1-tuple gray, a 3-tuple RGB, or a 4-tuple CMYK, values in 0..1 (or 0..255)."""
    if c is None:
        return "#000000"
    if isinstance(c, (int, float)):
        c = (c,)
    if not isinstance(c, (list, tuple)) or not c:
        return "#000000"

    def _to255(v: float) -> int:
        f = float(v)
        if f <= 1.0:  # 0..1 float component (pdfminer's usual form)
            f *= 255.0
        return max(0, min(255, int(round(f))))

    try:
        if len(c) == 1:
            g = _to255(c[0])
            r = gg = b = g
        elif len(c) == 3:
            r, gg, b = (_to255(v) for v in c)
        elif len(c) == 4:
            cc, m, y, k = (float(v) for v in c)
            r = _to255((1 - cc) * (1 - k))
            gg = _to255((1 - m) * (1 - k))
            b = _to255((1 - y) * (1 - k))
        else:
            r = gg = b = _to255(c[0])
    except Exception:
        return "#000000"
    return "#%02x%02x%02x" % (r, gg, b)


def _char_baseline_top(ch: dict, page_h: float) -> float:
    """Text baseline y for a char in TOP-LEFT origin points.

    pdfminer's text matrix translation ``matrix[5]`` (== f == ty) is the glyph origin,
    which sits on the baseline in bottom-left PDF coords; convert to top-left. Falls back to
    the char's bottom edge if the matrix is unavailable."""
    m = ch.get("matrix")
    if m and len(m) >= 6:
        try:
            return page_h - float(m[5])
        except Exception:
            pass
    return float(ch.get("bottom", 0.0))


def page_text_spans(data: bytes, page_index: int) -> list[dict]:
    """Existing text on a page as editable spans — normalized bbox + font/size/color — so
    the editor can offer click-to-edit-in-place with font matching (pdfplumber).

    Emits the same dict shape as ``pdf_edit.page_text_spans``:
    ``{text, x, y, w, h, oy, size, font, flags, color}`` with x/y/w/h/oy normalized 0..1
    top-left. pdfplumber ``top``/``bottom`` are already top-left origin. ``flags`` is 0 —
    pdfminer doesn't expose the bold/italic bitmask; ``pdf_edit._match_font`` recovers
    serif/mono/bold/italic from the font NAME, so no fidelity is lost beyond that bit.
    Chars are grouped into spans by line + font + size + color (contiguous reading order)."""
    import pdfplumber

    out: list[dict] = []
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        if page_index < 0 or page_index >= len(pdf.pages):
            return []
        page = pdf.pages[page_index]
        W = float(page.width) or 1.0
        H = float(page.height) or 1.0
        chars = page.chars or []

        cur: dict | None = None

        def _flush() -> None:
            nonlocal cur
            if cur is None:
                return
            txt = cur["text"]
            if txt.strip():
                x0, y0, x1, y1 = cur["x0"], cur["top"], cur["x1"], cur["bottom"]
                out.append(
                    {
                        "text": txt,
                        "x": x0 / W,
                        "y": y0 / H,
                        "w": (x1 - x0) / W,
                        "h": (y1 - y0) / H,
                        "oy": cur["oy"] / H,
                        "size": round(cur["size"], 1),
                        "font": cur["font"],
                        "flags": 0,
                        "color": cur["color"],
                    }
                )
            cur = None

        for ch in chars:
            font = ch.get("fontname", "") or ""
            size = round(float(ch.get("size", 11) or 11), 1)
            color = _color_hex(ch.get("non_stroking_color"))
            top = float(ch.get("top", 0.0))
            bottom = float(ch.get("bottom", 0.0))
            x0 = float(ch.get("x0", 0.0))
            x1 = float(ch.get("x1", 0.0))
            text = ch.get("text", "") or ""
            # Start a new span on a line break, font/size/color change, or a leftward
            # jump (new column) — matching how fitz breaks a line into spans.
            newline = cur is not None and abs(top - cur["top"]) > max(1.0, cur["size"] * 0.3)
            style = cur is not None and (
                font != cur["font"] or size != cur["size"] or color != cur["color"]
            )
            backjump = cur is not None and x0 < cur["x1"] - max(1.0, cur["size"])
            if cur is None or newline or style or backjump:
                _flush()
                cur = {
                    "text": text,
                    "x0": x0,
                    "x1": x1,
                    "top": top,
                    "bottom": bottom,
                    "size": size,
                    "font": font,
                    "color": color,
                    "oy": _char_baseline_top(ch, H),
                }
            else:
                cur["text"] += text
                cur["x1"] = max(cur["x1"], x1)
                cur["x0"] = min(cur["x0"], x0)
                cur["top"] = min(cur["top"], top)
                cur["bottom"] = max(cur["bottom"], bottom)
        _flush()
    return out
