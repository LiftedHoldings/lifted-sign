"""Permissive PDF stamping engine for the native e-sign system (NO PyMuPDF / MuPDF).

This module burns completed field values and author-added text onto a working PDF using
only permissively-licensed libraries — reportlab (BSD) to author an overlay page, pypdf
(BSD) to merge it, Pillow (HPND) for image validation, and fontTools (MIT) for glyph
coverage. It replaces the AGPL ``fitz`` path in :mod:`server.pdf_edit` for the stamp/add-text
surface; ``pdf_edit`` delegates to :func:`stamp_fields`, :func:`add_text`,
:func:`unsupported_chars` and :func:`is_valid_image` here.

Coordinate system (identical to the fitz engine): every field/item carries NORMALIZED
x, y, w, h in 0..1 of the page's width/height with a TOP-LEFT origin, expressed in the
*visual* (rotation-applied) frame the signer sees in the editor. Rotation is handled by
authoring the overlay in that visual frame and merging it through the page's rotation CTM
via ``pypdf.PageObject.merge_transformed_page`` — NOT by derotating each field. This lands
stamps at the same visual spot on /Rotate 0/90/180/270 and keeps text upright.

Fonts: Latin-1-encodable text renders in a base-14 family (Helvetica/Times/Courier, zero
embed cost). Anything else embeds a subset of the vendored Droid Sans Fallback (Apache-2.0,
the same face MuPDF ships as ``fitz.Font("cjk")`` — Latin/Latin-ext/Cyrillic/Greek/CJK, NOT
Arabic/Hebrew/Thai/Indic/emoji). reportlab auto-subsets the TTF on embed.
"""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import pathlib as _pl

from fontTools.ttLib import TTFont as _FTFont
from PIL import Image
from pypdf import PdfReader, PdfWriter
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfbase.ttfonts import TTFont as _RLTTFont
from reportlab.pdfgen import canvas as _rl_canvas

from . import fontmap

_log = logging.getLogger(__name__)

# --- vendored universal fallback face (replaces fitz.Font("cjk")) -------------------------
_FONT_DIR = _pl.Path(__file__).parent / "assets" / "fonts"
_UFONT_PATH = _FONT_DIR / "DroidSansFallback.ttf"
_UFONT_NAME = "LSFallback"  # reportlab registration alias (stable, process-wide)
_ufont_registered = False
_ufont_cmap: frozenset[int] | None = None


def _ensure_ufont() -> bool:
    """Register the vendored fallback TTF with reportlab (once) and cache its cmap.

    Returns True when the face is available. reportlab subsets the embedded font to the
    glyphs actually drawn, so registering it globally costs nothing until it is used."""
    global _ufont_registered, _ufont_cmap
    if _ufont_cmap is not None:
        return _ufont_registered
    try:
        _ufont_cmap = frozenset(_FTFont(str(_UFONT_PATH)).getBestCmap().keys())
    except Exception:  # noqa: BLE001 — font asset missing/corrupt → non-latin text unsupported
        _log.warning("pdf_stamp: vendored fallback font not usable (%s)", _UFONT_PATH)
        _ufont_cmap = frozenset()
        _ufont_registered = False
        return False
    try:
        if not _ufont_registered:
            pdfmetrics.registerFont(_RLTTFont(_UFONT_NAME, str(_UFONT_PATH)))
            _ufont_registered = True
    except Exception:  # noqa: BLE001
        _log.warning("pdf_stamp: could not register fallback font with reportlab")
        _ufont_registered = False
    return _ufont_registered


# --- fonts -------------------------------------------------------------------------------
# Base-14 family aliases mapped to reportlab's standard PostScript names.
_B14: dict[tuple[str, bool, bool], str] = {
    ("sans", False, False): "Helvetica",
    ("sans", True, False): "Helvetica-Bold",
    ("sans", False, True): "Helvetica-Oblique",
    ("sans", True, True): "Helvetica-BoldOblique",
    ("serif", False, False): "Times-Roman",
    ("serif", True, False): "Times-Bold",
    ("serif", False, True): "Times-Italic",
    ("serif", True, True): "Times-BoldItalic",
    ("mono", False, False): "Courier",
    ("mono", True, False): "Courier-Bold",
    ("mono", False, True): "Courier-Oblique",
    ("mono", True, True): "Courier-BoldOblique",
}
_ADDTEXT_FAMILY = {"sans": "sans", "serif": "serif", "mono": "mono"}

_CHECK_TRUE = {"1", "true", "yes", "on", "x", "checked", "✓"}
_ACCENT = (0.106, 0.329, 0.78)  # rich electric blue #1B54C7 — the affirmative check colour


def _latin1(text: str) -> bool:
    """True when a base-14 family can render `text`. Gate on latin-1 ENCODABILITY (the real
    base-14 boundary) — has_glyph-style checks falsely report Cyrillic as covered."""
    try:
        text.encode("latin-1")
        return True
    except UnicodeEncodeError:
        return False


def _font_for(text: str, family: str = "sans", bold: bool = False, italic: bool = False) -> str:
    """Resolve a reportlab font name for `text`: a base-14 family face when the text is
    latin-1, else the vendored fallback (which also covers latin, so mixed strings render in
    one face with no tofu). Falls back to base-14 if the fallback face is unavailable."""
    if _latin1(text):
        return _B14[(family if family in ("sans", "serif", "mono") else "sans", bold, italic)]
    if _ensure_ufont():
        return _UFONT_NAME
    return _B14[("sans", bold, italic)]


# --- run-font bridge: fontmap metric-clone -> reportlab face (for edit-in-place) ---------
# Cache of registered substitute faces, keyed by a STABLE style key (family+bold+italic), so
# the same clone face is registered with reportlab exactly once per process.
_reg_faces: dict[str, str] = {}
_BOLD_WORDS = ("bold", "black", "heavy", "semibold", "demibold", "demi")
_ITALIC_WORDS = ("italic", "oblique")
# clone family key -> base-14 class, for the last-resort ladder when the TTF can't be registered
_CLASS_OF = {
    "tinos": "serif",
    "caladea": "serif",
    "gelasio": "serif",
    "merriweather": "serif",
    "ptserif": "serif",
    "cousine": "mono",
    "jbmono": "mono",
}


def _register_face(buf: bytes, key: str) -> str:
    """Register one substitute-font buffer with reportlab (once) under a stable alias derived
    from `key`, and return the alias for ``pen.text``. `key` MUST encode family+weight+style
    (e.g. "carlito-10") so bold never collides with regular. reportlab auto-subsets on embed."""
    alias = _reg_faces.get(key)
    if alias is None:
        alias = "LSrun_" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]
        pdfmetrics.registerFont(_RLTTFont(alias, io.BytesIO(buf)))
        _reg_faces[key] = alias
    return alias


def font_for_run(
    name: str,
    size: float,
    text: str = "",
    bold: bool | None = None,
    italic: bool | None = None,
    flags: int = 0,
) -> str:
    """Best reportlab font NAME to REDRAW a run that was originally set in font `name`.

    Bridges :func:`fontmap.resolve` (metric-clone match — Arial→Arimo, Times→Tinos,
    Calibri→Carlito, Courier→Cousine, Cambria→Caladea, Georgia→Gelasio; subset prefix
    stripped, bold/italic recovered from the name) to a reportlab-registered face via
    :func:`_register_face`. Non-latin-1 text keeps the existing Droid CJK fallback (the clones
    are latin-only). If the clone can't be resolved/registered, falls back to the base-14
    family of the right serif/sans/mono class via :func:`_font_for`."""
    b = bool(bold) if bold is not None else False
    i = bool(italic) if italic is not None else False
    if not _latin1(text):
        # clones are latin-only; keep the universal CJK/Cyrillic fallback face
        return _UFONT_NAME if _ensure_ufont() else _font_for(text, "sans", bold=b, italic=i)
    # Fold explicit style hints into the flag bits fontmap.resolve reads (16=bold, 2=italic);
    # resolve ALSO recovers style from the (subset-stripped) name, so a bare name still works.
    eff_flags = int(flags or 0) | (16 if b else 0) | (2 if i else 0)
    key = fontmap._family_key(name or "", eff_flags)
    try:
        buf, fam_key, _metric = fontmap.resolve(name or "", eff_flags, text)
    except Exception:  # noqa: BLE001 — resolver failure -> base-14 ladder
        buf, fam_key = None, key
    if buf:
        raw = (name or "").lower()
        rb = bool(eff_flags & 16) or any(k in raw for k in _BOLD_WORDS)
        ri = bool(eff_flags & 2) or any(k in raw for k in _ITALIC_WORDS)
        # style-qualified cache key: distinct weight/italic buffers never share an alias.
        reg_key = f"{fam_key}-{int(rb)}{int(ri)}"
        try:
            return _register_face(buf, reg_key)
        except Exception:  # noqa: BLE001 — corrupt asset -> base-14 ladder
            pass
    cls = _CLASS_OF.get(fam_key, "sans")
    return _font_for(text, cls, bold=b, italic=i)


def unsupported_chars(text: str) -> str:
    """Characters that NEITHER a base-14 family NOR the vendored fallback can render — i.e.
    text that would bake tofu into a document someone will sign. Empty string = all good.

    Parity with the fitz engine's ``unsupported_chars``: latin-1 text is always fine; anything
    else is checked against the fallback face's cmap (fontTools), so the exact same accept-set
    (Latin/ext, Cyrillic, Greek, CJK — not Arabic/Hebrew/Thai/Indic/emoji) is enforced."""
    if _latin1(text):
        return ""
    _ensure_ufont()
    cmap = _ufont_cmap or frozenset()
    return "".join(sorted({ch for ch in text if ch not in ("\n", "\t") and ord(ch) not in cmap}))


def _color(c) -> tuple[float, float, float]:
    """Normalize a colour (RGB 0..1 tuple, "#rrggbb", or packed sRGB int) to an RGB float
    triple. Matches ``pdf_edit._color`` so stamped colours are identical."""
    if isinstance(c, (list, tuple)) and len(c) == 3:
        return tuple(float(v) for v in c)  # type: ignore[return-value]
    if isinstance(c, str) and c.startswith("#") and len(c) >= 7:
        try:
            return tuple(int(c[i : i + 2], 16) / 255 for i in (1, 3, 5))  # type: ignore[return-value]
        except ValueError:
            return (0, 0, 0)
    if isinstance(c, int):
        return ((c >> 16 & 255) / 255, (c >> 8 & 255) / 255, (c & 255) / 255)
    return (0, 0, 0)


# --- rotation ----------------------------------------------------------------------------
def _visual_dims(page) -> tuple[float, float, int, float, float]:
    """(vw, vh, rot, W0, H0) for a pypdf page: the visual (rotation-applied) width/height the
    signer sees, the page /Rotate, and the un-rotated MediaBox width/height."""
    mb = page.mediabox
    w0, h0 = float(mb.width), float(mb.height)
    # Use pypdf's .rotation property (resolves /Rotate INHERITED from the page tree, which a
    # raw page.get("/Rotate") would miss on many real-world uploads) and normalize to 0..270.
    try:
        rot = int(page.rotation) % 360
    except Exception:  # noqa: BLE001 — fall back to the direct key
        rot = int(page.get("/Rotate", 0) or 0) % 360
    if rot in (90, 270):
        return h0, w0, rot, w0, h0
    return w0, h0, rot, w0, h0


def _ctm(rot: int, w0: float, h0: float) -> tuple[float, float, float, float, float, float]:
    """Rotation CTM mapping overlay content authored in the visual frame onto the page's
    un-rotated MediaBox. Proven correct for all four orientations (see port plan)."""
    if rot == 90:
        return (0, 1, -1, 0, w0, 0)
    if rot == 180:
        return (-1, 0, 0, -1, w0, h0)
    if rot == 270:
        return (0, -1, 1, 0, 0, h0)
    return (1, 0, 0, 1, 0, 0)


class _Pen:
    """Thin adapter that lets the ported drawing code work in TOP-LEFT visual coordinates
    (y grows downward, matching the fitz engine and the normalized field frame) while emitting
    to a reportlab canvas whose origin is bottom-left. Every helper below draws through this,
    so the geometry is a near-1:1 port of the fitz stamping helpers."""

    def __init__(self, c: "_rl_canvas.Canvas", vw: float, vh: float) -> None:
        self.c = c
        self.vw = vw
        self.vh = vh

    def _fy(self, y: float) -> float:
        return self.vh - y

    def text(self, x: float, baseline: float, s: str, font: str, size: float, color) -> None:
        self.c.setFont(font, size)
        self.c.setFillColorRGB(*color)
        self.c.drawString(x, self._fy(baseline), s)

    def line(
        self, x1: float, y1: float, x2: float, y2: float, color, width: float, cap: int = 1
    ) -> None:
        self.c.setStrokeColorRGB(*color)
        self.c.setLineWidth(width)
        self.c.setLineCap(cap)
        self.c.line(x1, self._fy(y1), x2, self._fy(y2))

    def image(self, png: bytes, x0: float, y0: float, x1: float, y1: float) -> None:
        rx, ry, rw, rh = x0, self._fy(y1), (x1 - x0), (y1 - y0)
        self.c.drawImage(
            ImageReader(io.BytesIO(png)),
            rx,
            ry,
            rw,
            rh,
            preserveAspectRatio=True,
            anchor="c",
            mask="auto",
        )


def _rect_px(f: dict, vw: float, vh: float) -> tuple[float, float, float, float]:
    """Field's normalized rect → absolute top-left rect (x0, y0, x1, y1) in visual points."""
    x, y, w, h = (
        float(f.get("x", 0)),
        float(f.get("y", 0)),
        float(f.get("w", 0)),
        float(f.get("h", 0)),
    )
    return (x * vw, y * vh, (x + w) * vw, (y + h) * vh)


# --- image validation --------------------------------------------------------------------
def is_valid_image(data: bytes | None) -> bool:
    """True if `data` is an image a stamp can actually place (mirrors what the seal draws).
    A crafted string that merely base64-decodes must NOT pass — Pillow verify rejects it."""
    if not data:
        return False
    try:
        Image.open(io.BytesIO(data)).verify()
        return True
    except Exception:  # noqa: BLE001
        return False


def _png_from_data_url(s) -> bytes | None:
    if not s or not isinstance(s, str):
        return None
    if s.startswith("data:"):
        s = s.split(",", 1)[-1]
    try:
        return base64.b64decode(s)
    except Exception:  # noqa: BLE001
        return None


def _is_checked(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    return str(v or "").strip().lower() in _CHECK_TRUE


# --- single-line / multi-line fitted text (ports _fit_text / _fit_textbox) ----------------
def _fit_text(
    pen: _Pen,
    x0: float,
    y0: float,
    x1: float,
    y1: float,
    text: str,
    size: float | None = None,
    italic: bool = False,
) -> None:
    """One line, vertically centered in the box, shrunk to fit the width — the reportlab twin
    of ``pdf_edit._fit_text``. Font is chosen by coverage (base-14 for latin-1, else the
    vendored fallback) so Cyrillic/CJK values render real glyphs, not tofu."""
    text = (text or "").replace("\n", " ").strip()
    if not text:
        return
    bw, bh = (x1 - x0), (y1 - y0)
    font = _font_for(text, "sans", bold=False, italic=italic)
    s = size or max(8, min(bh * 0.7, 22))
    while s > 6 and stringWidth(text, font, s) > bw - 2:
        s -= 0.5
    baseline = y0 + (bh + s * 0.7) / 2  # top-left baseline, box-centered (matches fitz)
    pen.text(x0 + 1, baseline, text, font, s, (0, 0, 0))


def _wrap(text: str, font: str, size: float, max_w: float) -> list[str]:
    """Greedy word-wrap honoring explicit newlines; hard-breaks any single token wider than
    the box so nothing overflows."""
    out: list[str] = []
    for para in text.split("\n"):
        words = para.split(" ")
        line = ""
        for w in words:
            trial = w if not line else line + " " + w
            if stringWidth(trial, font, size) <= max_w or not line:
                # a lone word wider than the box: hard-break by characters
                if not line and stringWidth(w, font, size) > max_w:
                    cur = ""
                    for ch in w:
                        if stringWidth(cur + ch, font, size) > max_w and cur:
                            out.append(cur)
                            cur = ch
                        else:
                            cur += ch
                    line = cur
                else:
                    line = trial
            else:
                out.append(line)
                line = w
        out.append(line)
    return out


def _fit_textbox(
    pen: _Pen,
    x0: float,
    y0: float,
    x1: float,
    y1: float,
    text: str,
    size: float | None = None,
) -> None:
    """Wrap multi-line text into the box, shrinking the size until every wrapped line fits the
    height — the reportlab twin of ``pdf_edit._fit_textbox``. Falls back to a single fitted
    line if wrapping can't fit even at the minimum size."""
    bw, bh = (x1 - x0 - 3), (y1 - y0 - 3)
    text = (text or "").strip()
    if not text:
        return
    font = _font_for(text, "sans")
    s = size or max(8, min((y1 - y0) * 0.55, 13))
    while s > 6:
        lines = _wrap(text, font, s, bw)
        leading = s * 1.2
        if len(lines) * leading <= bh:
            pen.c.setFont(font, s)
            pen.c.setFillColorRGB(0, 0, 0)
            baseline = y0 + 1.5 + s  # first line top-left baseline
            for ln in lines:
                pen.text(x0 + 1.5, baseline, ln, font, s, (0, 0, 0))
                baseline += leading
            return
        s -= 0.5
    _fit_text(pen, x0, y0, x1, y1, text, size=size)


# --- checkbox tick (ports _draw_check / _vcheck) -----------------------------------------
def _vcheck(pen: _Pen, x: float, y_baseline: float, s: float = 9.0, color=None) -> float:
    """Two-stroke vector check mark whose tip rests on the text baseline `y_baseline` (top-left
    y). Returns the x-advance consumed. No Unicode glyph (base-14 has no U+2713)."""
    col = color if color is not None else _ACCENT
    h = s * 0.66
    x0 = x
    top = y_baseline - h
    short = h * 0.42
    p1 = (x0, y_baseline - h * 0.42)
    p2 = (x0 + short, y_baseline)
    p3 = (x0 + h * 0.95, top)
    w = max(0.9, s * 0.10)
    pen.line(p1[0], p1[1], p2[0], p2[1], col, w, cap=1)
    pen.line(p2[0], p2[1], p3[0], p3[1], col, w, cap=1)
    return h * 0.95 + s * 0.18


def _draw_check(pen: _Pen, x0: float, y0: float, x1: float, y1: float) -> None:
    """A crisp accent-blue vector tick centered in the field box."""
    bw, bh = (x1 - x0), (y1 - y0)
    s = max(8, min(bh * 0.78, 18))
    tw = s * 0.95
    x = x0 + (bw - tw) / 2
    y_base = y0 + (bh + s * 0.5) / 2
    _vcheck(pen, max(x0 + 1, x), y_base, s=s, color=_ACCENT)


# --- signature caption (ports _sig_caption) ----------------------------------------------
def _sig_caption(pen: _Pen, x0: float, y0: float, x1: float, y1: float, meta: dict) -> None:
    """DocuSign-style verification stamp under a signature: accent rule + signer/timestamp
    line and IP/signature-ID line (monospace). Placed above the field if there's no room
    below. Authored in the visual frame so it reads upright on any rotation."""
    em = (0.055, 0.647, 0.416)
    grey = (0.34, 0.37, 0.44)
    grey2 = (0.5, 0.53, 0.6)
    y = y1 + 2.5
    if y + 16 > pen.vh:  # no room below → place above the field
        y = y0 - 15
    pen.line(x0, y, max(x1, x0 + 130), y, em, 0.7)
    name = (meta.get("name") or "").strip()
    when = (meta.get("when") or "").strip()
    line1 = ("Signed by " + name if name else "Signed") + (("  " + when) if when else "")
    line1 = line1[:64]
    bits = []
    if meta.get("ip"):
        bits.append("IP " + str(meta["ip"]))
    if meta.get("sig_id"):
        bits.append(str(meta["sig_id"]))
    elif meta.get("env"):
        bits.append("Env " + str(meta["env"]))
    line2 = "  ·  ".join(bits)[:64] if bits else ""
    pen.text(x0 + 1, y + 7.5, line1, _font_for(line1, "sans", bold=True), 5.4, grey)
    if line2:
        pen.text(x0 + 1, y + 14, line2, _font_for(line2, "mono"), 5.0, grey2)


# --- overlay driver ----------------------------------------------------------------------
def _merge_overlays(data: bytes, page_draw: dict[int, list]) -> bytes:
    """For each page index in `page_draw`, build ONE reportlab overlay in visual dims, run every
    draw callable (each takes a :class:`_Pen`), and merge it onto the page through the rotation
    CTM. Pages without draws pass through untouched. Returns the new PDF bytes."""
    reader = PdfReader(io.BytesIO(data))
    writer = PdfWriter()
    for i, pg in enumerate(reader.pages):
        draws = page_draw.get(i)
        if draws:
            vw, vh, rot, w0, h0 = _visual_dims(pg)
            buf = io.BytesIO()
            c = _rl_canvas.Canvas(buf, pagesize=(vw, vh))
            pen = _Pen(c, vw, vh)
            for d in draws:
                d(pen)
            c.save()
            buf.seek(0)
            ov = PdfReader(buf).pages[0]
            pg.merge_transformed_page(ov, _ctm(rot, w0, h0))
        writer.add_page(pg)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


# --- public API --------------------------------------------------------------------------
def stamp_fields(data: bytes, fields: list[dict]) -> bytes:
    """Burn completed field values into the PDF. Each field:
      {type, page, x, y, w, h, value?, image?(signature/initials data-url), size?, stamp_meta?}
    Supported types (the canonical SG_FIELDS set): signature, initials, date, name, email,
    title, company, text, checkbox (truthy value → tick). Any unrecognized type is stamped as
    plain text so nothing the contract sends is dropped.

    Coordinates are 0..1 top-left normalized in the visual (rotated) frame. A malformed field
    is skipped rather than aborting the whole pass (one bad field must not corrupt the executed
    document for every other signer). Returns the stamped PDF bytes."""
    reader = PdfReader(io.BytesIO(data))
    npages = len(reader.pages)
    dims: dict[int, tuple[float, float]] = {}
    page_draw: dict[int, list] = {}

    for f in fields or []:
        try:
            pi = int(f.get("page", 0))
        except (TypeError, ValueError):
            continue
        if pi < 0 or pi >= npages:
            continue
        if pi not in dims:
            vw, vh, *_ = _visual_dims(reader.pages[pi])
            dims[pi] = (vw, vh)
        vw, vh = dims[pi]
        try:
            x0, y0, x1, y1 = _rect_px(f, vw, vh)
        except (TypeError, ValueError):
            continue
        if (x1 - x0) <= 0 or (y1 - y0) <= 0:
            continue
        ftype = (f.get("type") or "text").lower()

        # Bind a per-field draw closure. Each closure is fully self-contained (captures its own
        # geometry + values) and is wrapped so one malformed field can't abort the page.
        def _mk(ftype=ftype, f=f, x0=x0, y0=y0, x1=x1, y1=y1):
            def _draw(pen: _Pen) -> None:
                try:
                    if ftype in ("signature", "initials"):
                        img = _png_from_data_url(f.get("image") or f.get("value"))
                        if img and is_valid_image(img):
                            pen.image(img, x0, y0, x1, y1)
                        else:
                            tv = f.get("image") or f.get("value")
                            if isinstance(tv, str) and tv and not tv.lstrip().startswith("data:"):
                                _fit_text(pen, x0, y0, x1, y1, tv.strip(), italic=True)
                        if f.get("stamp_meta"):
                            _sig_caption(pen, x0, y0, x1, y1, f["stamp_meta"])
                    elif ftype == "checkbox":
                        if _is_checked(f.get("value")):
                            _draw_check(pen, x0, y0, x1, y1)
                    else:
                        val = f.get("value")
                        val = "" if val is None else str(val)
                        if val.strip():
                            multiline = (
                                ftype == "text"
                                and (y1 - y0) >= 26
                                and ("\n" in val or stringWidth(val, "Helvetica", 10) > (x1 - x0))
                            )
                            size = float(f.get("size", 0)) or None
                            if multiline:
                                _fit_textbox(pen, x0, y0, x1, y1, val, size=size)
                            else:
                                _fit_text(pen, x0, y0, x1, y1, val, size=size)
                except Exception:  # noqa: BLE001 — never let one field corrupt the document
                    return

            return _draw

        page_draw.setdefault(pi, []).append(_mk())

    if not page_draw:
        return data
    return _merge_overlays(data, page_draw)


def add_text(data: bytes, items: list[dict]) -> bytes:
    """Author-added text (the ``kind:'text'`` add-text from the fitz engine's ``apply_edits``).
    Each item: {page, x, y, text, size?, color?, font?} — text is placed with its first line's
    baseline at the normalized (x, y) top-left point in the visual frame.

    Latin-1 text uses the chosen base-14 family (font ∈ {sans, serif, mono}); anything else
    embeds the vendored fallback (auto-subset). PRESERVES the fail-closed guard: text whose
    first (or any wrapped) line runs off the bottom of the page raises
    ``ValueError("text runs off the bottom of page N")`` so the caller returns a 400 and no
    file is written — dropped text on a legally-signed document is worse than tofu.
    Returns the edited PDF bytes."""
    reader = PdfReader(io.BytesIO(data))
    npages = len(reader.pages)
    page_draw: dict[int, list] = {}

    for e in items or []:
        if e.get("kind", "text") != "text":
            continue
        try:
            pi = int(e.get("page", 0))
        except (TypeError, ValueError):
            continue
        if pi < 0 or pi >= npages:
            continue
        vw, vh, *_ = _visual_dims(reader.pages[pi])
        size = float(e.get("size", 11)) or 11
        text = str(e.get("text", ""))
        family = _ADDTEXT_FAMILY.get(str(e.get("font", "sans")), "sans")
        font = _font_for(text, family)
        color = _color(e.get("color"))
        x = float(e.get("x", 0)) * vw
        # first line's baseline in TOP-LEFT visual coords (matches fitz: point is the baseline,
        # top of the glyph box at y*H, baseline size lower).
        top_baseline = float(e.get("y", 0)) * vh + size
        lines = text.split("\n")
        leading = size * 1.2
        # Fail-closed off-page guard: check the first AND every subsequent line's baseline
        # against the page height BEFORE drawing. fitz silently dropped off-page lines; here we
        # refuse the whole edit instead.
        last_baseline = top_baseline + leading * (len(lines) - 1)
        if top_baseline > vh or last_baseline > vh:
            raise ValueError(f"text runs off the bottom of page {pi + 1}")

        def _mk(
            lines=lines,
            x=x,
            top_baseline=top_baseline,
            leading=leading,
            font=font,
            size=size,
            color=color,
        ):
            def _draw(pen: _Pen) -> None:
                baseline = top_baseline
                for ln in lines:
                    pen.text(x, baseline, ln, font, size, color)
                    baseline += leading

            return _draw

        page_draw.setdefault(pi, []).append(_mk())

    if not page_draw:
        return data
    return _merge_overlays(data, page_draw)


def replace_runs(data: bytes, runs: list[dict]) -> bytes:
    """In-place text replacement by VECTOR cover+redraw. Each run:
      {page, x0, y0, x1, y1 (norm top-left, the ORIGINAL run bbox), baseline (norm top-left y),
       text (the NEW string), orig_font, flags?, size, color, bg (r,g,b 0..1), pad?}.

    For each run, on ONE overlay per page (merged through the rotation CTM like every other
    stamp), a filled rect in the run's sampled background colour is drawn over the original run
    bbox, then the new text is drawn at the extracted baseline in a fontmap-resolved, width-
    matched face (:func:`font_for_run`) at the extracted colour + size. The rest of the page
    stays VECTOR — nothing here rasterizes. A longer replacement is shrunk-to-fit (floor 6pt)
    so it can't spill past the original run's right edge. A malformed run is skipped, never
    corrupting the page for the others."""
    reader = PdfReader(io.BytesIO(data))
    npages = len(reader.pages)
    page_draw: dict[int, list] = {}

    for r in runs or []:
        try:
            pi = int(r["page"])
        except (TypeError, ValueError, KeyError):
            continue
        if pi < 0 or pi >= npages:
            continue
        vw, vh, *_ = _visual_dims(reader.pages[pi])
        try:
            x0 = float(r["x0"]) * vw
            x1 = float(r["x1"]) * vw
            y0 = float(r["y0"]) * vh
            y1 = float(r["y1"]) * vh
            base = float(r["baseline"]) * vh
        except (TypeError, ValueError, KeyError):
            continue
        size = float(r.get("size", 11)) or 11
        text = str(r.get("text", ""))
        color = _color(r.get("color"))
        bg = _color(r.get("bg") if r.get("bg") is not None else (1, 1, 1))
        font = font_for_run(
            str(r.get("orig_font", "")),
            size,
            text,
            bold=r.get("bold"),
            italic=r.get("italic"),
            flags=int(r.get("flags", 0) or 0),
        )
        pad = float(r.get("pad", size * 0.18))
        # shrink-to-fit: keep the replacement inside the original run's horizontal extent.
        s = size
        box_w = x1 - x0
        while s > 6 and stringWidth(text, font, s) > box_w + pad:
            s -= 0.25

        def _mk(
            x0=x0,
            y0=y0,
            x1=x1,
            y1=y1,
            base=base,
            text=text,
            font=font,
            s=s,
            color=color,
            bg=bg,
            pad=pad,
        ):
            def _draw(pen: _Pen) -> None:
                try:
                    # Cover rect over the original run. Top-left span is y in [y0-pad, y1+pad];
                    # reportlab's rect origin is bottom-left, so convert the BOTTOM edge (y1+pad).
                    rh = (y1 - y0) + 2 * pad
                    pen.c.setFillColorRGB(*bg)
                    pen.c.rect(x0 - 1, pen._fy(y1 + pad), (x1 - x0) + 2, rh, stroke=0, fill=1)
                    pen.text(x0, base, text, font, s, color)
                except Exception:  # noqa: BLE001 — one bad run must not corrupt the page
                    return

            return _draw

        page_draw.setdefault(pi, []).append(_mk())

    if not page_draw:
        return data
    return _merge_overlays(data, page_draw)
