"""Certificate of Completion + PDF post-ops for the native e-sign system — PERMISSIVE stack.

This module is a fitz/PyMuPDF-FREE reimplementation of the certificate renderer and the
seal/sanitize/append post-operations that previously lived in ``pdf_edit.py``. It imports
NO AGPL code. Every drawing primitive is reportlab (BSD); the seal/scrub/rewrite ops are
pikepdf (MPL-2.0); page appends are pypdf (BSD).

Public API (drop-in replacements for the fitz versions in ``pdf_edit``):
    make_certificate(...) -> bytes   — the branded multi-page Certificate of Completion
    sanitize_pdf(data)    -> bytes   — scrub metadata / JS / actions + GC rewrite (no crypto)
    secure_pdf(data)      -> bytes   — sanitize + AES-256 (owner-pw only, empty user-pw)
    append_pdf(a, b)      -> bytes   — concatenate two PDFs (cert pages onto the executed doc)
    sha256(data)          -> str

Coordinate model: internally the certificate is authored in the SAME top-left, y-down,
612x792-point frame the original fitz code used, so the ~660-line layout is transcribed
verbatim. A thin ``_Canvas`` wrapper records draw ops and, at ``render`` time, flips Y into
reportlab's bottom-left space and replays them onto a real ``reportlab.pdfgen.canvas``. Page
numbering ("page i of N") is resolved at render time because N is only known once the whole
document has been laid out — which is why ops are buffered rather than drawn eagerly.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import io
import logging
import math
import pathlib as _pl
import re
import secrets as _secrets

import pikepdf
import pypdf
from reportlab.lib.colors import Color
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as _rcanvas

from . import config

_log = logging.getLogger(__name__)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------------------------------
# Palette (verbatim from the original certificate) + page geometry
# ------------------------------------------------------------------------------------------
_BG = (1, 1, 1)
_HERO = (0.016, 0.027, 0.043)
_HERO2 = (0.035, 0.063, 0.094)
_ONHERO = (0.96, 0.975, 0.985)
_ONHERO2 = (0.60, 0.69, 0.78)
_ACCENT = (0.106, 0.329, 0.78)
_ACCENT_HERO = (0.353, 0.651, 1.0)
_ACCENT_DK = (0.078, 0.243, 0.62)
_TEAL = (0.098, 0.435, 0.84)
_LOGO_INK = (0.09, 0.12, 0.16)
_INK = (0.08, 0.11, 0.15)
_GREY = (0.42, 0.47, 0.54)
_GREY2 = (0.55, 0.60, 0.66)
_RED = (0.80, 0.16, 0.16)
_LINE = (0.85, 0.88, 0.92)
_TINT = (0.965, 0.978, 0.986)
_TINT2 = (0.92, 0.95, 1.0)
_ZEBRA = (0.972, 0.982, 0.99)
_W, _H, _M = 612, 792, 54


# ------------------------------------------------------------------------------------------
# Font registration (brand faces → reportlab; fall back to base-14 if a file is missing)
# ------------------------------------------------------------------------------------------
_FONT_DIR = _pl.Path(__file__).parent / "assets" / "fonts"
_REG: dict[str, str] = {}  # brand alias -> registered reportlab font name (only if loaded)
_FALLBACK = {
    "sora": "Helvetica-Bold",
    "sorax": "Helvetica-Bold",
    "inter": "Helvetica",
    "interb": "Helvetica-Bold",
    "mono": "Courier",
    "helv": "Helvetica",
    "hebo": "Helvetica-Bold",
    "heit": "Helvetica-Oblique",
    "hebi": "Helvetica-BoldOblique",
    "cour": "Courier",
    "cobo": "Courier-Bold",
    "coit": "Courier-Oblique",
    "tiro": "Times-Roman",
    "tibo": "Times-Bold",
    "tiit": "Times-Italic",
    "tibi": "Times-BoldItalic",
}
for _alias, _fn in (
    ("sora", "Sora-600.ttf"),
    ("sorax", "Sora-700.ttf"),
    ("inter", "Inter-400.ttf"),
    ("interb", "Inter-600.ttf"),
    ("mono", "JBMono-400.ttf"),
):
    try:
        pdfmetrics.registerFont(TTFont(_alias, str(_FONT_DIR / _fn)))
        _REG[_alias] = _alias
    except Exception:  # noqa: BLE001 — a missing brand face degrades to base-14, never fatal
        pass
if not _REG:
    _log.warning(
        "pdf_cert: bundled brand fonts not found (%s); certificates will use base-14", _FONT_DIR
    )


def _rf(alias: str) -> str:
    """Resolve a font alias (brand or base-14 shorthand) to a usable reportlab font name."""
    if alias in _REG:
        return _REG[alias]
    if alias in _FALLBACK:
        return _FALLBACK[alias]
    return alias  # already a reportlab base-14 name (e.g. "Helvetica")


def _bf(alias: str) -> str:
    """Kept for transcription fidelity with the original — resolution happens in ``_rf``."""
    return alias


def _tw(alias: str, text: str, size: float) -> float:
    """Text width in the resolved font — for layout fit/centering (replaces fitz text_length)."""
    try:
        return stringWidth(text or "", _rf(alias), size)
    except Exception:  # noqa: BLE001 — a bad glyph must never abort a legal certificate
        return stringWidth(text or "", "Helvetica", size)


def _C(t) -> Color | None:
    if t is None:
        return None
    return Color(t[0], t[1], t[2])


# ------------------------------------------------------------------------------------------
# fitz.Rect / fitz.Point / fitz.Matrix stand-ins (top-left, y-down authoring space)
# ------------------------------------------------------------------------------------------
class Rect:
    __slots__ = ("x0", "y0", "x1", "y1")

    def __init__(self, x0, y0, x1, y1):
        self.x0, self.y0, self.x1, self.y1 = float(x0), float(y0), float(x1), float(y1)

    @property
    def width(self):
        return self.x1 - self.x0

    @property
    def height(self):
        return self.y1 - self.y0


class Point:
    __slots__ = ("x", "y")

    def __init__(self, x, y):
        self.x, self.y = float(x), float(y)


class Matrix:
    __slots__ = ("a", "b", "c", "d", "e", "f")

    def __init__(self, a, b, c, d, e, f):
        self.a, self.b, self.c, self.d, self.e, self.f = a, b, c, d, e, f


# ------------------------------------------------------------------------------------------
# Buffered canvas: record draw ops in top-left space, replay flipped into reportlab
# ------------------------------------------------------------------------------------------
class _Canvas:
    """Records certificate draw ops per page; ``render`` flips Y and replays onto reportlab.

    Method signatures mirror the subset of the fitz ``Page`` API the certificate used, so the
    original layout code transcribes almost verbatim (``p.insert_text``, ``p.draw_rect`` …)."""

    def __init__(self) -> None:
        self.pages: list[list[tuple]] = []
        self.rect = Rect(0, 0, _W, _H)

    def new_page(self, width: float | None = None, height: float | None = None) -> "_Canvas":
        self.pages.append([])
        return self

    @property
    def _cur(self) -> list[tuple]:
        return self.pages[-1]

    def insert_text(
        self, pt, txt, fontsize=11, color=(0, 0, 0), fontname="helv", morph=None, fill_opacity=None
    ) -> None:
        self._cur.append(
            ("text", (pt[0], pt[1], txt, fontsize, color, fontname, morph, fill_opacity))
        )

    def draw_rect(self, r, color=None, fill=None, radius=0, width=1.0) -> None:
        self._cur.append(("rect", (r.x0, r.y0, r.x1, r.y1, color, fill, radius, width)))

    def draw_line(self, p1, p2, color=(0, 0, 0), width=1.0, lineCap=0) -> None:
        self._cur.append(("line", (p1.x, p1.y, p2.x, p2.y, color, width, lineCap)))

    def draw_circle(self, center, r, color=None, fill=None, fill_opacity=None, width=1.0) -> None:
        self._cur.append(("circle", (center.x, center.y, r, color, fill, fill_opacity, width)))

    def draw_oval(self, r, color=None, fill=None, width=1.0) -> None:
        self._cur.append(("oval", (r.x0, r.y0, r.x1, r.y1, color, fill, width)))

    def insert_image(self, r, stream=None, keep_proportion=True) -> None:
        self._cur.append(("image", (r.x0, r.y0, r.x1, r.y1, stream, keep_proportion)))

    def insert_textbox(
        self, r, txt, fontsize=11, color=(0, 0, 0), fontname="helv", align=0, rotate=0
    ) -> None:
        self._cur.append(
            ("textbox", (r.x0, r.y0, r.x1, r.y1, txt, fontsize, color, fontname, align))
        )

    def fingerprint(self, cx, cy, r, stroke) -> None:
        self._cur.append(("fp", (cx, cy, r, stroke)))

    def render(self, env: str) -> bytes:
        buf = io.BytesIO()
        c = _rcanvas.Canvas(buf, pagesize=(_W, _H))
        total = len(self.pages)
        for i, cmds in enumerate(self.pages):
            for op, args in cmds:
                _DISPATCH[op](c, *args)
            _footer(c, i, total, env)
            c.showPage()
        c.save()
        return buf.getvalue()


# --- op dispatchers (top-left → reportlab bottom-left flip lives here) ---------------------
def _do_text(c, x, y, txt, size, color, font, morph, alpha) -> None:
    if txt is None or txt == "":
        return
    c.saveState()
    # Bake alpha INTO the Color: reportlab's setFillColor sets alpha from the color's own
    # .alpha (default 1.0), so a separate setFillAlpha would be clobbered by setFillColor.
    col = color or (0, 0, 0)
    c.setFillColor(Color(col[0], col[1], col[2], alpha if alpha is not None else 1.0))
    c.setFont(_rf(font), size)
    if morph is not None:
        pivot, mat = morph
        ang = math.degrees(math.atan2(mat.b, mat.a))
        c.translate(pivot.x, _H - pivot.y)
        c.rotate(ang)
        c.translate(-pivot.x, -(_H - pivot.y))
    c.drawString(x, _H - y, str(txt))
    c.restoreState()


def _do_rect(c, x0, y0, x1, y1, color, fill, radius, width) -> None:
    w, h = x1 - x0, y1 - y0
    by = _H - y1
    c.saveState()
    sc, fc = color is not None, fill is not None
    if sc:
        c.setStrokeColor(_C(color))
        c.setLineWidth(width or 1.0)
    if fc:
        c.setFillColor(_C(fill))
    rad = (radius * min(abs(w), abs(h))) if radius else 0
    if rad > 0:
        c.roundRect(x0, by, w, h, rad, stroke=1 if sc else 0, fill=1 if fc else 0)
    else:
        c.rect(x0, by, w, h, stroke=1 if sc else 0, fill=1 if fc else 0)
    c.restoreState()


def _do_line(c, x0, y0, x1, y1, color, width, cap) -> None:
    c.saveState()
    c.setStrokeColor(_C(color) or Color(0, 0, 0))
    c.setLineWidth(width or 1.0)
    try:
        c.setLineCap(cap)
    except Exception:  # noqa: BLE001
        pass
    c.line(x0, _H - y0, x1, _H - y1)
    c.restoreState()


def _do_circle(c, cx, cy, r, color, fill, alpha, width) -> None:
    c.saveState()
    sc, fc = color is not None, fill is not None
    a = alpha if alpha is not None else 1.0
    if sc:
        c.setStrokeColor(Color(color[0], color[1], color[2], a))
        c.setLineWidth(width or 1.0)
    if fc:
        c.setFillColor(Color(fill[0], fill[1], fill[2], a))
    c.circle(cx, _H - cy, r, stroke=1 if sc else 0, fill=1 if fc else 0)
    c.restoreState()


def _do_oval(c, x0, y0, x1, y1, color, fill, width) -> None:
    c.saveState()
    sc, fc = color is not None, fill is not None
    if sc:
        c.setStrokeColor(_C(color))
        c.setLineWidth(width or 1.0)
    if fc:
        c.setFillColor(_C(fill))
    c.ellipse(x0, _H - y1, x1, _H - y0, stroke=1 if sc else 0, fill=1 if fc else 0)
    c.restoreState()


def _do_image(c, x0, y0, x1, y1, stream, keep_proportion) -> None:
    if not stream:
        return
    try:
        img = ImageReader(io.BytesIO(stream))
        iw, ih = img.getSize()
        bw, bh, by = x1 - x0, y1 - y0, _H - y1
        if keep_proportion and iw and ih:
            sc = min(bw / iw, bh / ih)
            dw, dh = iw * sc, ih * sc
            c.drawImage(img, x0 + (bw - dw) / 2, by + (bh - dh) / 2, dw, dh, mask="auto")
        else:
            c.drawImage(img, x0, by, bw, bh, mask="auto")
    except Exception:  # noqa: BLE001 — a bad signature thumb must not abort the certificate
        pass


def _do_textbox(c, x0, y0, x1, y1, txt, size, color, font, align) -> None:
    fn = _rf(font)
    c.setFillColor(_C(color) or Color(0, 0, 0))
    c.setFont(fn, size)
    maxw = (x1 - x0) - 1
    lines: list[str] = []
    for para in str(txt).split("\n"):
        cur = ""
        for word in para.split(" "):
            test = (cur + " " + word).strip()
            if cur and stringWidth(test, fn, size) > maxw:
                lines.append(cur)
                cur = word
            else:
                cur = test
        lines.append(cur)
    ty = y0 + size
    lh = size * 1.2
    for ln in lines:
        if ty > y1 + 1:
            break
        c.drawString(x0, _H - ty, ln)
        ty += lh


# --- lucide "fingerprint" glyph, drawn as vector paths (replaces the fitz SVG→PNG bake) ----
_FP_PATHS = (
    "M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4",
    "M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2",
    "M17.29 21.02c.12-.6.43-2.3.5-3.02",
    "M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4",
    "M8.65 22c.21-.66.45-1.32.57-2",
    "M14 13.12c0 2.38 0 6.38-1 8.88",
    "M2 16h.01",
    "M21.8 16c.2-2 .131-5.354 0-6",
    "M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.17-.02 2",
)
_NUM_RE = re.compile(r"[-+]?(?:\d*\.\d+|\d+\.?\d*)(?:[eE][-+]?\d+)?")
_TOK_RE = re.compile(r"[MmLlHhVvCcSsQqTtAaZz]|" + _NUM_RE.pattern)


def _arc_to_beziers(x0, y0, rx, ry, phi_deg, large, sweep, x, y):
    """SVG endpoint-parameterised arc → list of cubic-bezier segments ('C',c1x,c1y,c2x,c2y,ex,ey)."""
    if rx == 0 or ry == 0:
        return [("L", x, y)]
    phi = math.radians(phi_deg)
    cosp, sinp = math.cos(phi), math.sin(phi)
    dx, dy = (x0 - x) / 2, (y0 - y) / 2
    x1p = cosp * dx + sinp * dy
    y1p = -sinp * dx + cosp * dy
    rx, ry = abs(rx), abs(ry)
    lam = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry)
    if lam > 1:
        s = math.sqrt(lam)
        rx, ry = rx * s, ry * s
    sign = -1 if large == sweep else 1
    num = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p
    den = rx * rx * y1p * y1p + ry * ry * x1p * x1p
    co = sign * math.sqrt(max(0.0, num / den)) if den else 0.0
    cxp = co * rx * y1p / ry
    cyp = -co * ry * x1p / rx
    cx = cosp * cxp - sinp * cyp + (x0 + x) / 2
    cy = sinp * cxp + cosp * cyp + (y0 + y) / 2

    def _ang(ux, uy, vx, vy):
        d = math.hypot(ux, uy) * math.hypot(vx, vy)
        cc = max(-1.0, min(1.0, (ux * vx + uy * vy) / d)) if d else 1.0
        a = math.acos(cc)
        return -a if (ux * vy - uy * vx) < 0 else a

    th1 = _ang(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry)
    dth = _ang((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry)
    if not sweep and dth > 0:
        dth -= 2 * math.pi
    if sweep and dth < 0:
        dth += 2 * math.pi
    nseg = max(1, int(math.ceil(abs(dth) / (math.pi / 2))))
    out = []
    d_ = dth / nseg
    t = (4 / 3) * math.tan(d_ / 4)
    for i in range(nseg):
        a1 = th1 + i * d_
        a2 = a1 + d_
        ca1, sa1, ca2, sa2 = math.cos(a1), math.sin(a1), math.cos(a2), math.sin(a2)

        def _pt(ca, sa):
            return (
                cx + rx * cosp * ca - ry * sinp * sa,
                cy + rx * sinp * ca + ry * cosp * sa,
            )

        e1x, e1y = _pt(ca1, sa1)
        e2x, e2y = _pt(ca2, sa2)
        d1x, d1y = -rx * cosp * sa1 - ry * sinp * ca1, -rx * sinp * sa1 + ry * cosp * ca1
        d2x, d2y = -rx * cosp * sa2 - ry * sinp * ca2, -rx * sinp * sa2 + ry * cosp * ca2
        out.append(("C", e1x + t * d1x, e1y + t * d1y, e2x - t * d2x, e2y - t * d2y, e2x, e2y))
    return out


def _parse_svg_path(d: str):
    """Parse the (small, known) SVG path subset used by the fingerprint into absolute segments."""
    toks = _TOK_RE.findall(d)
    i, n = 0, len(toks)
    cx = cy = sx = sy = 0.0
    cmd = ""
    segs: list[tuple] = []

    def num():
        nonlocal i
        v = float(toks[i])
        i += 1
        return v

    while i < n:
        if _NUM_RE.fullmatch(toks[i]) is None:
            cmd = toks[i]
            i += 1
        rel = cmd.islower()
        cu = cmd.upper()
        if cu == "M":
            x, y = num(), num()
            if rel:
                x, y = cx + x, cy + y
            cx, cy = x, y
            sx, sy = x, y
            segs.append(("M", x, y))
            cmd = "l" if rel else "L"  # implicit lineto for subsequent pairs
        elif cu == "L":
            x, y = num(), num()
            if rel:
                x, y = cx + x, cy + y
            cx, cy = x, y
            segs.append(("L", x, y))
        elif cu == "H":
            x = num()
            if rel:
                x = cx + x
            cx = x
            segs.append(("L", cx, cy))
        elif cu == "V":
            y = num()
            if rel:
                y = cy + y
            cy = y
            segs.append(("L", cx, cy))
        elif cu == "C":
            x1, y1, x2, y2, x, y = num(), num(), num(), num(), num(), num()
            if rel:
                x1, y1, x2, y2, x, y = (
                    cx + x1,
                    cy + y1,
                    cx + x2,
                    cy + y2,
                    cx + x,
                    cy + y,
                )
            segs.append(("C", x1, y1, x2, y2, x, y))
            cx, cy = x, y
        elif cu == "A":
            rx, ry, rot, large, sweep, x, y = (
                num(),
                num(),
                num(),
                num(),
                num(),
                num(),
                num(),
            )
            if rel:
                x, y = cx + x, cy + y
            segs.extend(_arc_to_beziers(cx, cy, rx, ry, rot, int(large), int(sweep), x, y))
            cx, cy = x, y
        elif cu == "Z":
            segs.append(("L", sx, sy))
            cx, cy = sx, sy
        else:  # unsupported command — bail out safely
            break
    return segs


def _do_fp(c, cx, cy, r, stroke) -> None:
    """Draw the fingerprint glyph centred at (cx,cy) inside a 2r box, honouring the 24x24 viewBox."""
    try:
        col = stroke
        if isinstance(stroke, str) and stroke.startswith("#") and len(stroke) >= 7:
            col = tuple(int(stroke[k : k + 2], 16) / 255 for k in (1, 3, 5))
        scale = (2 * r) / 24.0

        def mp(sx, sy):  # svg point -> reportlab point (via top-left, then flip)
            tx = cx - r + sx * scale
            ty = cy - r + sy * scale
            return tx, _H - ty

        c.saveState()
        c.setStrokeColor(Color(*col))
        c.setLineWidth(max(0.4, 1.7 * scale))
        c.setLineCap(1)
        c.setLineJoin(1)
        for d in _FP_PATHS:
            segs = _parse_svg_path(d)
            if not segs:
                continue
            path = c.beginPath()
            started = False
            for seg in segs:
                if seg[0] == "M":
                    px, py = mp(seg[1], seg[2])
                    path.moveTo(px, py)
                    started = True
                elif seg[0] == "L" and started:
                    px, py = mp(seg[1], seg[2])
                    path.lineTo(px, py)
                elif seg[0] == "C" and started:
                    c1 = mp(seg[1], seg[2])
                    c2 = mp(seg[3], seg[4])
                    e = mp(seg[5], seg[6])
                    path.curveTo(c1[0], c1[1], c2[0], c2[1], e[0], e[1])
            c.drawPath(path, stroke=1, fill=0)
        c.restoreState()
    except Exception:  # noqa: BLE001 — decorative mark; never abort the certificate
        pass


_DISPATCH = {
    "text": _do_text,
    "rect": _do_rect,
    "line": _do_line,
    "circle": _do_circle,
    "oval": _do_oval,
    "image": _do_image,
    "textbox": _do_textbox,
    "fp": _do_fp,
}


def _footer(c, i: int, total: int, env: str) -> None:
    """Repeating footer drawn at render time (needs the final page count)."""
    _do_line(c, _M, _H - 40, _W - _M, _H - 40, _LINE, 0.6, 0)
    _do_text(c, _M, _H - 26, f"Envelope {env}", 7.5, _GREY, "helv", None, None)
    _brand = "LiftedSign" + (f" · {config.LEGAL_ENTITY}" if config.LEGAL_ENTITY else "")
    _do_text(c, _M, _H - 16, _brand, 6.8, _GREY2, "helv", None, None)
    _do_text(
        c,
        _W - _M - 170,
        _H - 26,
        f"Secured by LiftedSign · page {i + 1} of {total}",
        7.5,
        _GREY,
        "helv",
        None,
        None,
    )


# ------------------------------------------------------------------------------------------
# Pure helpers (transcribed from pdf_edit — no fitz dependency)
# ------------------------------------------------------------------------------------------
def _png_from_data_url(s: str) -> bytes | None:
    if not s:
        return None
    if s.startswith("data:"):
        s = s.split(",", 1)[-1]
    try:
        return base64.b64decode(s)
    except Exception:  # noqa: BLE001
        return None


def _truthy(v) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on", "x")
    return bool(v)


def _fmt(ts) -> str:
    if not ts:
        return ""
    try:
        return datetime.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, TypeError):
        return str(ts)


def _mask_email(email: str) -> str:
    e = (email or "").strip()
    if "@" not in e:
        return "—"
    local, _, domain = e.partition("@")
    if not local or not domain:
        return "—"
    head = local[0]
    return f"{head}{'•' * max(3, min(len(local) - 1, 5))}@{domain}"


def _access_label(method: str) -> str:
    m = (method or "").strip()
    if not m:
        return "Demonstrated"
    return {"viewed_pdf_in_browser": "Viewed PDF in-browser"}.get(m, m.replace("_", " "))


def _friendly_ua(ua: str) -> str:
    u = (ua or "").lower()
    if not u:
        return "—"
    browser = (
        "Microsoft Edge"
        if "edg/" in u
        else "Opera"
        if ("opr/" in u or "opera" in u)
        else "Samsung Internet"
        if "samsungbrowser" in u
        else "Brave"
        if "brave" in u
        else "Chrome"
        if ("chrome" in u or "crios" in u) and "chromium" not in u
        else "Firefox"
        if ("firefox" in u or "fxios" in u)
        else "Safari"
        if "safari" in u
        else "Web browser"
    )
    osys = (
        "Windows"
        if "windows" in u
        else "Android"
        if "android" in u
        else "iOS"
        if ("iphone" in u or "ipad" in u or "ipod" in u)
        else "macOS"
        if ("macintosh" in u or "mac os" in u)
        else "Linux"
        if "linux" in u
        else ""
    )
    return f"{browser} on {osys}" if osys else browser


_AUTH_LABELS = {
    "email": "Email · single-use token link",
    "email_otp": "Email + one-time passcode (OTP)",
    "access_code": "Email + private access code",
}

_EVENT_LABELS = {
    "created": "Envelope created",
    "edited": "Document edited",
    "sent": "Envelope sent",
    "emailed": "Invitation emailed",
    "viewed": "Document viewed",
    "self_sign": "Self-sign link issued",
    "reminded": "Reminder sent",
    "signed": "Signer completed",
    "declined": "Signing declined",
    "completed": "Envelope completed",
    "voided": "Envelope voided",
    "signature_adopted": "Signature adopted",
    "field_signed": "Field signed",
    "econsent_accepted": "E-consent accepted",
    "records_access_demonstrated": "Records access demonstrated",
    "econsent_withdrawn": "E-consent withdrawn",
    "signer_authenticated": "Signer authenticated",
    "email_verified": "Email verified",
    "otp_verified": "OTP verified",
    "doc_frozen": "Document frozen (presented version)",
    "doc_sealed": "Document sealed",
    "redacted": "Content redacted",
    "text_added": "Text added",
    "completed_copy_delivered": "Completed copy delivered",
    "access_challenge_passed": "Identity check passed",
    "access_challenge_failed": "Identity check failed",
    "access_challenge_locked": "Identity check locked",
    "access_challenge_configured": "Identity check configured",
    "envelope_access_verified": "Envelope access verified",
    "envelope_viewed": "Envelope viewed",
}


def _event_label(t: str) -> str:
    key = (t or "").strip().lower()
    return _EVENT_LABELS.get(key, (t or "").replace("_", " ").strip().title() or "Event")


_CHALLENGE_LABELS = {
    "code": "Access code verified",
    "text": "Security question verified",
    "dob": "Date of birth verified",
    "ssn": "SSN verified",
    "ssn_last4": "Last-4 SSN verified",
}
_CHALLENGE_FACTOR = {
    "code": "Private access code",
    "text": "Security question · knowledge-based",
    "dob": "Date of birth · knowledge-based",
    "ssn": "Social Security number · knowledge-based",
    "ssn_last4": "Last 4 of SSN · knowledge-based",
}


def _identity_evidence(s, events, override=None):
    src = dict(s or {})
    if override:
        src.update({k: v for k, v in override.items() if v is not None})
    sid = s.get("id") if s else None
    out: list[tuple[str, str]] = []
    ctype = src.get("challenge_type") or "none"
    passed = (
        bool(src.get("passed"))
        or bool(src.get("challenge_passed_at"))
        or any(
            (e.get("type", "") or "").upper() == "ACCESS_CHALLENGE_PASSED"
            and (e.get("signer_id") == sid)
            for e in (events or [])
        )
    )
    if ctype and ctype != "none" and passed:
        out.append(("Identity check", _CHALLENGE_LABELS.get(ctype, "Identity check verified")))
    method = src.get("env_auth_method") or ""
    when = _fmt(src.get("env_auth_at") or src.get("otp_verified_at"))
    if method.startswith("otp:"):
        channel = "SMS" if method.endswith("sms") else "Email"
        out.append((f"{channel} OTP verified", when or "Verified"))
    elif method == "google":
        gmail = src.get("env_auth_email") or src.get("email")
        out.append(("Google verified", _mask_email(gmail or "")))
    elif src.get("otp_verified_at"):
        out.append(("OTP verified", when or "Verified"))
    return out


def _challenge_factor(s, events, override=None) -> str:
    src = dict(s or {})
    if override:
        src.update({k: v for k, v in override.items() if v is not None})
    sid = s.get("id") if s else None
    ctype = src.get("challenge_type") or "none"
    passed = (
        bool(src.get("passed"))
        or bool(src.get("challenge_passed_at"))
        or any(
            (e.get("type", "") or "").upper() == "ACCESS_CHALLENGE_PASSED"
            and (e.get("signer_id") == sid)
            for e in (events or [])
        )
    )
    if ctype and ctype != "none" and passed:
        return _CHALLENGE_FACTOR.get(ctype, "Sender access lock")
    return ""


def _wrap_lines(txt: str, width: float, size: float = 7.2, font: str = "helv") -> list[str]:
    out: list[str] = []
    line = ""
    for word in (txt or "").split():
        test = (line + " " + word).strip()
        if line and _tw(font, test, size) > width:
            out.append(line)
            line = word
        else:
            line = test
    if line:
        out.append(line)
    return out or [""]


def _signer_affirmation(s, consumer, disclosure_version, auth_label, tz) -> str:
    name = (s.get("name") or s.get("email") or "This signer").strip()
    when = _fmt(s.get("consent_at")) or _fmt(s.get("signed_at"))
    dv = (disclosure_version or s.get("disclosure_version") or "").strip()
    auth = (auth_label or "a unique single-use access link").strip()
    parts = [
        f"{name} took an affirmative action to adopt an electronic signature and, by applying "
        "it, affirmed the intent to sign this record and agreed that the electronic signature "
        "is the legal equivalent of a handwritten signature."
    ]
    if _truthy(s.get("consent")) or s.get("consent_at"):
        consent_clause = (
            "affirmatively consented to transact business electronically and to "
            "use electronic records and signatures"
        )
        if dv:
            consent_clause += (
                f", accepting the Electronic Record and Signature Disclosure (version {dv})"
            )
        else:
            consent_clause += " under the ESIGN Act and UETA"
        if when:
            consent_clause += f" on {when} ({tz})"
        parts.append(f"The signer {consent_clause}.")
    else:
        parts.append(
            "Consent to transact electronically was not separately recorded for this "
            "signer (non-consumer / inferred from conduct)."
        )
    parts.append(
        f"Identity was authenticated via {auth}; the IP address, device and timestamp "
        "of each action are recorded in the audit trail."
    )
    if consumer:
        access = (
            _access_label(s.get("access_method")) if _truthy(s.get("access_demonstrated")) else ""
        )
        cons = (
            "As a consumer, the signer was shown the §7001(c) disclosure (paper-copy right, "
            "withdrawal right and consequences, scope, how to update contact information, and "
            "the hardware/software requirements) before consenting, and demonstrated the "
            "ability to access the electronic records"
        )
        if access:
            cons += f" ({access})"
        cons += "."
        parts.append(cons)
    if s.get("consent_withdrawn_at"):
        parts.append(
            "This signer subsequently withdrew electronic-records consent on "
            f"{_fmt(s.get('consent_withdrawn_at'))}."
        )
    return " ".join(parts)


# ------------------------------------------------------------------------------------------
# Brand drawing helpers (take the buffered canvas `p`)
# ------------------------------------------------------------------------------------------
def _reg_fonts(p) -> None:
    """No-op — reportlab fonts are registered globally at import (kept for call-site fidelity)."""
    return None


def _draw_logo(p, x, baseline, s, wordmark=True, ink=None, accent=None) -> None:
    fn = _bf("sora")
    ink = ink if ink is not None else _LOGO_INK
    accent = accent if accent is not None else _ACCENT
    p.insert_text((x, baseline), "Lifted", fontsize=s, color=ink, fontname=fn)
    w1 = _tw("sora", "Lifted", s)
    p.insert_text((x + w1, baseline), "Sign", fontsize=s, color=accent, fontname=fn)
    w2 = _tw("sora", "Sign", s)
    uy = baseline + s * 0.16
    p.draw_line(
        Point(x, uy),
        Point(x + (w1 + w2) * 0.74, uy),
        color=accent,
        width=max(0.7, s * 0.045),
    )


def _draw_fingerprint(p, cx, cy, r, stroke) -> None:
    p.fingerprint(cx, cy, r, stroke)


def _draw_globe(p, cx, cy, r, color, width=0.9) -> None:
    p.draw_oval(Rect(cx - r, cy - r, cx + r, cy + r), color=color, width=width)
    p.draw_line(Point(cx - r, cy), Point(cx + r, cy), color=color, width=width)
    p.draw_oval(Rect(cx - r, cy - r * 0.42, cx + r, cy + r * 0.42), color=color, width=width * 0.85)
    p.draw_oval(Rect(cx - r * 0.5, cy - r, cx + r * 0.5, cy + r), color=color, width=width * 0.85)
    p.draw_oval(Rect(cx - r * 0.85, cy - r, cx + r * 0.85, cy + r), color=color, width=width * 0.7)


def _glow(p) -> None:
    for cx, cy, r, op in ((_W - 24, 30, 170, 0.05), (36, _H - 16, 190, 0.04)):
        p.draw_circle(Point(cx, cy), r, color=None, fill=_ACCENT, fill_opacity=op)


def _watermark(p) -> None:
    txt, fs = "LiftedSign", 76
    w = _tw("sora", txt, fs)
    a = math.radians(27)
    pivot = Point(_W / 2, _H / 2 + 30)
    mat = Matrix(math.cos(a), math.sin(a), -math.sin(a), math.cos(a), 0, 0)
    p.insert_text(
        (_W / 2 - w / 2, _H / 2 + 50),
        txt,
        fontsize=fs,
        color=_ACCENT,
        fontname=_bf("sora"),
        morph=(pivot, mat),
        fill_opacity=0.05,
    )


def _vcheck(p, x, y_baseline, s=9.0, color=None):
    col = color if color is not None else _ACCENT
    h = s * 0.66
    x0 = x
    top = y_baseline - h
    short = h * 0.42
    p1 = Point(x0, y_baseline - h * 0.42)
    p2 = Point(x0 + short, y_baseline)
    p3 = Point(x0 + h * 0.95, top)
    w = max(0.9, s * 0.10)
    p.draw_line(p1, p2, color=col, width=w, lineCap=1)
    p.draw_line(p2, p3, color=col, width=w, lineCap=1)
    return h * 0.95 + s * 0.18


# ------------------------------------------------------------------------------------------
# The certificate
# ------------------------------------------------------------------------------------------
def make_certificate(
    agreement: dict,
    signers: list[dict],
    events: list[dict],
    doc_hash: str,
    signatures: dict | None = None,
    pages: int = 0,
    fields_n: int = 0,
    disclosure_text: str = "",
    disclosure_version: str = "",
    preseal_hash: str = "",
    sealed_hash: str = "",
    identity: dict | None = None,
    seal_method: str = "aes",
) -> bytes:
    """A branded LiftedSign **Certificate of Completion** — permissive (reportlab) rebuild of the
    original fitz renderer. Byte-for-byte content parity: envelope id, document hash chain
    (pre-seal → sealed), per-signer signature image + signature ID + IP + device + auth method +
    identity-verification evidence, the full §7001(c) e-consent record, the audit trail, the
    security/integrity section, the exact ERSD disclosure text, and the eIDAS SES positioning.
    The seal wording is method-aware (``seal_method``): PAdES/PKCS#7 when a certification signature
    was applied, else the AES-256 fallback seal. Multi-page with a repeating footer.

    SIGNATURE IS STABLE: every parameter past ``doc_hash`` is an optional, default-safe keyword.
    SECURITY: identity evidence renders TYPE/method/timestamp/masked-email only — never a DOB,
    SSN, access code, or OTP value (CERT-3/CERT-4).
    """
    signatures = signatures or {}
    identity = identity or {}
    # Operator identity for the certificate copy — env-derived (blank by default),
    # never a hardcoded company/email literal. Readable fallbacks keep legal text sane.
    _org = config.LEGAL_ENTITY or "the operator"
    _email = config.SUPPORT_EMAIL or config.MAIL_FROM or "the sender"
    _pades = (seal_method or "aes").lower() == "pades"
    env = agreement.get("envelope_id") or f"LS-{agreement.get('id', '')}"
    tz = datetime.datetime.now().astimezone().tzname() or "local"
    has_consumer = any(_truthy(s.get("is_consumer")) for s in signers)
    doc = _Canvas()
    state = {"doc": doc, "page": None, "y": 0, "n": 0}

    def new_page(first=False):
        p = doc.new_page(width=_W, height=_H)
        _reg_fonts(p)
        state["page"], state["n"] = p, state["n"] + 1
        p.draw_rect(p.rect, color=None, fill=_BG)
        _glow(p)
        _watermark(p)
        if first:
            HB = 150
            p.draw_rect(Rect(0, 0, _W, HB), color=None, fill=_HERO)
            p.draw_rect(Rect(0, HB - 34, _W, HB), color=None, fill=_HERO2)
            p.draw_circle(Point(_W - 70, 20), 150, color=None, fill=_ACCENT_HERO, fill_opacity=0.07)
            _draw_globe(p, _M + 11, 34, 11, _ACCENT_HERO, 1.0)
            _draw_logo(p, _M + 32, 40, 15, ink=_ONHERO, accent=_ACCENT_HERO)
            p.insert_text(
                (_M, 90),
                "Certificate of Completion",
                fontsize=22,
                color=_ONHERO,
                fontname=_bf("sorax"),
            )
            p.insert_text(
                (_M, 108),
                "Electronic record & signature audit",
                fontsize=8.5,
                color=_ONHERO2,
                fontname=_bf("inter"),
            )
            fc = Point(_W - _M - 30, 56)
            p.draw_circle(fc, 31, color=None, fill=(0.06, 0.11, 0.15))
            p.draw_circle(fc, 31, color=_ACCENT_HERO, width=1.1)
            _draw_fingerprint(p, fc.x, fc.y, 19, "#5AA6FF")
            sl = "SEALED"
            p.insert_text(
                (fc.x - _tw("interb", sl, 6.5) / 2, fc.y + 47),
                sl,
                fontsize=6.5,
                color=_ACCENT_HERO,
                fontname=_bf("interb"),
            )
            rx = _W - _M - 232
            p.insert_text(
                (rx, 96), "ENVELOPE ID", fontsize=7, color=_ONHERO2, fontname=_bf("interb")
            )
            es = 12.5
            while es > 8 and _tw("mono", env, es) > 168:
                es -= 0.5
            p.insert_text((rx, 110), env, fontsize=es, color=_ONHERO, fontname=_bf("mono"))
            sx = rx + _vcheck(p, rx, 124, s=7.5, color=_ACCENT_HERO)
            p.insert_text(
                (sx, 124),
                "Certified · PAdES PKCS#7 · SHA-256"
                if _pades
                else "Tamper-evident · SHA-256 + AES-256",
                fontsize=7.5,
                color=_ACCENT_HERO,
                fontname=_bf("interb"),
            )
            p.draw_rect(Rect(0, HB, _W, HB + 2.4), color=None, fill=_ACCENT)
            state["y"] = HB + 30
        else:
            p.draw_rect(Rect(0, 0, _W, 3), color=None, fill=_ACCENT)
            _draw_logo(p, _M, 48, 12.5)
            p.insert_text(
                (_M + 78, 48),
                "· Certificate of Completion",
                fontsize=10,
                color=_GREY,
                fontname=_bf("sora"),
            )
            p.insert_text(
                (_W - _M - 150, 48),
                f"Envelope {env}",
                fontsize=8,
                color=_GREY,
                fontname=_bf("mono"),
            )
            p.draw_line(Point(_M, 60), Point(_W - _M, 60), color=_LINE, width=0.6)
            state["y"] = 84
        return p

    def ensure(space):
        if state["y"] + space > _H - 56:
            new_page()

    def heading(txt, sub=""):
        ensure(38)
        p = state["page"]
        p.insert_text((_M, state["y"]), txt, fontsize=11, color=_ACCENT, fontname=_bf("sora"))
        if sub:
            w = _tw("sora", txt, 11)
            p.insert_text(
                (_M + w + 8, state["y"]),
                "· " + sub,
                fontsize=8.5,
                color=_GREY,
                fontname=_bf("inter"),
            )
        p.draw_line(
            Point(_M, state["y"] + 6), Point(_W - _M, state["y"] + 6), color=_ACCENT, width=1.1
        )
        state["y"] += 24

    def kv(label, value, x, w):
        p = state["page"]
        p.insert_text((x, state["y"]), label.upper(), fontsize=7, color=_GREY, fontname=_bf("sora"))
        p.insert_textbox(
            Rect(x, state["y"] + 4, x + w, state["y"] + 40),
            str(value),
            fontsize=9.5,
            color=_INK,
            fontname=_bf("inter"),
        )

    def text(txt, size=9.5, color=_INK, font="helv", dy=14, x=_M):
        state["page"].insert_text((x, state["y"]), txt, fontsize=size, color=color, fontname=font)
        state["y"] += dy

    new_page(first=True)
    col2 = _W / 2 + 10

    # --- summary grid -------------------------------------------------------------
    heading("DOCUMENT SUMMARY")
    kv("Document", agreement.get("name", "—"), _M, 240)
    kv("Status", str(agreement.get("status", "")).upper() or "—", col2, 200)
    state["y"] += 34
    kv("Pages", pages or "—", _M, 100)
    kv("Signers / Fields", f"{len(signers)} / {fields_n or 0}", _M + 130, 140)
    kv("Time zone", tz, col2, 200)
    state["y"] += 34
    _sender = (
        " · ".join(x for x in (config.LEGAL_ENTITY, config.SUPPORT_EMAIL or config.MAIL_FROM) if x)
        or "—"
    )
    kv("Sender (Holder of record)", _sender, _M, 300)
    kv("Issued by", "LiftedSign", col2, 200)
    state["y"] += 34
    kv("Document SHA-256 (executed)", doc_hash or "—", _M, _W - 2 * _M)
    state["y"] += 32

    # --- signers ------------------------------------------------------------------
    heading("SIGNERS", "identity verification · authentication · consent")
    for s in signers:
        consumer = _truthy(s.get("is_consumer"))
        rx = col2
        auth = _AUTH_LABELS.get((s.get("auth_method") or "email").lower(), _AUTH_LABELS["email"])
        det = [
            ("Signature ID", s.get("signature_id") or "—"),
            ("Authentication", auth),
            ("IP address", s.get("ip") or "—"),
            ("Device", _friendly_ua(s.get("user_agent") or "")),
        ]
        for lab, val in _identity_evidence(s, events, identity.get(s.get("id"))):
            det.append((lab, val))
        dv = s.get("disclosure_version") or disclosure_version
        if s.get("consent_at"):
            det.append(("Consent", f"Accepted ERSD {dv}".strip() if dv else "Accepted ERSD"))
            det.append(("Consent at", _fmt(s.get("consent_at"))))
        elif _truthy(s.get("consent")):
            det.append(("Consent", f"Accepted ERSD {dv}".strip() if dv else "Accepted ESIGN/UETA"))
        else:
            det.append(("Consent", "Not recorded"))
        if s.get("consent_ip"):
            det.append(("Consent IP", str(s.get("consent_ip"))))
        dh = s.get("disclosure_text_hash") or ""
        if dh:
            det.append(("Disclosure hash", dh[:16] + "…"))
        if consumer and _truthy(s.get("access_demonstrated")):
            det.append(("Access shown", _access_label(s.get("access_method"))))
        if s.get("consent_withdrawn_at"):
            det.append(("Consent withdrawn", _fmt(s.get("consent_withdrawn_at"))))

        affirm = _signer_affirmation(s, consumer, dv, auth, tz)
        aw = _W - 2 * _M - 14
        affirm_lines = _wrap_lines(affirm, aw, size=7.2, font="helv")
        band_h = 14 + len(affirm_lines) * 9.6

        factor = _challenge_factor(s, events, identity.get(s.get("id")))
        fb_h = 26 if factor else 0

        body_h = max(86, 18 + len(det) * 12.5)
        card_h = body_h + fb_h + band_h
        ensure(card_h + 24)
        p = state["page"]
        top = state["y"]
        p.draw_rect(
            Rect(_M - 6, top - 6, _W - _M + 6, top + card_h), color=_LINE, fill=_TINT, radius=0.04
        )
        p.draw_rect(Rect(_M - 6, top - 6, _M - 2, top + card_h), color=None, fill=_ACCENT)
        nm = s.get("name", "") or "—"
        p.insert_text((_M + 6, top + 13), nm, fontsize=11.5, color=_INK, fontname=_bf("sora"))
        if consumer:
            nw = _tw("sora", nm, 11.5)
            p.draw_rect(
                Rect(_M + 9 + nw, top + 4, _M + 9 + nw + 54, top + 15),
                color=None,
                fill=(0.90, 0.94, 1.0),
                radius=0.45,
            )
            p.insert_text(
                (_M + 14 + nw, top + 12.5),
                "CONSUMER",
                fontsize=6.2,
                color=_ACCENT_DK,
                fontname=_bf("sora"),
            )
        p.insert_text((_M + 6, top + 27), f"{s.get('email', '')}", fontsize=9, color=_GREY)
        st = (s.get("status") or "").upper()
        signed_ok = st in ("SIGNED", "COMPLETED")
        stc = _ACCENT if signed_ok else (_RED if st == "DECLINED" else _GREY)
        stx = _M + 6
        if signed_ok:
            stx += _vcheck(p, _M + 6, top + 43, s=9.0, color=stc)
        p.insert_text((stx, top + 43), (st or "—"), fontsize=9, color=stc, fontname=_bf("sora"))
        img = _png_from_data_url((signatures.get(s.get("id")) or ""))
        if img:
            p.draw_rect(
                Rect(_M + 6, top + 51, _M + 204, top + 83), color=_LINE, fill=(1, 1, 1), radius=0.06
            )
            p.insert_image(
                Rect(_M + 10, top + 53, _M + 200, top + 81), stream=img, keep_proportion=True
            )
        else:
            p.insert_text(
                (_M + 6, top + 65), "Signature captured electronically", fontsize=8, color=_GREY2
            )
        dy = top + 9
        for lab, val in det:
            p.insert_text(
                (rx, dy), lab.upper() + ":", fontsize=6.8, color=_GREY, fontname=_bf("sora")
            )
            p.insert_text((rx + 88, dy), str(val), fontsize=8, color=_INK)
            dy += 12.5
        if factor:
            fy = top + body_h
            p.draw_rect(Rect(_M - 6, fy, _W - _M + 6, fy + fb_h), color=None, fill=_TINT2)
            p.draw_rect(Rect(_M - 6, fy, _M - 2, fy + fb_h), color=None, fill=_ACCENT)
            _draw_fingerprint(p, _M + 13, fy + fb_h / 2, 8.5, "#1B54C7")
            p.insert_text(
                (_M + 28, fy + 11),
                "ADDITIONAL VERIFICATION FACTOR",
                fontsize=6.6,
                color=_ACCENT_DK,
                fontname=_bf("sora"),
            )
            p.insert_text(
                (_M + 28, fy + 21), factor, fontsize=8.2, color=_INK, fontname=_bf("interb")
            )
            lk = "SENDER-LOCKED"
            p.insert_text(
                (_W - _M - _tw("interb", lk, 6.4) - 2, fy + 16),
                lk,
                fontsize=6.4,
                color=_ACCENT_DK,
                fontname=_bf("interb"),
            )
        by = top + body_h + fb_h
        p.draw_line(Point(_M - 2, by), Point(_W - _M + 6, by), color=_LINE, width=0.5)
        p.insert_text(
            (_M + 6, by + 11),
            "CONSENT & INTENT",
            fontsize=6.4,
            color=_ACCENT_DK,
            fontname=_bf("sora"),
        )
        ay = by + 21
        for ln in affirm_lines:
            p.insert_text((_M + 6, ay), ln, fontsize=7.2, color=_GREY, fontname=_bf("inter"))
            ay += 9.6
        state["y"] = top + card_h + 6
        ts = []
        if s.get("viewed_at"):
            ts.append(f"opened {_fmt(s['viewed_at'])}")
        if s.get("consent_at"):
            ts.append(f"consented {_fmt(s['consent_at'])}")
        elif _truthy(s.get("consent")) and s.get("signed_at"):
            ts.append(f"consented {_fmt(s['signed_at'])}")
        if s.get("signed_at"):
            ts.append(f"signed {_fmt(s['signed_at'])}")
        if ts:
            text("    " + "   ·   ".join(ts), 8, _GREY, dy=18)
        else:
            state["y"] += 6

    # --- record tracking / audit trail -------------------------------------------
    state["y"] += 6
    heading("RECORD TRACKING", "audit trail · server time")
    _T1, _T2 = _M + 142, _M + 304

    def audit_header():
        p = state["page"]
        p.draw_rect(
            Rect(_M - 4, state["y"] - 9, _W - _M + 4, state["y"] + 4), color=None, fill=_TINT
        )
        p.insert_text(
            (_M, state["y"]),
            "TIMESTAMP (" + tz + ")",
            fontsize=6.6,
            color=_GREY,
            fontname=_bf("sora"),
        )
        p.insert_text((_T1, state["y"]), "EVENT", fontsize=6.6, color=_GREY, fontname=_bf("sora"))
        p.insert_text(
            (_T2, state["y"]),
            "ACTOR / IP / DEVICE",
            fontsize=6.6,
            color=_GREY,
            fontname=_bf("sora"),
        )
        state["y"] += 4
        p.draw_line(
            Point(_M - 4, state["y"]), Point(_W - _M + 4, state["y"]), color=_LINE, width=0.6
        )
        state["y"] += 12

    audit_header()
    zebra = False
    for e in events:
        det = []
        if e.get("ip"):
            det.append(f"IP {e['ip']}")
        if e.get("user_agent"):
            det.append(_friendly_ua(e["user_agent"]))
        if e.get("detail"):
            det.append(str(e["detail"])[:74])
        row_h = 11 + (11 if det else 0)
        if state["y"] + row_h > _H - 56:
            new_page()
            audit_header()
            zebra = False
        p = state["page"]
        zebra = not zebra
        if zebra:
            p.draw_rect(
                Rect(_M - 4, state["y"] - 8.5, _W - _M + 4, state["y"] + row_h - 7),
                color=None,
                fill=_ZEBRA,
            )
        who = e.get("signer_email") or "system"
        p.insert_text(
            (_M, state["y"]), _fmt(e.get("at")), fontsize=7.6, color=_INK, fontname=_bf("mono")
        )
        p.insert_text(
            (_T1, state["y"]),
            _event_label(e.get("type", ""))[:32],
            fontsize=7.8,
            color=_INK,
            fontname=_bf("sora"),
        )
        p.insert_text((_T2, state["y"]), str(who)[:36], fontsize=7.8, color=_INK)
        state["y"] += 11
        if det:
            p.insert_text((_T1, state["y"]), ("  ·  ".join(det))[:96], fontsize=6.8, color=_GREY)
            state["y"] += 11

    # --- security & integrity -----------------------------------------------------
    state["y"] += 12
    if state["y"] + 130 > _H - 56:
        new_page()
    heading("SECURITY & INTEGRITY")
    seal = [
        ("Hash algorithm", "SHA-256 (FIPS 180-4) over the executed PDF"),
        ("Document fingerprint", doc_hash or "—"),
    ]
    if preseal_hash:
        seal.append(("Pre-seal SHA-256", preseal_hash))
    if sealed_hash and not _pades:
        seal.append(("Sealed SHA-256", sealed_hash))
    if _pades:
        seal += [
            (
                "Seal method",
                "PAdES / PKCS#7 certification signature (DocMDP level 1 — no changes "
                "permitted after certification) + SHA-256 tamper-evident hash chain + flattened",
            ),
            (
                "Certification",
                f"Self-signed X.509 ({_org}); any change after certification "
                "invalidates the signature in every compliant PDF reader. The certificate is "
                f"not chained to a public CA — verifiers who add the {_org} certificate "
                "to their trust store see a fully-trusted status.",
            ),
        ]
    else:
        seal += [
            ("Seal method", "AES-256 encryption + SHA-256 tamper-evident hash chain + flattened"),
        ]
    seal += [
        (
            "Envelope binding",
            f"All signer actions recorded against envelope {env} in the audit trail",
        ),
        (
            "Access control",
            "Each signer reached the document only via a unique, single-use token link",
        ),
        (
            "Tamper evidence",
            "Any post-completion change to the document invalidates the hash above",
        ),
        ("Completed (sealed)", _fmt(datetime.datetime.now().timestamp()) + "  " + tz),
    ]
    seal_lx = _M + 138
    for lab, val in seal:
        is_hash = (
            bool(val) and val != "—" and ("SHA-256" in lab.upper() or "FINGERPRINT" in lab.upper())
        )
        vh = 16 if (is_hash and _tw("mono", str(val), 7.8) > _W - _M - seal_lx) else 13
        ensure(vh + 4)
        p = state["page"]
        p.insert_text(
            (_M, state["y"]), lab.upper(), fontsize=7, color=_ACCENT, fontname=_bf("sora")
        )
        p.insert_textbox(
            Rect(seal_lx, state["y"] - 7.5, _W - _M, state["y"] + vh + 2),
            str(val),
            fontsize=7.8 if is_hash else 8.3,
            color=_INK,
            fontname=_bf("mono") if is_hash else "helv",
        )
        state["y"] += vh

    # --- disclosure ---------------------------------------------------------------
    state["y"] += 12
    if state["y"] + 200 > _H - 56:
        new_page()
    heading(
        "ELECTRONIC RECORD AND SIGNATURE DISCLOSURE",
        (f"version {disclosure_version}" if disclosure_version else ""),
    )
    framing = (
        "Each party named above consented to conduct business electronically and to use electronic "
        "records and electronic signatures in connection with this transaction, in accordance with the "
        "U.S. ESIGN Act (15 U.S.C. ch. 96) and the Uniform Electronic Transactions Act (UETA). By "
        "selecting the consent option and applying their signature, each signer affirmed their intent to "
        "sign and agreed that their electronic signature is the legal equivalent of a handwritten "
        "signature. Identity was verified by email and a unique, single-use access link; the IP address, "
        "user agent, and timestamp of each action are recorded in the audit trail above. The SHA-256 "
        "document hash shown above allows any party to detect alteration of the executed document after "
        "completion. Under the EU eIDAS Regulation (910/2014) this constitutes a Simple Electronic "
        "Signature (SES); admissibility is supported by the audit trail and certificate. It is not a "
        "Qualified Electronic Signature (QES). This certificate, together with the executed document, "
        "constitutes the complete record of the transaction and is admissible as evidence. Issued and "
        f"secured by LiftedSign on behalf of {_org}."
    )
    if _pades:
        framing += (
            " This executed document is sealed with a PAdES certification (PKCS#7/CMS) "
            "signature at DocMDP level 1; any modification after certification invalidates "
            "the signature and is flagged by any compliant PDF reader (Adobe Acrobat, etc.). "
            f"The signing certificate is self-signed by {_org} (an SES-tier "
            "certification, as used by DocuSign and Dropbox Sign) and is not chained to a "
            "public Certificate Authority."
        )
    _flow_text(state, doc, new_page, framing, size=8.3, color=_GREY, lh=1.36)

    if has_consumer:
        state["y"] += 8
        ensure(20)
        state["page"].insert_text(
            (_M, state["y"]),
            "CONSUMER DISCLOSURE — ESIGN §7001(c) (five required elements)",
            fontsize=8.5,
            color=_ACCENT_DK,
            fontname=_bf("sora"),
        )
        state["y"] += 14

    body = (disclosure_text or "").strip()
    if not body:
        body = (
            "Paper copies. You have the right to receive this record on paper. To request a paper copy, "
            f"email {_email}; no fee is charged for the first copy.  "
            "Withdrawing consent. You may withdraw your consent to receive records electronically at any "
            f"time by emailing {_email} or using the withdraw link in your signing invitation; "
            "the consequence is that the transaction may instead be completed on paper.  "
            "Scope. Your consent applies to this transaction and its related records.  "
            "Updating contact information. To update the email address used for records, email "
            f"{_email}.  "
            "Hardware and software. A current web browser (Chrome, Edge, Safari, or Firefox), a PDF reader, "
            "internet access, an email account, and a device able to view and download files are required to "
            "access and retain these records."
        )
    _flow_text(state, doc, new_page, body, size=8.3, color=_INK, lh=1.36)
    if disclosure_version:
        state["y"] += 6
        ensure(14)
        h = disclosure_text and sha256(disclosure_text.encode("utf-8")) or ""
        line = f"Disclosure version {disclosure_version}" + (f" · hash {h[:16]}…" if h else "")
        state["page"].insert_text(
            (_M, state["y"]), line, fontsize=7.5, color=_GREY2, fontname=_bf("mono")
        )
        state["y"] += 12

    return doc.render(env)


def _flow_text(state, doc, new_page, txt, size=8.3, color=_GREY, lh=1.35) -> None:
    """Pour a paragraph into the running column, spilling to a new page when it overflows the footer."""
    p = state["page"]
    width = _W - 2 * _M
    line_h = size * lh
    words = (txt or "").split()
    line = ""
    while words:
        test = (line + " " + words[0]).strip()
        if _tw("helv", test, size) <= width:
            line = test
            words.pop(0)
            continue
        if not line:
            line = words.pop(0)
        if state["y"] + line_h > _H - 56:
            new_page()
            p = state["page"]
        p.insert_text((_M, state["y"]), line, fontsize=size, color=color, fontname="helv")
        state["y"] += line_h
        line = ""
    if line:
        if state["y"] + line_h > _H - 56:
            new_page()
            p = state["page"]
        p.insert_text((_M, state["y"]), line, fontsize=size, color=color, fontname="helv")
        state["y"] += line_h


# ------------------------------------------------------------------------------------------
# Post-ops: sanitize / secure (pikepdf) · append (pypdf)
# ------------------------------------------------------------------------------------------
def _scrub(pdf: pikepdf.Pdf) -> None:
    """Strip hidden data / stale metadata / embedded JS / auto-actions (replaces doc.scrub())."""
    try:
        pdf.remove_unreferenced_resources()
    except Exception:  # noqa: BLE001
        pass
    root = pdf.Root
    for key in ("/OpenAction", "/AA", "/AcroForm"):
        try:
            if key in root:
                del root[key]
        except Exception:  # noqa: BLE001
            pass
    # document-level JavaScript name tree
    try:
        names = root.get("/Names")
        if names is not None and "/JavaScript" in names:
            del names["/JavaScript"]
    except Exception:  # noqa: BLE001
        pass
    # XMP metadata stream
    try:
        if "/Metadata" in root:
            del root["/Metadata"]
    except Exception:  # noqa: BLE001
        pass
    # docinfo dictionary (Author/Producer/Title/…)
    try:
        del pdf.docinfo
    except Exception:  # noqa: BLE001
        try:
            pdf.docinfo = pikepdf.Dictionary()
        except Exception:  # noqa: BLE001
            pass


def sanitize_pdf(data: bytes) -> bytes:
    """The flatten/clean half of ``secure_pdf`` WITHOUT encryption: strip hidden data / stale
    metadata / embedded JS / dead objects, then a garbage-collected rewrite. Reused on the PAdES
    signing path where the signature MUST be the last byte op (no re-serialization after signing)."""
    with pikepdf.open(io.BytesIO(data)) as pdf:
        _scrub(pdf)
        out = io.BytesIO()
        pdf.save(
            out,
            compress_streams=True,
            object_stream_mode=pikepdf.ObjectStreamMode.generate,
        )
        return out.getvalue()


def secure_pdf(data: bytes) -> bytes:
    """Lock the executed copy: AES-256 encryption with a random owner password and an EMPTY user
    password — anyone can open/view/print, but modify/annotate/form-fill is disallowed (like a
    completed DocuSign PDF). Matches the original fitz behavior (open with empty user pw). The
    owner password is discarded (never persisted); the permission bits are advisory, the real lock
    is the PAdES certification signature when configured."""
    with pikepdf.open(io.BytesIO(data)) as pdf:
        _scrub(pdf)
        perms = pikepdf.Permissions(
            extract=True,
            print_highres=True,
            print_lowres=True,
            modify_annotation=False,
            modify_assembly=False,
            modify_form=False,
            modify_other=False,
        )
        enc = pikepdf.Encryption(user="", owner=_secrets.token_urlsafe(24), R=6, allow=perms)
        out = io.BytesIO()
        pdf.save(
            out,
            encryption=enc,
            compress_streams=True,
            object_stream_mode=pikepdf.ObjectStreamMode.generate,
        )
        return out.getvalue()


def append_pdf(base_data: bytes, extra_data: bytes) -> bytes:
    """Concatenate ``extra`` after ``base`` (e.g. cert pages onto the executed document)."""
    writer = pypdf.PdfWriter()
    for src in (base_data, extra_data):
        reader = pypdf.PdfReader(io.BytesIO(src))
        for page in reader.pages:
            writer.add_page(page)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()
