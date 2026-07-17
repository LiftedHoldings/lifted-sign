"""Font resolver for in-place PDF text editing (Tier 1).

When you edit text on an uploaded PDF, the original font is usually embedded only as a
SUBSET (just the glyphs already used), so any NEW character you type isn't covered and the
old code fell back to base-14 Helvetica — which visibly doesn't match. This resolver maps the
original font NAME (+ style flags) to a bundled, FULL-coverage substitute we ship.

Resolution order (best -> fallback), used by pdf_edit.apply_edits:
  1. (caller) reuse the document's OWN embedded font if it covers the new glyphs (truest match).
  2. resolve() -> a bundled substitute, preferring a METRIC-COMPATIBLE one:
       Arimo≈Arial/Helvetica, Tinos≈Times, Cousine≈Courier, Carlito≈Calibri,
       Caladea≈Cambria, Gelasio≈Georgia. These share advance widths with the originals, so
       replaced text keeps the SAME width — no reflow, no scaling needed.
  3. classify serif/sans/mono + weight/style and pick a generic bundled family.
Plus ~11 popular web fonts (Roboto, Lato, Open Sans, Montserrat, Source Sans 3, Poppins,
Merriweather, Nunito Sans, Raleway, PT Sans/Serif) for modern documents, and the brand
faces (Sora, Inter, JetBrains Mono). All latin subsets, bundled in assets/fonts/.
"""

from __future__ import annotations

import logging
import pathlib
import re


_log = logging.getLogger(__name__)

_DIR = pathlib.Path(__file__).parent / "assets" / "fonts"
if not _DIR.is_dir():
    # One-time signal at import: without the bundled fonts, resolve() can't substitute and
    # edited text silently degrades to base-14 (visible mismatch). Warn once, not per call.
    _log.warning(
        "fontmap: bundled fonts dir missing (%s); edited PDF text will fall back to base-14",
        _DIR,
    )

# family-key -> {(bold:int, italic:int): filename}
_FAMILIES: dict[str, dict[tuple[int, int], str]] = {}


def _f4(base: str) -> dict[tuple[int, int], str]:
    """A full regular/bold/italic/bold-italic set named '<base>-400/700[i].ttf'."""
    return {
        (0, 0): f"{base}-400.ttf",
        (1, 0): f"{base}-700.ttf",
        (0, 1): f"{base}-400i.ttf",
        (1, 1): f"{base}-700i.ttf",
    }


for _b in (
    "Arimo",
    "Tinos",
    "Cousine",
    "Carlito",
    "Caladea",
    "Gelasio",
    "Roboto",
    "Lato",
    "OpenSans",
    "Montserrat",
    "SourceSans3",
    "Poppins",
    "Merriweather",
    "NunitoSans",
    "Raleway",
    "PTSans",
    "PTSerif",
):
    _FAMILIES[_b.lower()] = _f4(_b)
# brand faces (no bundled italic -> reuse upright; bold uses the heavier weight)
_FAMILIES["sora"] = {
    (0, 0): "Sora-400.ttf",
    (1, 0): "Sora-700.ttf",
    (0, 1): "Sora-400.ttf",
    (1, 1): "Sora-700.ttf",
}
_FAMILIES["inter"] = {
    (0, 0): "Inter-400.ttf",
    (1, 0): "Inter-600.ttf",
    (0, 1): "Inter-400.ttf",
    (1, 1): "Inter-600.ttf",
}
_FAMILIES["jbmono"] = {k: "JBMono-400.ttf" for k in ((0, 0), (1, 0), (0, 1), (1, 1))}

# families whose metrics match a base-14 / office original (so widths match with no scaling)
_METRIC = {"arimo", "tinos", "cousine", "carlito", "caladea", "gelasio"}

_SERIF = {"tinos", "caladea", "gelasio", "merriweather", "ptserif"}
_MONO = {"cousine", "jbmono"}

# normalized original family name -> our family key
_SUBSTITUTE = {
    # metric-compatible mappings (the dominant office/contract fonts)
    "arial": "arimo",
    "helvetica": "arimo",
    "helveticaneue": "arimo",
    "arimo": "arimo",
    "liberationsans": "arimo",
    "segoeui": "arimo",
    "segoe": "arimo",
    "verdana": "arimo",
    "tahoma": "arimo",
    "trebuchet": "arimo",
    "trebuchetms": "arimo",
    "dejavusans": "arimo",
    "franklingothic": "arimo",
    "calibrilight": "carlito",
    "timesnewroman": "tinos",
    "times": "tinos",
    "liberationserif": "tinos",
    "tinos": "tinos",
    "couriernew": "cousine",
    "courier": "cousine",
    "consolas": "cousine",
    "monaco": "cousine",
    "liberationmono": "cousine",
    "cousine": "cousine",
    "menlo": "jbmono",
    "jetbrainsmono": "jbmono",
    "calibri": "carlito",
    "carlito": "carlito",
    "cambria": "caladea",
    "caladea": "caladea",
    "cambriamath": "caladea",
    "georgia": "gelasio",
    "gelasio": "gelasio",
    "garamond": "ptserif",
    "minion": "ptserif",
    "book": "ptserif",
    "bookantiqua": "ptserif",
    # popular web/brand fonts
    "roboto": "roboto",
    "lato": "lato",
    "opensans": "opensans",
    "montserrat": "montserrat",
    "sourcesanspro": "sourcesans3",
    "sourcesans": "sourcesans3",
    "sourcesans3": "sourcesans3",
    "poppins": "poppins",
    "merriweather": "merriweather",
    "nunitosans": "nunitosans",
    "nunito": "nunitosans",
    "raleway": "raleway",
    "ptsans": "ptsans",
    "ptserif": "ptserif",
    "sora": "sora",
    "inter": "inter",
    "lato2": "lato",
}

_GENERIC = {"serif": "tinos", "sans": "arimo", "mono": "cousine"}

_STYLE_WORDS = (
    "thin",
    "extralight",
    "ultralight",
    "light",
    "regular",
    "normal",
    "book",
    "medium",
    "semibold",
    "demibold",
    "demi",
    "bold",
    "extrabold",
    "ultrabold",
    "black",
    "heavy",
    "italic",
    "oblique",
    "condensed",
    "cond",
    "narrow",
    "expanded",
    "roman",
    "mt",
    "ps",
)
_STYLE_RE = re.compile(r"\b(" + "|".join(_STYLE_WORDS) + r")\b", re.I)

# buffer cache keyed by filename; font cache keyed by that SAME stable filename key
# (NOT id(buf) — object identity can be reused by GC for a transient buffer and return
# the wrong cached Font).
_buf_cache: dict[str, bytes | None] = {}
# Per-font metrics for width + coverage, keyed by the STABLE filename key. Replaces fitz.Font
# (AGPL). fontTools reproduces fitz.text_length to 0.000pt (verified) via hmtx advance widths.
_metric_cache: dict[str, tuple] = {}  # key -> (unitsPerEm, cmap, hmtx_metrics, notdef_adv)


def _norm(name: str) -> str:
    n = (name or "").split("+")[-1]  # strip subset prefix (BCDEEE+Calibri -> Calibri)
    n = _STYLE_RE.sub("", n)  # drop weight/style words
    return re.sub(r"[^a-z0-9]", "", n.lower())


def _classify(norm_name: str) -> str:
    if any(
        k in norm_name
        for k in (
            "times",
            "serif",
            "georgia",
            "roman",
            "garamond",
            "minion",
            "merri",
            "cambria",
            "caladea",
            "gelasio",
            "ptserif",
            "book",
            "antiqua",
        )
    ):
        return "serif"
    if any(
        k in norm_name
        for k in (
            "courier",
            "mono",
            "consol",
            "cousine",
            "jetbrains",
            "menlo",
            "monaco",
        )
    ):
        return "mono"
    return "sans"


def _load(filename: str | None) -> bytes | None:
    if not filename:
        return None
    if filename in _buf_cache:
        return _buf_cache[filename]
    try:
        b: bytes | None = (_DIR / filename).read_bytes()
    except Exception:
        b = None
    _buf_cache[filename] = b
    return b


def _metrics(key: str | None, buf: bytes) -> tuple:
    """(unitsPerEm, cmap, hmtx_metrics, notdef_advance) for a font, cached by the stable filename
    key. Parses with fontTools (permissive) — no fitz. Uncached (key None) parses each call."""
    if key is not None and key in _metric_cache:
        return _metric_cache[key]
    import io

    from fontTools.ttLib import TTFont

    tt = TTFont(io.BytesIO(buf), lazy=True)
    upm = tt["head"].unitsPerEm or 1000
    cmap = tt.getBestCmap() or {}
    metrics = tt["hmtx"].metrics
    notdef = metrics.get(".notdef", (upm // 2, 0))[0]
    out = (upm, cmap, metrics, notdef)
    if key is not None:
        _metric_cache[key] = out
    return out


def _covers(key: str, buf: bytes, text: str) -> bool:
    """True if the font has glyphs for every non-space char in `text` (fail-open on error)."""
    if not text:
        return True
    try:
        _, cmap, _, _ = _metrics(key, buf)
        return all(ord(c) in cmap for c in text if c.strip())
    except Exception:
        return True


def _family_key(name: str, flags: int = 0) -> str:
    n = _norm(name)
    if n in _SUBSTITUTE:
        return _SUBSTITUTE[n]
    for k, fam in _SUBSTITUTE.items():  # contains-match (e.g. ArialNarrow -> arial)
        if len(k) >= 4 and k in n:
            return fam
    # Generic (no named match): classify by name, but let the get_text serif/mono flag
    # bits decide when the name itself is non-committal — same flags _match_font uses
    # (pdf_edit.py: serif=flags&4, mono=flags&8). Avoids misclassifying a serif/mono
    # generic font as sans.
    cls = _classify(n)
    if cls == "sans":
        if flags & 8:
            cls = "mono"
        elif flags & 4:
            cls = "serif"
    return _GENERIC[cls]


def resolve(name: str = "", flags: int = 0, text: str = "") -> tuple[bytes | None, str, bool]:
    """Return (font_buffer, family_key, metric_compatible) for the requested original font.

    The caller embeds `font_buffer` (None -> fall back to base-14). `metric_compatible` is True
    when the substitute shares advance widths with the original (so no width-fit needed).
    Picks the right weight/italic with graceful fallback (BI -> B -> I -> R)."""
    raw = (name or "").lower()
    bold = bool(flags & 16) or any(
        k in raw for k in ("bold", "black", "heavy", "semibold", "demibold")
    )
    italic = bool(flags & 2) or any(k in raw for k in ("italic", "oblique"))
    key = _family_key(name, flags)
    fam = _FAMILIES.get(key) or _FAMILIES[_GENERIC[_classify(_norm(name))]]
    for bi in ((int(bold), int(italic)), (int(bold), 0), (0, int(italic)), (0, 0)):
        fn = fam.get(bi)
        buf = _load(fn)
        if buf and _covers(fn, buf, text):
            return buf, key, (key in _METRIC)
    # last resort: a generic of the right class, regular
    gkey = _family_key(name, flags)
    buf = _load(_FAMILIES[gkey].get((0, 0)))
    return (buf, gkey, gkey in _METRIC) if buf else (None, key, False)


def text_width(buf: bytes, text: str, size: float) -> float:
    """Sum of glyph advance widths for `text` at `size` pt. Matches fitz.text_length to 0.000pt
    (verified) — advance widths from the hmtx table, scaled by size/unitsPerEm."""
    # Reuse the cached metrics under the buffer's STABLE filename key when this is one of our
    # cached buffers (identity-match against the live buffer cache, so no GC id() reuse risk).
    key = next((fn for fn, b in _buf_cache.items() if b is buf), None)
    upm, cmap, metrics, notdef = _metrics(key, buf)
    total = 0.0
    for c in text:
        gn = cmap.get(ord(c))
        total += metrics[gn][0] if (gn and gn in metrics) else notdef
    return total * size / upm
