# `sign/assets/fonts/` — backend PDF-embed font set

These TTFs are read **from the filesystem** by the PDF engine
([`sign/fontmap.py`](../../fontmap.py), used by `pdf_edit`) to embed glyphs when
stamping or editing text into a PDF. They are loaded as `bytes` via
`pathlib.Path.read_bytes()` (`_DIR = <this package>/assets/fonts`) — they are
**never served over HTTP**. The `/static` mount in `sign/app.py` covers `web/`
only; it does not expose this directory.

## Why this is a separate set from `web/ds/fonts/`

There are two font consumers in this repo with different delivery mechanisms and
different completeness requirements — so the fonts live in two places on purpose:

| | `sign/assets/fonts/` (this dir) | `web/ds/fonts/` |
|---|---|---|
| Consumer | PDF engine (Python, server-side) | Browser (`@font-face`) |
| Delivery | filesystem read, packaged with the `sign` package | HTTP via `/static/ds/fonts/` |
| Set | **full** substitution set (77 files) | subset (30 files) it actually fetches |

This set is the larger of the two: besides the design-system faces
(Inter / Sora / JetBrains Mono) and the metric-compatible office substitutes
(Arimo≈Arial, Tinos≈Times, Cousine≈Courier, Carlito≈Calibri, Caladea≈Cambria,
Gelasio≈Georgia), it also carries ~11 popular document families (Roboto, Lato,
Open Sans, Montserrat, Source Sans 3, Poppins, Merriweather, Nunito Sans,
Raleway, PT Sans/Serif) plus `DroidSansFallback` for CJK fallback. `fontmap.py`
needs all of these to pick a full-coverage substitute for whatever font an
uploaded PDF happens to use; the browser never needs the document-only families,
so they are not duplicated into `web/ds/fonts/`.

## Relationship to the web copy

Every file in `web/ds/fonts/` is **byte-identical** to its namesake here (verified
by sha256), so the web dir is a strict subset. They are **not** deduplicated to a
single copy or symlink because:

- The two consumers require the files at **different paths** — one a packaged
  Python asset resolved relative to `sign/__file__`, the other an HTTP URL under
  `/static`. The `sign` package is designed to be embeddable standalone (see
  [`sign/__init__.py`](../../__init__.py)); its PDF fonts must travel with the
  package regardless of whether any web static mount exists.
- Symlinks are not portable across the Windows-dev / Linux-prod split or through
  git checkouts.
- The overlap is only ~1.0 MB (30 files); coupling the web static layer to the
  Python package's internal asset path to save it is not a good trade.

If you add a family to the browser preview, add it to **both** dirs (and to
`_FAMILIES`/`_SUBSTITUTE` in `fontmap.py`).
