# `web/ds/fonts/` — frontend web font set

These TTFs are served over HTTP from the `/static` mount (`sign/app.py` mounts
`StaticFiles` over `web/`) and loaded by the browser via `@font-face`:

- [`web/ds/tokens/fonts.css`](../tokens/fonts.css) declares the design-system
  UI faces — **Inter**, **Sora**, and **JetBrains Mono** (`JBMono`).
- [`web/signapp.html`](../../signapp.html) additionally declares the six
  **metric-compatible substitute families** (Arimo, Tinos, Cousine, Carlito,
  Caladea, Gelasio) so the in-browser PDF editor renders a text preview in the
  *same* substitute the backend will embed on seal — WYSIWYG between the editor
  and the stamped PDF.

That is why this dir holds 30 files, not just the 3 UI families.

## Why this is a separate set from `sign/assets/fonts/`

There are two font consumers with different delivery mechanisms and different
completeness requirements, so the fonts live in two places on purpose:

| | `web/ds/fonts/` (this dir) | `sign/assets/fonts/` |
|---|---|---|
| Consumer | Browser (`@font-face`) | PDF engine (Python, server-side) |
| Delivery | HTTP via `/static/ds/fonts/` | filesystem read, packaged with `sign` |
| Set | subset (30 files) the browser fetches | **full** substitution set (77 files) |

Every file here is **byte-identical** to its namesake in `sign/assets/fonts/`
(verified by sha256) — this dir is a strict subset. The backend set is larger
because `sign/fontmap.py` also carries document families the browser never needs
(Roboto, Lato, Open Sans, Montserrat, Source Sans 3, Poppins, Merriweather,
Nunito Sans, Raleway, PT Sans/Serif, DroidSansFallback).

The two copies are **not** merged to one file / symlink because the consumers
need them at different paths (an HTTP `/static` URL vs a Python-package-relative
filesystem path), symlinks aren't portable across the Windows-dev / Linux-prod
split, and the overlap is only ~1.0 MB. See
[`sign/assets/fonts/README.md`](../../../sign/assets/fonts/README.md) for the
backend side.

If you add a family to the browser preview, add it to **both** dirs.
