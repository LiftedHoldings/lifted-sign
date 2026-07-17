"""Permissive-license PDF page operations for Lifted Sign.

Engine: pikepdf (MPL-2.0) as the primary, single dependency surface — with pypdf
(BSD) available as a fallback in the environment. Deliberately fitz/PyMuPDF-FREE
(PyMuPDF is AGPL) so these building-block operations can ship without an AGPL
obligation. The richer render/edit/redact path stays in server/pdf_edit.py.

Contract shared by every public function:
  • all page indices are 0-based,
  • functions are pure — bytes -> bytes (or -> list[bytes] / -> int) — with no
    hidden global state,
  • output is deterministic: Pdf.save(..., deterministic_id=True) and no wall-clock
    timestamps are written, so the same input always yields byte-identical output.

Part of the Lifted Sign PDF engine.
"""

from __future__ import annotations

import io

import pikepdf
from pikepdf import Encryption, Pdf, Permissions

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _open(data: bytes) -> Pdf:
    """Open PDF bytes, raising a clean ValueError on anything malformed."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    if not data:
        raise ValueError("invalid PDF")
    try:
        return Pdf.open(io.BytesIO(bytes(data)))
    except pikepdf.PdfError as exc:  # noqa: TRY003 - narrow, intentional
        raise ValueError("invalid PDF") from exc


def _new() -> Pdf:
    return Pdf.new()


def _to_bytes(pdf: Pdf, **save_kw) -> bytes:
    """Serialize a Pdf to bytes.

    Non-encrypted saves are made byte-reproducible via deterministic_id=True.
    Encrypted saves CANNOT be deterministic: QPDFWriter refuses deterministic_id
    when encrypting, and AES encryption derives a fresh random file key each save,
    so encrypt() output is intentionally non-reproducible (correct crypto behavior).
    """
    if "encryption" not in save_kw:
        save_kw.setdefault("deterministic_id", True)
    buf = io.BytesIO()
    pdf.save(buf, **save_kw)
    return buf.getvalue()


def _validate_index(i: object, n: int) -> int:
    """Coerce and bounds-check a 0-based page index against page count n."""
    try:
        idx = int(i)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"page index must be an integer, got {i!r}") from exc
    if not (0 <= idx < n):
        raise IndexError(f"page index {idx} out of range for {n}-page document")
    return idx


# Permission profile mirrored from server/pdf_edit.py secure_pdf(): open/view/print/
# copy allowed, all modification disallowed.
def _seal_permissions() -> Permissions:
    return Permissions(
        extract=True,
        print_highres=True,
        print_lowres=True,
        modify_annotation=False,
        modify_form=False,
        modify_other=False,
        modify_assembly=False,
    )


# ---------------------------------------------------------------------------
# Public operations
# ---------------------------------------------------------------------------


def page_count(data: bytes) -> int:
    """Return the number of pages in a PDF."""
    pdf = _open(data)
    try:
        return len(pdf.pages)
    finally:
        pdf.close()


def merge(pdfs: list[bytes]) -> bytes:
    """Concatenate multiple PDFs into one, preserving input order.

    pikepdf auto-copies foreign pages at save time, so each source Pdf must stay
    open until the destination is serialized — hence the held-references list.
    """
    if not isinstance(pdfs, list):
        raise TypeError("pdfs must be a list of bytes")
    if not pdfs:
        raise ValueError("merge requires at least one PDF")
    dst = _new()
    sources: list[Pdf] = []
    try:
        for data in pdfs:
            src = _open(data)
            sources.append(src)
            dst.pages.extend(src.pages)
        return _to_bytes(dst)
    finally:
        dst.close()
        for src in sources:
            src.close()


def split(data: bytes) -> list[bytes]:
    """Split a PDF into one single-page PDF per page, in order."""
    src = _open(data)
    out: list[bytes] = []
    try:
        for i in range(len(src.pages)):
            d = _new()
            try:
                d.pages.append(src.pages[i])
                out.append(_to_bytes(d))
            finally:
                d.close()
        return out
    finally:
        src.close()


def extract_pages(data: bytes, ranges: list[tuple[int, int]]) -> bytes:
    """Extract the given inclusive 0-based (start, end) page ranges into one PDF.

    Ranges are emitted in the order given; duplicates/overlaps are allowed.
    """
    if not isinstance(ranges, list):
        raise TypeError("ranges must be a list of (start, end) tuples")
    src = _open(data)
    try:
        n = len(src.pages)
        indices: list[int] = []
        for rng in ranges:
            start, end = rng
            start = _validate_index(start, n)
            end = _validate_index(end, n)
            if start > end:
                raise ValueError(f"range start {start} after end {end}")
            indices.extend(range(start, end + 1))
        dst = _new()
        try:
            for i in indices:
                dst.pages.append(src.pages[i])
            return _to_bytes(dst)
        finally:
            dst.close()
    finally:
        src.close()


def reorder_pages(data: bytes, order: list[int]) -> bytes:
    """Reorder pages. `order` must be a permutation of range(page_count)."""
    if not isinstance(order, list):
        raise TypeError("order must be a list of page indices")
    src = _open(data)
    try:
        n = len(src.pages)
        if sorted(order) != list(range(n)):
            raise ValueError(
                f"order must be a permutation of all page indices (0..{n - 1}); got {order!r}"
            )
        dst = _new()
        try:
            for i in order:
                dst.pages.append(src.pages[i])
            return _to_bytes(dst)
        finally:
            dst.close()
    finally:
        src.close()


def rotate_pages(data: bytes, rotations: dict[int, int]) -> bytes:
    """Rotate pages by the given (relative) degrees. Keys are 0-based page indices;
    values are multiples of 90 in [-270, 270]. Rotation is applied relative to the
    page's existing rotation and normalized modulo 360."""
    if not isinstance(rotations, dict):
        raise TypeError("rotations must be a dict of {page_index: degrees}")
    allowed = {-270, -180, -90, 0, 90, 180, 270}
    pdf = _open(data)
    try:
        n = len(pdf.pages)
        # Validate everything before mutating anything.
        clean: dict[int, int] = {}
        for k, deg in rotations.items():
            idx = _validate_index(k, n)
            try:
                deg_i = int(deg)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"rotation must be an integer, got {deg!r}") from exc
            if deg_i not in allowed or deg_i % 90 != 0:
                raise ValueError(f"rotation {deg_i} must be a multiple of 90 in [-270, 270]")
            clean[idx] = deg_i % 360
        for idx, deg in clean.items():
            pdf.pages[idx].rotate(deg, relative=True)
        return _to_bytes(pdf)
    finally:
        pdf.close()


def delete_pages(data: bytes, pages: list[int]) -> bytes:
    """Delete the given 0-based pages. Rebuilds the doc keeping survivors (avoids
    in-place reindex bugs). Deleting every page raises ValueError."""
    if not isinstance(pages, list):
        raise TypeError("pages must be a list of page indices")
    src = _open(data)
    try:
        n = len(src.pages)
        drop = {_validate_index(i, n) for i in pages}
        keep = [i for i in range(n) if i not in drop]
        if not keep:
            raise ValueError("cannot delete all pages")
        dst = _new()
        try:
            for i in keep:
                dst.pages.append(src.pages[i])
            return _to_bytes(dst)
        finally:
            dst.close()
    finally:
        src.close()


def scrub_metadata(data: bytes) -> bytes:
    """Remove the /Info (docinfo) dictionary and the XMP /Metadata stream.

    Idempotent — safe to call on a document that already has neither.
    """
    pdf = _open(data)
    try:
        # docinfo.clear() fails (Object is not an Array); delete the dict outright.
        if pdf.trailer.get("/Info") is not None:
            del pdf.docinfo
        if pikepdf.Name.Metadata in pdf.Root:
            del pdf.Root.Metadata
        return _to_bytes(pdf)
    finally:
        pdf.close()


def encrypt(data: bytes, owner_pw: str, user_pw: str = "", aes: int = 256) -> bytes:
    """Encrypt a PDF with AES-256 (R=6). owner_pw must be non-empty; aes must be 256.

    Permissions mirror secure_pdf(): open/view/print/copy allowed, modification not.
    """
    if not isinstance(owner_pw, str) or not owner_pw:
        raise ValueError("owner_pw must be a non-empty string")
    if not isinstance(user_pw, str):
        raise TypeError("user_pw must be a string")
    if aes != 256:
        raise ValueError("only AES-256 (aes=256) is supported")
    pdf = _open(data)
    try:
        enc = Encryption(
            owner=owner_pw,
            user=user_pw,
            R=6,
            aes=True,
            metadata=True,
            allow=_seal_permissions(),
        )
        return _to_bytes(pdf, encryption=enc)
    finally:
        pdf.close()
