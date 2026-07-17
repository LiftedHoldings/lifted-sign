#!/usr/bin/env python3
# Lifted Sign Python SDK
# Copyright (c) 2026 Daniel Wilson Kemp
# SPDX-License-Identifier: MIT
#
# This client SDK is MIT-licensed and may be freely vendored into any project,
# open or closed — it is deliberately kept under a permissive license so that
# integrating against Lifted Sign never subjects your application to the AGPL
# that covers the Lifted Sign server. See sdks/LICENSE for the full MIT text.
"""Lifted Sign API — zero-dependency Python client.

A single-file, standard-library-only client for the Lifted Sign e-signature
service (https://sign.liftedholdings.com). There is nothing to `pip install`:
drop this module into your project and import it. It wraps the `/api/mysign/*`
REST endpoints in typed, ergonomic methods so you can create an envelope, add
signers, place fields, send it for signature, and download the sealed result.

Quick start
-----------
::

    from lifted_sign import LiftedSign

    ls = LiftedSign(api_key="sk_live_...")           # or LIFTED_SIGN_KEY in the environment
    env = ls.create_agreement("contract.pdf", name="Master Services Agreement")
    ls.add_signers(env["id"], [{"name": "Dana Client", "email": "dana@example.com"}])
    ls.place_fields(env["id"], [
        {"signer": "dana@example.com", "type": "signature", "anchor": "Signature:"},
        {"signer": "dana@example.com", "type": "date",      "anchor": "Date:"},
    ])
    ls.send(env["id"])                               # emails each signer a single-use link

Terminology
-----------
An *agreement* (a.k.a. *envelope*) is one document sent to one or more signers.
It moves through a lifecycle: created (draft) → signers/fields configured →
sent → signed → completed. Most methods take the integer envelope id returned
by :meth:`LiftedSign.create_agreement`.

Field placement
---------------
Fields are positioned by ANCHOR by default — you name text that already exists
in the PDF ("Signature:") and the field snaps to it, so you never compute
coordinates by hand. Absolute PDF points and normalized 0..1 coordinates are
also supported; see :meth:`LiftedSign.place_fields` for the full field schema.

Authentication
--------------
Every request is authenticated with a bearer API key, supplied either to the
constructor (``api_key=``) or via the ``LIFTED_SIGN_KEY`` environment variable.

Errors
------
All failures raise :class:`LiftedSignError`, which carries the HTTP ``status``
and the decoded response ``body`` for inspection. Note that field-placement and
other mutating endpoints may return an ``{"ok": false}`` body with HTTP 200;
this client treats that as an error too, so a failed placement never passes
silently.

Command-line usage
------------------
Run the module directly to send your first document in a single command::

    export LIFTED_SIGN_KEY=sk_live_xxx
    python lifted_sign.py contract.pdf dana@example.com "Dana Client"

License / requirements
----------------------
MIT licensed. No third-party dependencies. Python 3.8+.
"""

from __future__ import annotations

import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_BASE_URL = "https://sign.liftedholdings.com"


class LiftedSignError(RuntimeError):
    """Raised for any Lifted Sign API failure.

    Covers three failure modes uniformly: a missing API key at construction
    time, a non-2xx HTTP response, and a 200 response whose JSON body reports
    ``{"ok": false}``.

    Attributes:
        status: The HTTP status code associated with the failure, or ``None``
            for client-side errors (e.g. a missing API key). Server-side
            ``{"ok": false}`` bodies are reported with ``status=200``.
        body: The decoded response body — a ``dict``/``list`` when the server
            returned JSON, otherwise the raw response text. ``None`` when there
            is no associated response.
    """

    def __init__(self, message: str, *, status: Optional[int] = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


class LiftedSign:
    """A thin, complete client for the Lifted Sign REST API.

    One instance holds the API key, base URL, and request timeout, and exposes
    a method per endpoint. Instances are cheap to create and hold no network
    connections between calls (each call is an independent HTTP request), so
    they are effectively stateless and safe to reuse across an application.
    """

    def __init__(
        self, api_key: Optional[str] = None, base_url: str = DEFAULT_BASE_URL, timeout: float = 30.0
    ):
        """Construct a client.

        Args:
            api_key: The bearer API key. If omitted, it is read from the
                ``LIFTED_SIGN_KEY`` environment variable.
            base_url: The API origin. Defaults to the hosted service; override
                only to target a self-hosted or staging deployment. Any
                trailing slash is stripped so paths join cleanly.
            timeout: Per-request socket timeout in seconds.

        Raises:
            LiftedSignError: If no API key is provided or found in the
                environment.
        """
        self.api_key = api_key or os.environ.get("LIFTED_SIGN_KEY")
        if not self.api_key:
            raise LiftedSignError("No API key. Pass api_key=... or set LIFTED_SIGN_KEY.")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # -- low-level request ---------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        raw: bool = False,
    ) -> Any:
        """Issue a single authenticated HTTP request and normalize the result.

        This is the shared transport that every public method routes through.
        It attaches the bearer token and ``Accept: application/json``, sends
        the optional body, and decodes the response.

        Args:
            method: HTTP verb (``GET``, ``POST``, ``DELETE``, ...).
            path: Request path appended to ``base_url`` (e.g.
                ``/api/mysign/agreements``).
            body: Raw request body bytes, or ``None`` for a bodiless request.
            content_type: Value for the ``Content-Type`` header when ``body``
                is present.
            raw: When ``True``, return the response bytes verbatim (used for
                PDF downloads); otherwise decode the body as JSON.

        Returns:
            The parsed JSON value (``dict``/``list``/etc.), ``{}`` for an empty
            body, or the raw ``bytes`` when ``raw=True``.

        Raises:
            LiftedSignError: On any non-2xx HTTP status, or on a 200 response
                whose JSON body carries ``{"ok": false}``.
        """
        req = urllib.request.Request(self.base_url + path, data=body, method=method)
        req.add_header("Authorization", "Bearer " + self.api_key)
        req.add_header("Accept", "application/json")
        if content_type:
            req.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = resp.read()
                if raw:
                    # Binary endpoints (PDF downloads) skip JSON decoding.
                    return payload
                # An empty body (e.g. 204) is normalized to an empty dict.
                data = json.loads(payload.decode("utf-8")) if payload else {}
        except urllib.error.HTTPError as e:
            # Non-2xx: try to surface the server's JSON error body, but fall
            # back to raw text if it isn't valid JSON.
            detail = e.read().decode("utf-8", "replace")
            try:
                detail = json.loads(detail)
            except ValueError:
                pass
            # `from None` suppresses the urllib traceback so callers see a clean
            # LiftedSignError rather than a chained HTTPError.
            raise LiftedSignError(
                f"{method} {path} -> HTTP {e.code}", status=e.code, body=detail
            ) from None
        # Endpoints that place/mutate return {"ok": false, "error": "..."} with HTTP 200
        # when a field can't be resolved — surface that as an error, never a silent drop.
        if isinstance(data, dict) and data.get("ok") is False:
            raise LiftedSignError(
                f"{method} {path} -> {data.get('error', 'error')}", status=200, body=data
            )
        return data

    @staticmethod
    def _multipart(
        fields: Dict[str, str], file_field: str, filename: str, file_bytes: bytes, file_type: str
    ) -> Tuple[bytes, str]:
        """Hand-encode a ``multipart/form-data`` payload for a file upload.

        Implemented from scratch to keep the client dependency-free (no
        ``requests``/``email`` helpers). Emits each simple text field first,
        then a single binary file part.

        Args:
            fields: Plain text form fields, name -> value.
            file_field: The form field name that carries the file.
            filename: The uploaded file's name, echoed in the part header.
            file_bytes: The file's raw contents.
            file_type: The file's MIME type.

        Returns:
            A ``(body, content_type)`` tuple: the fully encoded request body and
            the matching ``Content-Type`` header value (which includes the
            generated boundary).
        """
        # A random boundary that is statistically guaranteed not to collide with
        # the file contents. Line endings must be CRLF per the multipart spec.
        boundary = "----LiftedSign" + uuid.uuid4().hex
        out = bytearray()
        # Text fields first.
        for name, value in fields.items():
            out += f"--{boundary}\r\n".encode()
            out += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            out += f"{value}\r\n".encode()
        # Then the file part: header, blank line, raw bytes, trailing CRLF.
        out += f"--{boundary}\r\n".encode()
        out += (
            f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
        ).encode()
        out += f"Content-Type: {file_type}\r\n\r\n".encode()
        out += file_bytes + b"\r\n"
        # Closing boundary (note the trailing `--`) terminates the body.
        out += f"--{boundary}--\r\n".encode()
        return bytes(out), f"multipart/form-data; boundary={boundary}"

    # -- envelopes -----------------------------------------------------------
    def create_agreement(self, pdf_path: str, name: Optional[str] = None) -> Dict[str, Any]:
        """Create a draft envelope by uploading a PDF.

        This is the first step of every signing workflow. The envelope starts
        as a draft with no signers or fields yet.

        Args:
            pdf_path: Path to the source PDF on the local filesystem.
            name: Human-readable name for the agreement. Defaults to the PDF's
                base filename.

        Returns:
            The created envelope as a dict, including its integer ``id`` — pass
            that id to every subsequent call.
        """
        with open(pdf_path, "rb") as fh:
            pdf = fh.read()
        # Detect the MIME type from the extension; assume PDF if unknown.
        file_type = mimetypes.guess_type(pdf_path)[0] or "application/pdf"
        fields = {"name": name or os.path.basename(pdf_path)}
        body, ctype = self._multipart(fields, "file", os.path.basename(pdf_path), pdf, file_type)
        return self._request("POST", "/api/mysign/agreements", body=body, content_type=ctype)

    def list_agreements(self, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        """List your agreements, most recent first, with pagination.

        Args:
            limit: Maximum number of agreements to return in this page.
            offset: Number of agreements to skip (for paging through results).

        Returns:
            A dict containing the page of agreements (and any pagination
            metadata the API includes).
        """
        return self._request("GET", f"/api/mysign/agreements?limit={limit}&offset={offset}")

    def get(self, aid: int) -> Dict[str, Any]:
        """Fetch a single agreement, including its current status and signers.

        Args:
            aid: The envelope id returned by :meth:`create_agreement`.

        Returns:
            The agreement as a dict.
        """
        return self._request("GET", f"/api/mysign/agreements/{aid}")

    def wait_for_completion(self, aid, *, timeout: float = 600, interval: float = 5) -> Dict[str, Any]:
        """Poll :meth:`get` until the agreement reaches a terminal status.

        Blocks the calling thread, sleeping ``interval`` seconds between polls,
        until the agreement is ``completed``/``signed`` (returned) or
        ``voided``/``declined`` (raises), or until ``timeout`` seconds elapse.

        Args:
            aid: The integer envelope id returned by :meth:`create_agreement`.
            timeout: Maximum seconds to wait before giving up.
            interval: Seconds to sleep between polls.

        Returns:
            The final agreement dict once it is completed or signed.

        Raises:
            LiftedSignError: If the agreement is voided or declined. The final
                agreement dict is attached as ``body``.
            TimeoutError: If ``timeout`` elapses before a terminal status.
        """
        deadline = time.monotonic() + timeout
        agreement = self.get(aid)
        status = str(agreement.get("status", "")).lower()
        while True:
            if status in ("completed", "signed"):
                return agreement
            if status in ("voided", "declined"):
                raise LiftedSignError(
                    f"Agreement {aid} reached terminal status '{status}'", status=None, body=agreement
                )
            now = time.monotonic()
            if now >= deadline:
                raise TimeoutError(
                    f"Agreement {aid} did not reach a terminal status within {timeout}s "
                    f"(last observed status: '{status}')"
                )
            time.sleep(min(interval, deadline - now))
            agreement = self.get(aid)
            status = str(agreement.get("status", "")).lower()

    def delete(self, aid: int) -> Dict[str, Any]:
        """Permanently delete a draft agreement.

        Args:
            aid: The envelope id to delete.

        Returns:
            The API's deletion-confirmation response.
        """
        return self._request("DELETE", f"/api/mysign/agreements/{aid}")

    # -- signers / fields ----------------------------------------------------
    def add_signers(self, aid: int, signers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Set (replace) the signer list for an agreement.

        The order of the list is the signing order. Call this before
        :meth:`place_fields`, since fields target signers by email.

        Args:
            aid: The envelope id.
            signers: The full signer list as
                ``[{"name": ..., "email": ...}, ...]``. This replaces any
                previously configured signers.

        Returns:
            The API response describing the saved signers.
        """
        return self._json("POST", f"/api/mysign/agreements/{aid}/signers", {"signers": signers})

    def place_fields(self, aid: int, fields: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Place signing fields on the document.

        Each field assigns an input to a specific signer (by ``signer`` email)
        and pins it to a location using exactly one of three positioning modes:

        anchor    : {"signer": "..", "type": "signature", "anchor": "Signature:"}   (recommended)
                    optional: "anchor_index" (nth match), "place" (right|left|below|above|over),
                    "dx"/"dy" (nudge, PDF points)
        points    : {"signer": "..", "type": "signature", "page": 0, "x": 100, "y": 200, "unit": "pt"}
        normalized: {"signer": "..", "type": "signature", "page": 0, "x": 0.5, "y": 0.5}  (0..1)

        Field types: signature, initials, date, text, name, email, checkbox.

        Args:
            aid: The envelope id.
            fields: The list of field specs to place (see the three modes
                above).

        Returns:
            The API response, typically including a ``count`` of placed fields.

        Note:
            Placement is fail-closed: if *any* field cannot be resolved (e.g. an
            anchor string isn't found), the entire batch is rejected rather than
            partially applied. Such a rejection surfaces as a
            :class:`LiftedSignError`.
        """
        return self._json("POST", f"/api/mysign/agreements/{aid}/fields", {"fields": fields})

    # -- sending -------------------------------------------------------------
    def send(self, aid: int) -> Dict[str, Any]:
        """Send the agreement for signature.

        Freezes the document and its fields and emails each configured signer a
        single-use signing link. After this the envelope is no longer a draft.

        Args:
            aid: The envelope id.

        Returns:
            The API response confirming the send.
        """
        return self._json("POST", f"/api/mysign/agreements/{aid}/send", {})

    def remind(self, aid: int) -> Dict[str, Any]:
        """Re-send the signing-link email to signers who haven't yet signed.

        Args:
            aid: The envelope id of an already-sent agreement.

        Returns:
            The API response describing which signers were reminded.
        """
        return self._json("POST", f"/api/mysign/agreements/{aid}/remind", {})

    def void(self, aid: int, reason: str = "") -> Dict[str, Any]:
        """Void a sent agreement, invalidating its outstanding signing links.

        Use this to cancel a document that is out for signature.

        Args:
            aid: The envelope id.
            reason: Optional human-readable reason recorded on the audit trail.

        Returns:
            The API response confirming the void.
        """
        return self._json("POST", f"/api/mysign/agreements/{aid}/void", {"reason": reason})

    # -- downloads -----------------------------------------------------------
    def download(self, aid: int, out_path: str) -> str:
        """Download the sealed, signed PDF and write it to disk.

        Available once the agreement is completed. The downloaded PDF is the
        final tamper-evident document with all signatures embedded.

        Args:
            aid: The envelope id.
            out_path: Local filesystem path to write the PDF to.

        Returns:
            ``out_path`` (for convenient chaining).
        """
        data = self._request("GET", f"/api/mysign/agreements/{aid}/download", raw=True)
        with open(out_path, "wb") as fh:
            fh.write(data)
        return out_path

    def certificate(self, aid: int, out_path: str) -> str:
        """Download the Certificate of Completion PDF and write it to disk.

        The certificate is the audit trail: signer identities, timestamps, IP
        addresses, and consent records for the agreement.

        Args:
            aid: The envelope id.
            out_path: Local filesystem path to write the certificate PDF to.

        Returns:
            ``out_path`` (for convenient chaining).
        """
        data = self._request("GET", f"/api/mysign/agreements/{aid}/certificate", raw=True)
        with open(out_path, "wb") as fh:
            fh.write(data)
        return out_path

    def account(self) -> Dict[str, Any]:
        """Fetch the account associated with the current API key.

        Useful as a lightweight credential/connectivity check.

        Returns:
            The account details as a dict.
        """
        return self._request("GET", "/api/mysign/account")

    # -- helper --------------------------------------------------------------
    def _json(self, method: str, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send a JSON-encoded request body via :meth:`_request`.

        Convenience wrapper shared by all the JSON (non-upload) endpoints: it
        serializes ``payload`` and sets the ``application/json`` content type.

        Args:
            method: HTTP verb.
            path: Request path appended to ``base_url``.
            payload: The request body, serialized to JSON.

        Returns:
            The decoded JSON response.
        """
        return self._request(
            method,
            path,
            body=json.dumps(payload).encode("utf-8"),
            content_type="application/json",
        )


def _demo() -> int:
    """Run the end-to-end command-line demo: upload → sign-request in one shot.

    Reads the PDF path, signer email, and (optionally) signer name and anchor
    text from ``sys.argv``, then walks the full create → add signer → place
    field → send flow, printing progress at each step. The API key comes from
    the ``LIFTED_SIGN_KEY`` environment variable.

    Returns:
        A process exit code: ``0`` on success, or ``2`` when required arguments
        are missing (usage is printed in that case).
    """
    # Need at least a PDF path and a signer email; otherwise print help.
    if len(sys.argv) < 3:
        print(__doc__)
        print("usage: python lifted_sign.py <pdf> <signer-email> [signer-name] [anchor]")
        return 2
    pdf, email = sys.argv[1], sys.argv[2]
    # Signer name defaults to the email; anchor defaults to "Signature:".
    name = sys.argv[3] if len(sys.argv) > 3 else email
    anchor = sys.argv[4] if len(sys.argv) > 4 else "Signature:"
    ls = LiftedSign()
    env = ls.create_agreement(pdf, name=os.path.basename(pdf))
    aid = env["id"]
    print(f"1/4  created envelope #{aid}")
    ls.add_signers(aid, [{"name": name, "email": email}])
    print(f"2/4  added signer {email}")
    res = ls.place_fields(aid, [{"signer": email, "type": "signature", "anchor": anchor}])
    print(f"3/4  placed {res.get('count', 0)} field(s) at anchor {anchor!r}")
    ls.send(aid)
    print(f"4/4  sent — {email} has a signing link in their inbox")
    print(f"\nTrack it:  {ls.base_url} · envelope #{aid}")
    return 0


if __name__ == "__main__":
    # CLI entry point: run the demo and translate any API failure into a
    # non-zero exit code plus a readable error (and the response body if any).
    try:
        raise SystemExit(_demo())
    except LiftedSignError as e:
        print(f"error: {e}", file=sys.stderr)
        if e.body:
            print(json.dumps(e.body, indent=2), file=sys.stderr)
        raise SystemExit(1)