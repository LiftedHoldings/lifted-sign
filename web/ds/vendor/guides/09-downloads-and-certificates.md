# Downloads & the Certificate of Completion

Once an envelope is signed, three PDFs come off the API — the document you sent,
the sealed executed copy, and the audit certificate — plus the page geometry you
need to render a preview from stored field coordinates. This guide covers all
four endpoints, what each artifact contains, and how the tamper-evident seal and
audit record are built.

Every request is authenticated with your API key as a Bearer token and scoped to
the account that key belongs to. Base URL is `https://sign.example.com`.

```http
Authorization: Bearer $LIFTED_SIGN_KEY
```

Requesting an envelope your account doesn't own returns `404` — existence is
never leaked.

---

## The three PDFs at a glance

| Endpoint | Artifact | When it's available | Filename |
| --- | --- | --- | --- |
| `GET …/{aid}/pdf` | **Presented / source PDF** — exactly what signers see | Always (frozen snapshot once sent, live draft source before) | inline, `<name>.pdf` |
| `GET …/{aid}/download` | **Executed, sealed PDF** — the signed legal record | Once `completed` (see the fallback note) | `<name>-SIGNED.pdf` |
| `GET …/{aid}/certificate` | **Certificate of Completion** — the audit record | Only when `status == completed` | `<name>-CERTIFICATE.pdf` |

All three return raw `application/pdf` bytes on success. On failure they return a
bare JSON error envelope — `{"error": "..."}` — not the `{"ok": false}` shape
the JSON endpoints use. A missing or invalid key is `401 {"error":"unauthorized"}`.

To know *when* to fetch these, subscribe to the `envelope.completed`
[webhook](./12-webhooks-and-polling.md) — or poll the envelope and watch `status` reach
`completed`. See [Webhooks](./12-webhooks-and-polling.md) for both.

---

## 1. The presented (source) PDF — `/pdf`

`GET /api/mysign/agreements/{aid}/pdf` returns the exact bytes presented to
signers. Before the envelope is sent this is the live draft source; **on send the
bytes are frozen** into an immutable snapshot, and from then on `/pdf` serves
that frozen copy. This is the same source the editor's canvas and the per-page
PNG render read from, so a preview built on it is pixel-identical to what the
signer saw.

```bash
curl -sS https://sign.example.com/api/mysign/agreements/42/pdf \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" -o presented.pdf
```

The response carries `Cache-Control: no-store` — don't cache it; re-fetch when
you need current bytes.

| Status | Meaning |
| --- | --- |
| `200` | PDF bytes. |
| `401` | Missing/invalid key. |
| `404` | `{"error": "no document"}` — no source on file. |

Use `/pdf` to render an unsigned preview or to reconcile what you uploaded. For
the *signed* document, use `/download` below.

---

## 2. The executed, sealed PDF — `/download`

`GET /api/mysign/agreements/{aid}/download` returns the executed copy: the
presented bytes with every signer's values and signature images stamped in, the
Certificate of Completion appended as extra pages, and the whole file sealed.

```bash
curl -OJ https://sign.example.com/api/mysign/agreements/42/download \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"
# -OJ honors the server filename: <name>-SIGNED.pdf
```

When the envelope is `completed`, the download is named `<name>-SIGNED.pdf` and
is the sealed legal record. A copy of this exact file is also emailed to every
signer and to the sender the moment the envelope completes.

| Status | Meaning |
| --- | --- |
| `200` | Executed PDF bytes; `Content-Disposition: inline`. |
| `401` | Missing/invalid key. |
| `404` | `{"error": "no document"}` — no document on file at all. |

> **Fallback behavior to know about.** `/download` serves the *executed* file
> once one exists (i.e. after completion). If the envelope hasn't been sealed
> yet, it falls back to the raw source bytes — **unsealed and without the
> `-SIGNED` suffix**. So a `200` from `/download` is not by itself proof the
> document is signed. Gate on `status == completed` (or on the `-SIGNED`
> filename) before treating a download as the executed legal copy.

### What the seal is

The executed copy is stamped, has the certificate appended, and is then sealed
by one of two methods. Which one is used depends on whether a signing
certificate is provisioned on the server:

| Seal method | How it's applied | What it guarantees |
| --- | --- | --- |
| **PAdES / PKCS#7** (when a signing cert + key are configured and valid) | A DocMDP level-1 certification signature is applied as the final byte operation. | Any change after certification invalidates the signature in every compliant PDF reader. The cert is a self-signed X.509 ([Operator Name] LLC); verifiers who add it to their trust store see a fully-trusted status. |
| **AES-256 fallback** (default when no signing cert is configured) | The file is flattened/scrubbed, then encrypted with AES-256 (random owner password, **empty user password**). | Anyone can open, view, and print; modify / annotate / form-fill are disallowed — like a completed DocuSign PDF. Permission bits are advisory; the SHA-256 hash chain is the real tamper evidence. |

Both methods carry a **SHA-256 hash chain** (see [The seal and the
fingerprint](#the-seal-and-the-fingerprint) below). The Certificate of
Completion always states, truthfully, which method was applied — it never labels
an AES-sealed file as "certified".

---

## 3. The Certificate of Completion — `/certificate`

`GET /api/mysign/agreements/{aid}/certificate` returns the standalone
**Certificate of Completion** — the branded, multi-page audit record. It's the
same certificate that's appended inside `/download`, re-rendered on its own for
convenience. It's read-only: fetching it never re-stamps or re-seals; it reuses
the persisted hash chain, so its content matches the embedded copy exactly.

```bash
curl -OJ https://sign.example.com/api/mysign/agreements/42/certificate \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"
# -> <name>-CERTIFICATE.pdf
```

| Status | Meaning |
| --- | --- |
| `200` | Certificate PDF bytes; `Content-Disposition: inline`. |
| `401` | Missing/invalid key. |
| `404` | `{"error": "not completed"}` — the envelope isn't `completed` yet. |

Unlike `/download`, the certificate has **no fallback** — it's `404` until the
envelope reaches `completed`.

### What the certificate records

The certificate is designed as courtroom-ready evidence for an ESIGN/UETA
electronic signature. It contains:

**Envelope header**

- Envelope ID, document name, and final status.
- Page count, signer/field counts, and time zone.
- Sender ("Holder of record") and issuer.
- The **executed document's SHA-256 fingerprint**.
- A method-aware seal badge: *"Certified · PAdES PKCS#7 · SHA-256"* or
  *"Tamper-evident · SHA-256 + AES-256"*.

**Per signer** (identity, authentication, and consent)

| Field | Content |
| --- | --- |
| Signature ID | The unique id bound to the drawn/typed signature. |
| Authentication | The method used (`email` single-use link, `email_otp`, `access_code`, …). |
| IP address | The IP the signing action came from. |
| Device | A friendly summary of the signer's user agent. |
| Identity check | Any knowledge-based / access-challenge evidence — recorded as **type, method, and timestamp only** (never a DOB, SSN, access code, or OTP value). |
| Consent | Whether the signer accepted the ERSD / ESIGN·UETA consent, the disclosure version, and the timestamp + IP of consent. |
| Consent withdrawn | Timestamp, if the signer later withdrew consent. |
| Disclosure hash | A hash of the exact disclosure text the signer saw. |
| Access shown | For consumer signers, evidence they demonstrated the ability to access electronic records (§7001(c)). |

Each signer also gets a plain-language affirmation paragraph and, for consumer
signers, the exact §7001(c) e-consent record embedded verbatim.

**Audit trail** — every state transition (viewed, authenticated, signed, consent
events, seal, completion) with its IP and timestamp.

**Security & integrity section** — the hash chain and seal details described next.

> **Privacy:** the certificate deliberately renders identity evidence as
> type/method/timestamp/masked values only. Sensitive inputs (SSN, DOB, one-time
> codes, access codes) are never printed on the certificate.

---

## The seal and the fingerprint

The tamper evidence is a **SHA-256 hash chain (FIPS 180-4)** captured at seal
time and printed in the certificate's Security & Integrity section:

| Certificate field | What it is |
| --- | --- |
| **Document fingerprint** | SHA-256 over the final executed PDF. |
| **Pre-seal SHA-256** | Hash of the stamped bytes *before* the seal was applied. |
| **Sealed SHA-256** | Hash of the sealed bytes (shown for AES-sealed files; the PAdES signature itself is the integrity anchor when certification is used). |
| **Seal method** | `PAdES / PKCS#7 … DocMDP level 1` or `AES-256 encryption + SHA-256 tamper-evident hash chain + flattened`. |
| **Envelope binding** | Every signer action is recorded against the envelope id in the audit trail. |
| **Access control** | Each signer reached the document only via a unique, single-use token link. |

**How to verify a downloaded document is untampered:** compute the SHA-256 of the
bytes you received from `/download` and compare it to the **Document fingerprint**
printed on the certificate. A match proves the file is byte-for-byte the sealed
original; any change invalidates it.

```bash
curl -sS https://sign.example.com/api/mysign/agreements/42/download \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" -o contract-SIGNED.pdf

sha256sum contract-SIGNED.pdf   # compare against "Document SHA-256" on the certificate
```

When the file was sealed with PAdES, you can additionally validate the
certification signature in any compliant reader (Adobe Acrobat, etc.) — add the
[Operator Name] certificate to your trust store for a fully-trusted status.

---

## 4. Page geometry — `/pages`

Field coordinates are stored as **normalized fractions of the page** (`x`, `y`,
`w`, `h` each in `0..1`, origin top-left) so they're resolution-independent — see
[Placing fields](./06-placing-fields.md). To draw those fields onto a preview you
need the physical page size in points. That's what `/pages` gives you.

`GET /api/mysign/agreements/{aid}/pages` returns per-page dimensions in PDF
points, taken from the same bytes signers see, with page rotation already applied
(a 90°/270° page reports swapped `w`/`h`).

```bash
curl -sS https://sign.example.com/api/mysign/agreements/42/pages \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"
```

```json
{
  "pages": [
    { "w": 612.0, "h": 792.0 },
    { "w": 612.0, "h": 792.0 }
  ],
  "count": 2
}
```

| Status | Meaning |
| --- | --- |
| `200` | Array of page dimensions + `count`. |
| `401` | Missing/invalid key. |
| `404` | No such envelope owned by this account. |

### Converting a normalized field to absolute points

A field on page `n` with normalized `{x, y, w, h}` maps onto `pages[n]` like so:

```python
page = pages[field["page"]]           # {"w": 612.0, "h": 792.0}
left   = field["x"] * page["w"]       # points from the left edge
top    = field["y"] * page["h"]       # points from the top edge
width  = field["w"] * page["w"]
height = field["h"] * page["h"]
```

Read the field layout from `GET /api/mysign/agreements/{aid}` (or the `fields`
array returned when you placed them), pair each field's `page` index with the
matching entry in `pages`, and you have absolute coordinates for a canvas or
PDF-overlay preview.

### Rendering a page image

If you'd rather composite over a rasterized page than the PDF itself,
`GET /api/mysign/agreements/{aid}/page/{n}` returns a `image/png` render of page
`n` (same source bytes as `/pages`, so the geometry lines up). It returns
`404 {"error": "no page"}` for an out-of-range index.

```bash
curl -sS https://sign.example.com/api/mysign/agreements/42/page/0 \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" -o page-0.png
```

---

## SDK helpers

Both vendored SDKs wrap the two most-used downloads. Each streams the raw bytes
straight to a file path you choose.

**Python** ([`lifted_sign.py`](../../../web/ds/vendor/sdk/lifted_sign.py)):

```python
from lifted_sign import LiftedSign

ls = LiftedSign()  # reads LIFTED_SIGN_KEY from the environment

ls.download(42, "contract-SIGNED.pdf")     # executed, sealed PDF
ls.certificate(42, "certificate.pdf")      # Certificate of Completion
```

**Node** ([`lifted-sign.mjs`](../../../web/ds/vendor/sdk/lifted-sign.mjs)):

```javascript
import { LiftedSign } from "./lifted-sign.mjs";

const ls = new LiftedSign(); // reads LIFTED_SIGN_KEY from the env

await ls.download(42, "contract-SIGNED.pdf");
await ls.certificate(42, "certificate.pdf");
```

Both clients raise/throw `LiftedSignError` (with `.status` and `.body`) on any
HTTP error — so a `404` before the envelope is completed surfaces as an exception
you can catch and turn into a "not ready yet, keep polling" branch. The `/pdf`,
`/pages`, and `/page/{n}` endpoints don't have a dedicated SDK method — call them
with `curl` or a raw request; `/pages` returns JSON, the others return binary.

---

## Next steps

- [Placing fields](./06-placing-fields.md) — anchor, absolute-points, and
  normalized-coordinate placement, and every field type's default size.
- [Envelopes](./04-envelopes.md) — the full lifecycle and reading an envelope's
  current state, signers, fields, and audit events.
- [Signers & signing order](./05-signers-and-routing.md) — authentication methods
  (`email`, `email_otp`, `access_code`) that show up on the certificate.
- [Webhooks](./12-webhooks-and-polling.md) — subscribe to `envelope.completed` (or poll)
  so you know exactly when to download.
