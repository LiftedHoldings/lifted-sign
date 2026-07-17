# Lifted Sign API — Overview

Turn a PDF into a legally binding, signed document with four HTTP calls: create an envelope from the PDF, add signers, place fields, send. Lifted Sign hosts the rest — the signing pages, the emailed single-use links, the identity and consent capture, the tamper seal, and the Certificate of Completion.

```bash
curl -X POST https://sign.example.com/api/mysign/agreements \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -F file=@contract.pdf \
  -F name="Master Services Agreement"
# → { "ok": true, "id": 42 }
```

That single call gives you envelope `#42` in `draft`. Everything else in this API hangs off that id.

## What it is

Lifted Sign is a **hosted e-signature service** exposed as a REST API. You keep your document and your data; Lifted Sign handles the parts that make a signature legally defensible:

- **ESIGN / UETA compliant.** Every signer passes through an intent-and-consent gate before they can sign, and consumer (B2C) signers get the appropriate disclosure. The consent event is recorded, not assumed.
- **Tamper-sealed.** When you `send`, the presented PDF bytes are frozen and hashed (`doc_hash`, SHA-256). When the last signer completes, the executed document is cryptographically sealed — any later modification is detectable.
- **Certificate-backed.** Completion produces a **Certificate of Completion**: a separate PDF recording each signer's identity, IP address, timestamps, consent, and authentication events — the audit trail you hand to a court or an auditor.
- **Hosted signing.** Each signer gets a single-use tokenized link (`https://sign.example.com/sign/<token>`). They authenticate, review, consent, and sign in the browser. You never build a signing UI.

Base URL for every request:

```
https://sign.example.com
```

Auth is a Bearer API key you mint in the **Developers** tab of your dashboard — `sk_live_…` in production, `sk_test_…` in sandbox. It's a server-side secret; never ship it to a browser or mobile client. See [Authentication](./03-authentication.md) for the full key model.

```http
Authorization: Bearer $LIFTED_SIGN_KEY
```

## Why reach for it

You want an e-signature on a document and you don't want to build — or carry the legal liability of — the signing flow, identity capture, consent recording, tamper detection, and audit certificate yourself. Reach for Lifted Sign when:

- You generate agreements programmatically (contracts, order forms, NDAs, consents) and need each one signed and filed without a human in the loop.
- You send the *same* document repeatedly with a few values changed — build it once as a [template](./07-templates-and-prefill.md), then mint prefilled drafts with an `answers` map.
- You need a defensible record, not just a signature image — the Certificate of Completion is the deliverable that survives a dispute.

If you only need a checkbox on a web form, this is overkill. If the document matters, it isn't.

## The core objects

Four objects, one containment hierarchy. The **envelope** is the root; everything else lives inside it.

```
Account  (your API key resolves to exactly one)
  │
  └── Envelope  ── "agreement" in the API path; the PDF + its people + its audit trail
        │           id · name · status · order_mode · doc_hash · created_at · sent_at · completed_at
        │
        ├── Signer   ── a person invited to sign
        │              name · email · role · sign_order · status · auth_method · color
        │
        ├── Field    ── a signature/date/text box bound to one Signer, positioned on the PDF
        │              signer_id · type · page · x,y,w,h (normalized 0..1) · required
        │
        └── Event[]  ── ordered audit trail: created, sent, viewed, signed, voided, …

Template  ── a reusable snapshot of a PDF + signer roles + field layout (incl. prefill fields).
             "Use" a template to mint a fresh, prefilled Envelope draft.
```

| Object | API name | What it is | Key fields |
|--------|----------|------------|------------|
| **Envelope** | `agreement` | One agreement — the PDF plus its signers, fields, and audit events. The unit you create, send, track, and download. | `id`, `name`, `status`, `order_mode`, `doc_hash`, `created_at`, `sent_at`, `completed_at` |
| **Signer** | `signer` | A person invited to sign an envelope. Replaced as a whole set while the envelope is a draft. | `id`, `name`, `email`, `role`, `sign_order`, `status`, `auth_method`, `color` |
| **Field** | `field` | A signature, initials, date, text, or checkbox box bound to one signer and placed on the document. | `signer_id`, `type`, `page`, `x`, `y`, `w`, `h`, `required` |
| **Template** | `template` | A reusable snapshot of a PDF + signer roles + field layout, including **prefill** fields you fill per use via `answers`. | `id`, `name`, `page_n`, `signer_n`, `field_n`, `signers[]`, `fields[]` |

A few things worth internalizing early:

- **"Envelope" and "agreement" are the same object.** The docs say *envelope*; the URL path says `agreement` (`/api/mysign/agreements/{aid}`). Don't let it trip you up.
- **Field coordinates are normalized 0..1 fractions of the page**, origin top-left, y increasing downward — that's what the API returns. But you rarely compute them: place fields **by anchor** (name text that already exists in the PDF and the field snaps to it). See [Placing fields](./06-placing-fields.md).
- **Everything is account-scoped.** A key grants no more than a logged-in user of that account. Requesting an envelope you don't own returns `404` — existence is never leaked across tenants.

## The envelope lifecycle

An envelope is a small state machine. You drive the top row; signers and the system drive the exits.

```
                          send()                        all signers sign
   ┌────────┐  ───────────────────────►  ┌──────────────────┐  ─────────────►  ┌───────────┐
   │ draft  │                            │ out_for_signature│                  │ completed │
   └────────┘                            └──────────────────┘                  └───────────┘
       │  editable: signers,                    │  frozen bytes; accrues
       │  fields, order-mode                    │  viewed/signed events
       │                                        │
    delete()                          ┌─────────┼─────────────┬──────────────┐
   (gone; draft only)                 ▼         ▼             ▼              ▼
                                  declined    voided      cancelled       expired
                                 (a signer   (you        (system /       (auto-expiry
                                  refused)    void()d it)  admin)          sweep)
```

**The happy path is three states:** `draft` → `out_for_signature` → `completed`.

1. **`draft`** — created by `POST /agreements` from a PDF. This is the *only* mutable state: you set signers, place fields, and choose the order mode here. A draft has been signed by nobody and can be `delete`d outright.
2. **`out_for_signature`** — after `POST /agreements/{aid}/send`. The presented bytes are frozen, each signer has a single-use link in their inbox, and the envelope accrues `viewed` / `signed` audit events. You can `remind` pending signers but you can no longer edit the document.
3. **`completed`** — every signer has signed. The executed PDF (`<name>-SIGNED.pdf`) and the Certificate of Completion become downloadable.

**The exits** — terminal states an envelope can land in instead of completing:

| Status | How it's reached | Notes |
|--------|------------------|-------|
| `declined` | A signer refuses to sign | Envelope stops; recorded in the audit trail. |
| `voided` | You call `POST /agreements/{aid}/void` | Immediately revokes all live signing sessions and outstanding links. Terminal legal record. |
| `cancelled` | System / administrative cancellation | Treated like `voided` for signing purposes — no new signing actions accepted. |
| `expired` | Auto-expiry sweep flips an unsigned `out_for_signature` envelope past its expiry window | A real terminal state the server sets on its own; unsigned signers can no longer act and must be re-sent. *Not yet in the OpenAPI `status` enum — the spec documents the six states above; `expired` is set by the backend sweep.* |

Two rules that catch integrators off guard:

- **Draft immutability.** Signers, fields, page edits, and order-mode can only change while the envelope is a `draft`. Once sent, those calls return `{"ok": false, "error": "locked — already sent"}` with **HTTP 200** — a soft, in-body rejection, not a 4xx. Check the `ok` field, not just the status code. (The vendored SDKs raise on `ok: false` for you.)
- **Sent envelopes are legal records.** A sent or completed envelope cannot be edited or deleted — only `void`ed. `DELETE` on a sent envelope is the one hard rejection: **HTTP 409**.

The `status` field on the [`Envelope`](../openapi.yaml) object tells you exactly where an envelope sits. Track it two ways: **register a webhook** and receive a signed POST the moment it changes, or **poll** `GET /agreements/{aid}` (or list with `GET /agreements`). See [Tracking status](./08-sending-and-tracking.md) and the [Webhooks](./12-webhooks-and-polling.md) guide.

## Your first call

Here's the whole happy path — create, add a signer, place a signature by anchor, send — in the three surfaces you'll actually use.

**curl:**

```bash
export KEY=sk_live_...

# 1. create a draft envelope from a PDF
AID=$(curl -s -X POST https://sign.example.com/api/mysign/agreements \
  -H "Authorization: Bearer $KEY" \
  -F file=@contract.pdf | jq .id)

# 2. add a signer
curl -s -X POST https://sign.example.com/api/mysign/agreements/$AID/signers \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"signers":[{"name":"Dana Client","email":"dana@example.com"}]}'

# 3. place a signature field by anchor (no coordinate math)
curl -s -X POST https://sign.example.com/api/mysign/agreements/$AID/fields \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"fields":[{"signer":"dana@example.com","type":"signature","anchor":"Signature:"}]}'

# 4. send — freezes the PDF and emails Dana a single-use link
curl -s -X POST https://sign.example.com/api/mysign/agreements/$AID/send \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" -d '{}'
```

**Python** (vendored [`lifted_sign.py`](../../../web/ds/vendor/sdk/lifted_sign.py), standard-library only):

```python
from lifted_sign import LiftedSign

ls  = LiftedSign(api_key="sk_live_...")           # or set LIFTED_SIGN_KEY
env = ls.create_agreement("contract.pdf", name="Master Services Agreement")
ls.add_signers(env["id"], [{"name": "Dana Client", "email": "dana@example.com"}])
ls.place_fields(env["id"], [
    {"signer": "dana@example.com", "type": "signature", "anchor": "Signature:"},
])
ls.send(env["id"])                                # Dana gets a single-use link by email
```

**Node** (vendored [`lifted-sign.mjs`](../../../web/ds/vendor/sdk/lifted-sign.mjs), built-in `fetch`/`FormData`):

```js
import { LiftedSign } from "./lifted-sign.mjs";

const ls  = new LiftedSign({ apiKey: "sk_live_..." });
const env = await ls.createAgreement("contract.pdf", { name: "Master Services Agreement" });
await ls.addSigners(env.id, [{ name: "Dana Client", email: "dana@example.com" }]);
await ls.placeFields(env.id, [
  { signer: "dana@example.com", type: "signature", anchor: "Signature:" },
]);
await ls.send(env.id);
```

Both SDK clients raise/throw on an `{"ok": false}` body, so a failed field placement never slips through as a silent success on a legal document.

**Next:** walk the full flow end to end in the [Quickstart](./02-quickstart.md), then dig into [Placing fields](./06-placing-fields.md) (anchors, points, and normalized coordinates) and [Templates](./07-templates-and-prefill.md) (build once, reuse with prefill). The machine-readable [OpenAPI 3.1 spec](../openapi.yaml) is the source of truth for every endpoint, field, and status code.
