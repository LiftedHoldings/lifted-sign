# Envelopes

An **envelope** is one document sent to one or more signers. In the API path it is called an *agreement* — the two words are interchangeable, and every endpoint lives under `/api/mysign/agreements`. This guide covers the envelope object itself: creating one from a PDF, listing your envelopes, reading a single envelope with its full audit trail, and deleting a draft. Signer and field configuration have their own guides ([Placing fields](./06-placing-fields.md)); everything here is the container those live in.

Base URL: `https://sign.example.com`. Every request is authenticated with a Bearer key (`sk_live_…` in production, `sk_test_…` in sandbox):

```http
Authorization: Bearer $LIFTED_SIGN_KEY
```

A missing or invalid key returns `401 {"error":"unauthorized"}`. Requesting an envelope your account does not own returns `404 {"error":"not found"}` — existence is never leaked to non-owners.

The examples below use the zero-dependency vendored SDKs: [`lifted_sign.py`](../../../web/ds/vendor/sdk/lifted_sign.py) (Python 3.8+, stdlib only) and [`lifted-sign.mjs`](../../../web/ds/vendor/sdk/lifted-sign.mjs) (Node 18+, no npm install). Drop either file into your project and import it.

---

## Create an envelope from a PDF

```
POST /api/mysign/agreements
```

Upload a PDF to create a new `draft` envelope. The request is `multipart/form-data` with a `file` part (the source PDF) and an optional `name` (defaults to the uploaded filename). The new envelope starts life as a `draft` — add signers, place fields, and edit pages before you send it.

**Form parts**

| Part | Required | Description |
|---|---|---|
| `file` | yes | The source PDF. Max **60 MB**. |
| `name` | no | Human-friendly envelope name. Defaults to the uploaded filename. |

The PDF is fully opened and validated **before** any row or file is written, so a bad upload is a clean `400` — it never becomes a black-hole envelope that 500s downstream. Rejected uploads:

| Condition | `400` `error` |
|---|---|
| No `file` part | `file required` |
| Larger than 60 MB | `file too large (max 60 MB)` |
| Not a PDF (bad magic bytes) | `not a PDF` |
| Encrypted with a user password | `password-protected PDFs are not supported` |
| Zero pages | `PDF has no pages` |
| Corrupt / unreadable | `corrupt or unreadable PDF` |

> PDFs with an *owner* password but an empty *user* password (including Lifted Sign's own sealed output) open fine and are accepted.

**curl**

```bash
curl -X POST https://sign.example.com/api/mysign/agreements \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY…" \
  -F file=@msa.pdf \
  -F name="Master Services Agreement"
# → { "ok": true, "id": 42 }
```

**Python**

```python
from lifted_sign import LiftedSign

ls = LiftedSign(api_key="sk_live_…")            # or set LIFTED_SIGN_KEY
env = ls.create_agreement("msa.pdf", name="Master Services Agreement")
print(env["id"])                                 # 42
```

**Node**

```js
import { LiftedSign } from "./lifted-sign.mjs";

const ls = new LiftedSign({ apiKey: "sk_live_…" });   // or LIFTED_SIGN_KEY
const env = await ls.createAgreement("msa.pdf", { name: "Master Services Agreement" });
console.log(env.id);                                   // 42
```

**Response** `200`

```json
{ "ok": true, "id": 42 }
```

Keep that `id` — every subsequent call ([signers](./05-signers-and-routing.md), [fields](./06-placing-fields.md), send, download) is addressed by it.

---

## List envelopes

```
GET /api/mysign/agreements?limit=50&offset=0
```

Return the account's envelopes, **newest first**, with pagination. Each item is enriched with rollup counts and a lightweight `signers` array so a dashboard can render a table without a second call per row.

**Query parameters**

| Param | Type | Default | Notes |
|---|---|---|---|
| `limit` | integer | `50` | Page size, clamped server-side to `1..200`. |
| `offset` | integer | `0` | Rows to skip. Negative values are clamped to `0`. |

**curl**

```bash
curl "https://sign.example.com/api/mysign/agreements?limit=50&offset=0" \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY…"
```

**Python**

```python
page = ls.list_agreements(limit=50, offset=0)
for env in page["agreements"]:
    print(env["id"], env["status"], f'{env["signed_n"]}/{env["signer_n"]} signed')
```

**Node**

```js
const page = await ls.listAgreements({ limit: 50, offset: 0 });
for (const env of page.agreements) {
  console.log(env.id, env.status, `${env.signed_n}/${env.signer_n} signed`);
}
```

**Response** `200`

```json
{
  "agreements": [
    {
      "id": 42,
      "name": "Master Services Agreement.pdf",
      "status": "out_for_signature",
      "message": "Please countersign by Friday.",
      "order_mode": "sequential",
      "created_at": 1752624000.0,
      "sent_at": 1752624120.0,
      "completed_at": null,
      "signers": [
        {
          "name": "Dana Client",
          "email": "dana@example.com",
          "status": "viewed",
          "color": "#2F6FED",
          "viewed_at": 1752624300.0,
          "signed_at": null
        }
      ],
      "signed_n": 0,
      "signer_n": 1,
      "field_n": 3,
      "page_n": 4
    }
  ],
  "total": 1,
  "offset": 0,
  "limit": 50,
  "has_more": false
}
```

**Envelope list wrapper**

| Field | Type | Description |
|---|---|---|
| `agreements` | array | The page of envelopes (each with the derived counts below). |
| `total` | integer | Total envelopes owned by the account (not just this page). |
| `offset` | integer | The echoed offset. |
| `limit` | integer | The echoed (clamped) limit. |
| `has_more` | boolean | `true` when `offset + returned < total`. |

Paginate by walking `offset` in `limit`-sized steps until `has_more` is `false`.

**Derived rollup counts** (present on list items only)

| Field | Meaning |
|---|---|
| `signed_n` | Signers whose `status` is `signed`. |
| `signer_n` | Total signers on the envelope. |
| `field_n` | Total placed fields. |
| `page_n` | One past the highest 0-based **field** page — i.e. the number of pages that carry a field, `0` when no fields are placed. |

> `page_n` in the list is a **field-coverage** count, not the document's true page count. For the real page count (and per-page geometry) call `GET /api/mysign/agreements/{aid}/pages`, whose `count` is the actual number of PDF pages.

The per-item `signers` array here is deliberately lightweight — `name`, `email`, `status`, `color`, `viewed_at`, `signed_at`. For the full signer rows (with `id`, `role`, `sign_order`, `auth_method`) fetch the single envelope below.

---

## Get one envelope

```
GET /api/mysign/agreements/{aid}
```

Return the full envelope: metadata, the complete `signers` rows, the placed `fields`, and the ordered `events` audit trail. This is the call you poll to watch an envelope move toward `completed`.

**curl**

```bash
curl https://sign.example.com/api/mysign/agreements/42 \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY…"
```

**Python**

```python
env = ls.get(42)
print(env["status"])                 # e.g. "completed"
for ev in env["events"]:
    print(ev["at"], ev["type"], ev.get("detail", ""))
```

**Node**

```js
const env = await ls.get(42);
console.log(env.status);
for (const ev of env.events) console.log(ev.at, ev.type, ev.detail ?? "");
```

**Response** `200`

```json
{
  "id": 42,
  "name": "Master Services Agreement.pdf",
  "message": "Please countersign by Friday.",
  "status": "out_for_signature",
  "order_mode": "sequential",
  "created_by": "dev@acme.com",
  "doc_hash": "9f2c1b7e…a71b",
  "created_at": 1752624000.0,
  "sent_at": 1752624120.0,
  "completed_at": null,
  "signers": [
    {
      "id": 101,
      "name": "Dana Client",
      "email": "dana@example.com",
      "role": "Client",
      "sign_order": 1,
      "status": "viewed",
      "auth_method": "email",
      "color": "#2F6FED"
    }
  ],
  "fields": [
    { "signer_id": 101, "type": "signature", "page": 3, "x": 0.12, "y": 0.78, "w": 0.30, "h": 0.06, "required": true }
  ],
  "events": [
    { "type": "sent", "signer_id": 101, "detail": "to dana@example.com", "at": 1752624120.0 }
  ]
}
```

The `events` array is the append-only audit trail, oldest-first. Each entry:

| Field | Type | Description |
|---|---|---|
| `type` | string | Event kind — e.g. `created`, `sent`, `viewed`, `signed`, `voided`. |
| `signer_id` | integer \| null | The signer the event concerns, when applicable. |
| `detail` | string | Human-readable detail (e.g. `to dana@example.com`). |
| `at` | number | Unix epoch seconds. |

> The `events` array is present on this single-envelope GET, not on the list. For the machine-readable Certificate of Completion (a sealed PDF), use `GET /api/mysign/agreements/{aid}/certificate` once the envelope is `completed`.

A `404 {"error":"not found"}` here means no envelope with that id is owned by your account — the API does not distinguish "doesn't exist" from "not yours".

---

## Delete a draft

```
DELETE /api/mysign/agreements/{aid}
```

Permanently delete a **draft** envelope along with its child rows (signers, fields, events) and its stored PDF. Once an envelope has been sent it is a legal record and **cannot be deleted** — [void](./08-sending-and-tracking.md) it instead.

**curl**

```bash
curl -X DELETE https://sign.example.com/api/mysign/agreements/42 \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY…"
# → { "ok": true }
```

**Python**

```python
ls.delete(42)     # raises LiftedSignError on 404 / 409
```

**Node**

```js
await ls.delete(42);   // throws LiftedSignError on 404 / 409
```

**Responses**

| Status | Body | When |
|---|---|---|
| `200` | `{ "ok": true }` | Draft deleted. |
| `404` | `{ "ok": false, "error": "not_found" }` | No such envelope owned by this account. |
| `409` | `{ "ok": false, "error": "locked" }` | Envelope already sent — void it, don't delete it. |

Unlike the soft in-body lock on the editing endpoints (below), `DELETE` on a sent envelope is a hard `409`.

---

## Draft immutability

An envelope is only editable while its `status` is `draft`. The moment you send it, `send` freezes the presented PDF bytes (that snapshot is what every signer sees and what the `doc_hash` covers), and the structural editing endpoints refuse further changes. **How** they refuse depends on the endpoint — this is the part most integrations get wrong, so it's spelled out precisely:

| Endpoint | On a sent envelope |
|---|---|
| `POST …/signers` | `200` `{"ok": false, "error": "locked — already sent"}` |
| `POST …/fields` | `200` `{"ok": false, "error": "locked — already sent"}` |
| `POST …/order-mode` | `200` `{"ok": false, "error": "locked — already sent"}` |
| `POST …/pages/reorder` · `…/pages/rotate` · `…/pages/delete` · `…/pages/add` | `409` `{"ok": false, "error": "locked — already sent"}` |
| `POST …/text` · `…/edit-text` · `…/redact` | `409` `{"ok": false, "error": "locked — already sent"}` |
| `DELETE …` | `409` `{"ok": false, "error": "locked"}` |

Two conventions are at play:

- **Signer / field / order-mode edits** return a **soft, in-body rejection with HTTP `200`** — `{"ok": false, "error": "locked — already sent"}`. Check `ok`, never the status code. The vendored SDKs already treat an `{"ok": false}` body as an error and raise `LiftedSignError` (status `200`, with the body attached), so a locked edit never passes silently.
- **Page-structure and content edits** (`/pages/*`, `/text`, `/edit-text`, `/redact`) and `DELETE` return an HTTP **`409`** instead.

Either way the rule is the same: a sent, completed, voided, or otherwise terminal envelope is frozen. To change a sent document you cannot edit it — void the envelope and send a fresh one. The only lifecycle actions still available after send are `remind` (re-notify pending signers), `void` (revoke it), and the read/download endpoints.

---

## Reference

### Envelope object

| Field | Type | Description |
|---|---|---|
| `id` | integer | Unique envelope id. |
| `name` | string | Envelope name. |
| `message` | string | Optional note shown to signers in the invitation email. |
| `status` | string | Lifecycle state — see [status vocabulary](#envelope-status). |
| `order_mode` | string | Signing routing — `sequential` or `parallel`. |
| `created_by` | string | Free-text display name of the creator (never used for authorization). |
| `doc_hash` | string | SHA-256 of the current document bytes. |
| `created_at` | number | Unix epoch seconds when created. |
| `sent_at` | number \| null | Unix epoch seconds when sent (`null` while draft). |
| `completed_at` | number \| null | Unix epoch seconds when completed (`null` otherwise). |
| `signers` | array | Signer rows — see [Signers](./05-signers-and-routing.md). |
| `fields` | array | Placed fields — see [Placing fields](./06-placing-fields.md). |
| `events` | array | Ordered audit trail (single-envelope GET only). |

Required in every serialization: `id`, `name`, `status`, `created_at`, `signers`, `fields`.

### Envelope status

| Status | Meaning |
|---|---|
| `draft` | Being prepared. Editable. Not yet sent. |
| `out_for_signature` | Sent; awaiting one or more signatures. PDF frozen. |
| `completed` | Every signer has signed. Executed PDF + Certificate downloadable. |
| `declined` | A signer declined. Terminal. |
| `voided` | Sender voided it; all live signing links revoked. Terminal. |
| `expired` | Auto-expired; signing window elapsed. Terminal. |

### Signer status

| Status | Meaning |
|---|---|
| `pending` | Created, not yet notified (e.g. later in a sequential order). |
| `sent` | Signing invite emailed. |
| `viewed` | Signer opened the document. |
| `signed` | Signer completed and signed. |
| `declined` | Signer declined to sign. |

### Status codes

| Code | When |
|---|---|
| `200` | Success — **including** a soft `{"ok": false, "error": "locked — already sent"}` in-body lock on `/signers`, `/fields`, `/order-mode`. |
| `400` | Bad upload on create (see the rejection table above). |
| `401` | Missing or invalid API key. |
| `404` | No such envelope owned by this account (existence not leaked). |
| `409` | Locked — `DELETE` on a sent envelope, or a page/content edit after send. |
| `429` | Rate limited. Per-account limits may apply on the managed cloud — handle it defensively: back off and retry with jitter. |

---

## What's next

- [Signers](./05-signers-and-routing.md) — add, order, and authenticate the people who sign.
- [Placing fields](./06-placing-fields.md) — drop signature, date, and text fields by anchor, points, or normalized coordinates.
- [Sending & lifecycle](./08-sending-and-tracking.md) — dispatch, remind, void, and download the sealed document.
- [Templates](./07-templates-and-prefill.md) — build a document once and spin up prefilled envelopes from it.
- [Webhooks](./12-webhooks-and-polling.md) — subscribe to signed event deliveries as an envelope changes (or poll `GET /api/mysign/agreements/{aid}` until `status` is `completed`).
