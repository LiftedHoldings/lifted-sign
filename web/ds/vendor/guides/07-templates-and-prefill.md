# Templates & prefill

Build a document once, then mint ready-to-send drafts from it for the rest of its life. A **template** is a snapshot of an envelope you already own — its source PDF, its signer roles, and its field layout — with no signatures attached. Call `POST /api/mysign/templates/{tid}/use` whenever you need a fresh copy, hand it the values that change (`answers`) and the people who sign it (`recipients`), and you get back a prefilled **draft** you can `send`.

Base URL is `https://sign.example.com`. Every call authenticates with a Bearer key (`sk_live_…` in production, `sk_test_…` against test data):

```
Authorization: Bearer $LIFTED_SIGN_KEY
```

Templates are **owner-scoped**: you only ever list, read, use, or archive your own. A template id that belongs to another account is reported as `404 { "error": "not found" }` — never a `403` — so the API never confirms that someone else's template exists.

---

## The two kinds of fill-in

A field on the document is filled by one of two parties, and templates care about the difference:

| | **Signer field** | **Prefill field** |
|---|---|---|
| Filled by | the recipient, in the signing UI | you (the sender), at `use` time |
| Marked with | `signer` / `signer_index` | `prefill: true` + `field_key` + `prompt` |
| Value source | the signer's ink/typing | the `answers` map on `POST …/use` |
| Example | signature, date, initials | company name, effective date, contract amount |

A **prefill field** is text you already know when you generate the document — the customer's company, today's date, a dollar figure — so there's no reason to make a human type it. You place it once, key it with a stable `field_key`, and supply the value per use.

---

## Marking a prefill field when you place it

Prefill fields are placed with the same `POST /api/mysign/agreements/{aid}/fields` call as everything else (see [Placing fields](./06-placing-fields.md)). Add three properties: `prefill: true`, a stable `field_key`, and a human-readable `prompt`.

```bash
curl -sS https://sign.example.com/api/mysign/agreements/42/fields \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "fields": [
      { "signer": "dana@example.com", "type": "signature", "anchor": "Signature:" },
      { "type": "company", "anchor": "Company:", "prefill": true,
        "field_key": "company", "prompt": "Company name" },
      { "type": "date", "anchor": "Effective Date:", "prefill": true,
        "field_key": "effective_date", "prompt": "Effective date" }
    ]
  }'
```

| Field property | Type | Meaning |
|---|---|---|
| `prefill` | boolean (default `false`) | Marks the field as sender-filled — it does **not** belong to a signer. |
| `field_key` | string | Stable key the `answers` map is keyed by. Keep it short and machine-friendly (`company`, `effective_date`). |
| `prompt` | string | The question shown for the field (e.g. `"Company name"`). This is what a caller reads back to know what to supply. |

> **`POST /fields` is replace-all.** Each call to `/fields` deletes the envelope's existing fields and writes the batch you sent. Send **all** fields — signer and prefill — in one call, or place signer fields first and use [auto-detect](#auto-detecting-prefill-fields) (which is additive) to append prefill fields afterward. Never place signer fields *after* a detect run, or you'll wipe the detected fields.

---

## Saving an envelope as a template

Once an envelope has the layout you want, snapshot it. Any envelope you own works — `draft`, `out_for_signature`, or `completed` — because only the **layout** is copied, never the signatures or the executed bytes.

```bash
curl -sS https://sign.example.com/api/mysign/templates \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "agreement_id": 42, "name": "MSA template" }'
```

```json
{ "ok": true, "id": 5 }
```

**Request body**

| Field | Required | Description |
|---|---|---|
| `agreement_id` | yes | The envelope to snapshot. Must belong to your account. |
| `name` | no | Template name. Defaults to the envelope's name. |

**Responses**

| Status | Body | When |
|---|---|---|
| `200` | `{ "ok": true, "id": 5 }` | Template created; `id` is the new template id. |
| `400` | `{ "ok": false, "error": "agreement not found" }` | The source envelope isn't yours (or doesn't exist). |
| `400` | `{ "ok": false, "error": "source document not allowed" }` | The snapshot's source PDF couldn't be read. |
| `401` | — | Missing or invalid API key. |

---

## Listing and reading templates

`GET /api/mysign/templates` returns your templates, newest first, each with its full field layout — so you can read the prefill fields' `field_key` and `prompt` to know what a `use` call needs.

```bash
curl -sS https://sign.example.com/api/mysign/templates \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"
```

```json
{
  "templates": [
    {
      "id": 5,
      "name": "MSA template",
      "created_at": 1752624000.0,
      "page_n": 4,
      "signer_n": 1,
      "field_n": 3,
      "has_source": true,
      "signers": [ { "name": "", "email": "", "role": "Client", "order": 1 } ],
      "fields": [
        { "signer_index": 0, "type": "signature", "page": 3, "x": 0.12, "y": 0.78,
          "w": 0.30, "h": 0.06, "required": true, "prefill": false, "field_key": "", "prompt": "" },
        { "signer_index": 0, "type": "company", "page": 0, "x": 0.30, "y": 0.14,
          "w": 0.25, "h": 0.03, "required": true, "prefill": true,
          "field_key": "company", "prompt": "Company name" }
      ]
    }
  ]
}
```

`GET /api/mysign/templates/{tid}` returns one template under a `template` key with the same shape. This is the canonical way to discover a template's `answers` — filter its `fields` to `prefill: true` and collect each `field_key` + `prompt`:

```bash
curl -sS https://sign.example.com/api/mysign/templates/5 \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"
```

**Template fields**

| Field | Description |
|---|---|
| `id`, `name`, `created_at` | Identity. `created_at` is Unix epoch seconds. |
| `page_n`, `signer_n`, `field_n` | Counts of pages, signer roles, and fields. |
| `has_source` | Whether a source PDF is stored (a template with `has_source: false` cannot be `use`d — see below). |
| `signers[]` | The signer roles: `name`, `email`, `role`, `order`. Roles are usually blank templates — you fill them via `recipients` on `use`. |
| `fields[]` | The saved layout. Each has `signer_index` (into `signers`), `type`, normalized `x/y/w/h`, `required`, and — for prefill fields — `prefill: true`, `field_key`, `prompt`. |

A missing or cross-tenant `tid` returns `404 { "error": "not found" }`.

---

## Using a template to mint a prefilled draft

`POST /api/mysign/templates/{tid}/use` instantiates a fresh **draft** envelope from the template. Supply `recipients` to fill the signer roles by position and `answers` to fill the prefill fields. Everything in the body is optional.

```bash
curl -sS https://sign.example.com/api/mysign/templates/5/use \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MSA — Acme Corp",
    "recipients": [ { "name": "Dana Client", "email": "dana@example.com" } ],
    "answers": { "company": "Acme Corp", "effective_date": "2026-08-01" }
  }'
```

```json
{ "ok": true, "id": 43, "template_id": 5 }
```

`id` is the new draft envelope. It comes back prefilled and ready to `send` (see [Sending](./08-sending-and-tracking.md)).

**Request body** ([`UseTemplateInput`])

| Field | Type | Description |
|---|---|---|
| `name` | string | Name for the new draft. Defaults to the template name. |
| `recipients` | array | Signers to fill the template's roles **by position**. Each may set `name`, `email`, `role`, `auth`, `is_consumer`. Extra recipients beyond the template's roles are appended. |
| `answers` | object | Prefill values, keyed by `field_key` **or** positional index (as a string). Values are strings. |

### How `answers` keys resolve

`answers` accepts two kinds of key, and **`field_key` wins** when both could match a field:

- **By `field_key`** (recommended): `{ "company": "Acme Corp" }` fills the prefill field whose `field_key` is `company`. Stable across layout edits — this is the API-friendly path.
- **By positional index** (as a string): `{ "1": "Acme Corp" }` fills the *second* prefill-eligible field by its position in the template's `fields` list. This is what the web questionnaire uses; fragile if the layout changes.

Prefer `field_key`. Read the keys straight off `GET /api/mysign/templates/{tid}`. Unknown keys are ignored; prefill fields you don't answer keep their stored default (usually blank).

**Responses**

| Status | Body | When |
|---|---|---|
| `200` | `{ "ok": true, "id": 43, "template_id": 5 }` | A new draft was created. |
| `400` | `{ "ok": false, "error": "template has no source document" }` | The template's stored PDF is missing (`has_source: false`). |
| `404` | `{ "error": "not found" }` | The `tid` isn't yours or doesn't exist. |
| `401` | — | Missing or invalid API key. |

---

## Auto-detecting prefill fields

Placing prefill fields by hand is optional. `POST /api/mysign/agreements/{aid}/detect` scans a **draft** envelope's PDF and adds a prefill field for every fill-in it recognizes — no coordinates, no AI, fully deterministic and local.

It looks for two things:

1. **Merge tokens** — `{{company}}`, `[amount]`, `<<effective_date>>`. The token name becomes the `field_key`.
2. **Common labels** — `Company Name:`, `Effective Date:`, and similar. A field is placed to the right of the label, typed by what the label means (`company`, `date`, `title`, `name`, `email`, `text`).

```bash
curl -sS https://sign.example.com/api/mysign/agreements/42/detect \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -X POST
```

```json
{
  "ok": true,
  "added": 1,
  "detected": 1,
  "fields": [
    { "type": "company", "page": 0, "x": 0.30, "y": 0.14, "w": 0.25, "h": 0.03,
      "required": true, "prefill": 1, "field_key": "company",
      "prompt": "Company", "placeholder": "Company" }
  ]
}
```

**Response**

| Field | Description |
|---|---|
| `ok` | `true` when detection ran. |
| `added` | Count of **new** prefill fields written this call. |
| `detected` | Total candidates found (including ones already present). |
| `fields[]` | The newly added prefill fields (a detected field carries `prefill: 1` and no `signer_id`). |

**Two things to internalize about `detect`:**

- **It is additive and idempotent.** Detected fields are merged onto the envelope's existing fields; a field whose `field_key` is already present is not duplicated. Re-running is safe and cheap.
- **Run it *after* placing signer fields, never before.** `POST /fields` is replace-all — it would delete anything `detect` added. `detect` preserves existing fields, so the safe order is: place your signer fields → `detect` prefill fields → save as template.

**Soft rejections** come back with HTTP `200` and `ok: false` (mirroring `/fields`):

| Body | When |
|---|---|
| `{ "ok": false, "error": "locked — already sent" }` | The envelope isn't a draft. Fields are frozen once sent. |
| `{ "ok": false, "error": "no_source" }` | The envelope has no readable source PDF. |
| `404 { "error": "not found" }` | The `aid` isn't yours or doesn't exist (this one *is* a real `404`). |

---

## Archiving a template

`POST /api/mysign/templates/{tid}/archive` soft-archives a template so it drops out of the list. The snapshot is retained; it just stops appearing in `GET /api/mysign/templates`.

```bash
curl -sS https://sign.example.com/api/mysign/templates/5/archive \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -X POST
```

```json
{ "ok": true }
```

**Responses**

| Status | Body | When |
|---|---|---|
| `200` | `{ "ok": true }` | Archived. |
| `404` | `{ "error": "not found" }` | The template isn't yours **or is already archived**. A second archive of the same template returns `404`, not `200` — existence is never leaked. |
| `401` | — | Missing or invalid API key. |

---

## Full worked example: agreement → detect → save → use

This is the whole loop. Prepare an MSA once with `{{company}}` merge tokens in the PDF, let `detect` find them, save the layout as a template, then generate a per-customer draft with a single `answers` map.

### curl

```bash
BASE=https://sign.example.com
AUTH="Authorization: Bearer $LIFTED_SIGN_KEY"

# 1) Create a draft envelope from the PDF (the PDF contains {{company}} and Effective Date:)
AID=$(curl -sS "$BASE/api/mysign/agreements" -H "$AUTH" \
  -F "name=Master Services Agreement" \
  -F "file=@msa.pdf;type=application/pdf" | jq -r '.id')

# 2) Add the signer role and place the signature field (replace-all — do this FIRST)
curl -sS "$BASE/api/mysign/agreements/$AID/signers" -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "signers": [ { "name": "Dana Client", "email": "dana@example.com", "role": "Client" } ] }'

curl -sS "$BASE/api/mysign/agreements/$AID/fields" -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{ "fields": [ { "signer": "dana@example.com", "type": "signature", "anchor": "Signature:" } ] }'

# 3) Auto-detect prefill fields ({{company}}, Effective Date:) — additive, runs AFTER /fields
curl -sS "$BASE/api/mysign/agreements/$AID/detect" -H "$AUTH" -X POST
#  -> { "ok": true, "added": 2, "detected": 2, "fields": [ {"field_key":"company",...}, {"field_key":"effective_date",...} ] }

# 4) Save the whole layout as a reusable template
TID=$(curl -sS "$BASE/api/mysign/templates" -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d "{ \"agreement_id\": $AID, \"name\": \"MSA template\" }" | jq -r '.id')

# 5) Mint a prefilled draft for a specific customer — field_key-keyed answers
curl -sS "$BASE/api/mysign/templates/$TID/use" -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "MSA — Acme Corp",
        "recipients": [ { "name": "Sam Buyer", "email": "sam@acme.com" } ],
        "answers": { "company": "Acme", "effective_date": "2026-08-01" }
      }'
#  -> { "ok": true, "id": 44, "template_id": 5 }  — draft #44, prefilled, ready to send
```

### Python

The [vendored `lifted_sign.py`](../../../web/ds/vendor/sdk/lifted_sign.py) SDK wraps the envelope-build steps (`create_agreement`, `add_signers`, `place_fields`, `send`). The template endpoints aren't wrapped yet, so call them over its low-level `_json` helper — or with `requests`. Here it is end to end using the SDK for the build and its raw helper for templates:

```python
from lifted_sign import LiftedSign

ls = LiftedSign(api_key="sk_live_xxx")  # or set LIFTED_SIGN_KEY

# 1) build the envelope
env = ls.create_agreement("msa.pdf", name="Master Services Agreement")
aid = env["id"]
ls.add_signers(aid, [{"name": "Dana Client", "email": "dana@example.com", "role": "Client"}])
ls.place_fields(aid, [{"signer": "dana@example.com", "type": "signature", "anchor": "Signature:"}])

# 2) detect prefill fields (additive — after place_fields)
det = ls._json("POST", f"/api/mysign/agreements/{aid}/detect", {})
print("detected:", [f["field_key"] for f in det["fields"]])  # ['company', 'effective_date']

# 3) save as a template
tid = ls._json("POST", "/api/mysign/templates",
               {"agreement_id": aid, "name": "MSA template"})["id"]

# 4) inspect the template's prefill fields to learn the answer keys
tpl = ls._request("GET", f"/api/mysign/templates/{tid}")
prompts = {f["field_key"]: f["prompt"] for f in tpl["template"]["fields"] if f["prefill"]}
print(prompts)  # {'company': 'Company', 'effective_date': 'Effective Date'}

# 5) mint a prefilled draft
draft = ls._json("POST", f"/api/mysign/templates/{tid}/use", {
    "name": "MSA — Acme Corp",
    "recipients": [{"name": "Sam Buyer", "email": "sam@acme.com"}],
    "answers": {"company": "Acme", "effective_date": "2026-08-01"},
})
ls.send(draft["id"])  # draft is prefilled — send it straight out
```

### Node

```js
import { LiftedSign } from "./lifted-sign.mjs";

const ls = new LiftedSign({ apiKey: "sk_live_xxx" }); // or LIFTED_SIGN_KEY

// 1) build the envelope
const env = await ls.createAgreement("msa.pdf", { name: "Master Services Agreement" });
await ls.addSigners(env.id, [{ name: "Dana Client", email: "dana@example.com", role: "Client" }]);
await ls.placeFields(env.id, [{ signer: "dana@example.com", type: "signature", anchor: "Signature:" }]);

// 2) detect (additive — after placeFields)
const det = await ls._json("POST", `/api/mysign/agreements/${env.id}/detect`, {});
console.log("detected:", det.fields.map((f) => f.field_key)); // ['company','effective_date']

// 3) save as a template
const { id: tid } = await ls._json("POST", "/api/mysign/templates",
  { agreement_id: env.id, name: "MSA template" });

// 4) mint a prefilled draft (answers keyed by field_key)
const draft = await ls._json("POST", `/api/mysign/templates/${tid}/use`, {
  name: "MSA — Acme Corp",
  recipients: [{ name: "Sam Buyer", email: "sam@acme.com" }],
  answers: { company: "Acme", effective_date: "2026-08-01" },
});
await ls.send(draft.id);
```

---

## Rate limits

Template calls count against the standard **120 requests/minute** per account. Bursts above it get `429 Too Many Requests` — back off and retry with jitter. PDF uploads (the `create_agreement` step) are capped at **60 MB**.

## Webhooks?

Not yet. There's no push notification when a signer opens or completes a document generated from a template. Poll the envelope's status (see [Status](./08-sending-and-tracking.md)) until webhooks ship — the roadmap is in the [Webhooks guide](./12-webhooks-and-polling.md).

---

### See also

- [Placing fields](./06-placing-fields.md) — anchors, points, and normalized coordinates; how prefill fields are placed.
- [Sending](./08-sending-and-tracking.md) — dispatch a draft minted from a template.
- [Status](./08-sending-and-tracking.md) — poll an envelope's progress.
