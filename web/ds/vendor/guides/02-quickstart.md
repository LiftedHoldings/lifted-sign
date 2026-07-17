# Quickstart — send your first document for signature

In about five minutes you'll take a PDF and turn it into a legally binding,
certificate-backed signature request. The whole flow is five calls:

1. **Mint an API key** in the dashboard.
2. **Create an envelope** by uploading a PDF (`multipart/form-data`).
3. **Add a signer** (name + email).
4. **Place a signature field by anchor** — you name text that already exists in
   the PDF and the field snaps to it. No coordinate math.
5. **Send** — Lifted Sign freezes the bytes and emails the signer a single-use
   link.

Everything is scoped to the account your key belongs to. Base URL for every
request is `https://sign.example.com`.

---

## 0. Mint an API key

Open the **Developers** tab of your [Lifted Sign dashboard](https://sign.example.com),
create a key, and copy it. The full key is shown **once** — store it in your
secret manager.

Keys come in two modes:

| Prefix | Mode | Use for |
| --- | --- | --- |
| `sk_test_…` | Sandbox | Development. Nothing is billed. |
| `sk_live_…` | Production | Real, sent, legally binding documents. |

Every request authenticates with the key as a **Bearer token**:

```http
Authorization: Bearer $LIFTED_SIGN_KEY
```

Keys are server-side secrets — never embed one in a browser or mobile app. A
missing or invalid key returns `401 {"error":"unauthorized"}`. Requesting an
envelope your account doesn't own returns `404 {"error":"not found"}` (existence
is never leaked).

Export it into your shell so the examples below run as-is:

```bash
export LIFTED_SIGN_KEY=sk_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

---

## The whole flow in curl

### 1. Create an envelope from a PDF

`POST /api/mysign/agreements` is `multipart/form-data`: a `file` part (the PDF,
max 60 MB) and an optional `name` (defaults to the filename). Encrypted,
zero-page, non-PDF, and corrupt files are rejected with a `400` before any
envelope is created.

```bash
curl -sS https://sign.example.com/api/mysign/agreements \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -F "file=@contract.pdf;type=application/pdf" \
  -F "name=Master Services Agreement"
```

```json
{ "ok": true, "id": 42 }
```

Keep that `id` — it's the envelope id (`aid`) for every call below. The
envelope starts as a **draft**; signers and fields can only be changed while it
stays a draft.

### 2. Add a signer

`POST /api/mysign/agreements/{aid}/signers` **replaces the entire signer set**.
Each signer needs a `name` and `email`; `role`, `order`, and `auth` are
optional (`auth` defaults to `email`, the single-use link).

```bash
curl -sS https://sign.example.com/api/mysign/agreements/42/signers \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "signers": [
          { "name": "Dana Client", "email": "dana@example.com" }
        ]
      }'
```

```json
{
  "ok": true,
  "signers": [
    {
      "id": 101,
      "name": "Dana Client",
      "email": "dana@example.com",
      "role": "signer",
      "sign_order": 1,
      "status": "pending",
      "auth_method": "email",
      "color": "#2F6FED"
    }
  ]
}
```

### 3. Place a signature field — by anchor

`POST /api/mysign/agreements/{aid}/fields` replaces the whole field layout in
one fail-closed batch. The easy way to say *where* a field goes is **anchor
placement**: name text that already exists in the document (`"Signature:"`) and
the field snaps beside it. The match is case-insensitive and spans word
boundaries — you never render the PDF or do coordinate math.

Because this envelope has exactly one signer, you can even omit `signer` and it
defaults to that signer. We'll be explicit here:

```bash
curl -sS https://sign.example.com/api/mysign/agreements/42/fields \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "fields": [
          { "signer": "dana@example.com", "type": "signature", "anchor": "Signature:" }
        ]
      }'
```

```json
{
  "ok": true,
  "count": 1,
  "fields": [
    {
      "type": "signature",
      "anchor": "Signature:",
      "signer_id": 101,
      "page": 0,
      "x": 0.217,
      "y": 0.347,
      "w": 0.294,
      "h": 0.056,
      "placed": true
    }
  ]
}
```

**Fail-closed:** if the anchor text isn't found (or any field can't be
resolved), the whole batch is rejected and **nothing is written** — a `400`
with a machine `error` code and the offending `field` index:

```json
{ "ok": false, "error": "anchor_not_found", "field": 0, "detail": "Signature:" }
```

> If your PDF doesn't contain a literal `Signature:` label, either add one to
> the document or place the field by coordinates instead — see
> [Placing fields](./06-placing-fields.md).

### 4. Send

`POST /api/mysign/agreements/{aid}/send` freezes the presented PDF, generates a
single-use token per signer, emails each their link, and moves the envelope to
`out_for_signature`. The optional `message` is included in the invite.

```bash
curl -sS https://sign.example.com/api/mysign/agreements/42/send \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "message": "Please countersign by Friday. Thanks!" }'
```

```json
{
  "ok": true,
  "emailed": 1,
  "email_errors": [],
  "links": [
    {
      "signer_id": 101,
      "name": "Dana Client",
      "email": "dana@example.com",
      "token": "EXAMPLE-signer-token-xxxx",
      "url": "https://sign.example.com/sign/EXAMPLE-signer-token-xxxx"
    }
  ]
}
```

Dana now has a signing link in her inbox. The `links` array is returned to you
too — handy if you'd rather deliver the link yourself.

> **Two hard 403s to know about.** Send returns `403` and sends nothing if your
> subscription is inactive (`{"ok": false, "error": "subscription_inactive",
> "billing": true}`) or your sending email is unverified
> (`{"ok": false, "error": "email_unverified"}`). Business rejections like *no
> signers* or *already sent* come back in-body with HTTP **200** and
> `"ok": false` instead.

That's it — you've sent your first document. 🎉

---

## The same flow in Python

Drop [`lifted_sign.py`](../../../web/ds/vendor/sdk/lifted_sign.py) into your
project — it's one file, standard library only, no `pip install`.

```python
from lifted_sign import LiftedSign

ls = LiftedSign()  # reads LIFTED_SIGN_KEY from the environment

env = ls.create_agreement("contract.pdf", name="Master Services Agreement")
aid = env["id"]

ls.add_signers(aid, [{"name": "Dana Client", "email": "dana@example.com"}])

ls.place_fields(aid, [
    {"signer": "dana@example.com", "type": "signature", "anchor": "Signature:"},
])

result = ls.send(aid)
print(f"sent — emailed {result['emailed']} signer(s)")
print(result["links"][0]["url"])
```

The client raises `LiftedSignError` on any HTTP error **and** on a soft
`{"ok": false}` body (e.g. a `locked — already sent` or `anchor_not_found`
rejection) — so a failed placement never silently drops a field on a legal
document. Catch it if you want to inspect `.status` and `.body`:

```python
from lifted_sign import LiftedSign, LiftedSignError

try:
    ls.place_fields(aid, [{"type": "signature", "anchor": "Nowhere:"}])
except LiftedSignError as e:
    print(e.status, e.body)  # 400 {'ok': False, 'error': 'anchor_not_found', 'field': 0, ...}
```

You can also run the SDK straight from a shell to send in one command:

```bash
export LIFTED_SIGN_KEY=sk_live_xxx
python lifted_sign.py contract.pdf dana@example.com "Dana Client"
```

---

## The same flow in Node

Drop [`lifted-sign.mjs`](../../../web/ds/vendor/sdk/lifted-sign.mjs) into your
project — one file, no `npm install` (built-in `fetch`/`FormData`, Node 18+).

```javascript
import { LiftedSign } from "./lifted-sign.mjs";

const ls = new LiftedSign(); // reads LIFTED_SIGN_KEY from the env

const env = await ls.createAgreement("contract.pdf", { name: "Master Services Agreement" });

await ls.addSigners(env.id, [{ name: "Dana Client", email: "dana@example.com" }]);

await ls.placeFields(env.id, [
  { signer: "dana@example.com", type: "signature", anchor: "Signature:" },
]);

const result = await ls.send(env.id);
console.log(`sent — emailed ${result.emailed} signer(s)`);
console.log(result.links[0].url);
```

Like the Python client, `placeFields`/`send` throw a `LiftedSignError` (with
`.status` and `.body`) on both HTTP errors and soft `{ ok: false }` rejections.
Run it directly, too:

```bash
export LIFTED_SIGN_KEY=sk_live_xxx
node lifted-sign.mjs contract.pdf dana@example.com "Dana Client"
```

---

## What just happened

- **You created an envelope** — a PDF plus its signers, fields, and audit trail
  — starting life as a `draft`.
- **Signers and fields are draft-only.** Once sent, the presented bytes are
  frozen. Trying to edit signers/fields on a sent envelope returns
  `{"ok": false, "error": "locked — already sent"}` with HTTP 200. A sent
  envelope is a legal record: you can `void` it, but you can't edit or delete it
  (deleting a sent envelope returns `409`).
- **The anchor did the layout for you.** The server found `Signature:` in the
  PDF text and reported back where the field landed in normalized `0..1` page
  fractions.
- **Sending froze the document, minted a single-use token per signer, and
  emailed the links.** The envelope moved from `draft` → `out_for_signature`.

When Dana authenticates, consents, and signs, the envelope accrues audit events
and — once every signer is done — becomes `completed`. At that point the
executed, sealed PDF and the **Certificate of Completion** (IPs, timestamps,
consent, authentication events) become downloadable.

### Envelope status vocabulary

`draft` · `out_for_signature` · `completed` · `declined` · `voided` ·
`cancelled`

### Signer status vocabulary

`pending` · `sent` · `viewed` · `signed` · `declined`

### Track and collect the result

```bash
# Current state, signers, fields, and the full audit trail
curl -sS https://sign.example.com/api/mysign/agreements/42 \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"

# Once completed: the executed, sealed PDF
curl -sS https://sign.example.com/api/mysign/agreements/42/download \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" -o contract-SIGNED.pdf

# And the Certificate of Completion (completed envelopes only)
curl -sS https://sign.example.com/api/mysign/agreements/42/certificate \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" -o certificate.pdf
```

> **No webhooks yet.** Lifted Sign doesn't push events to your endpoint. Until
> it does, poll the envelope (`GET /api/mysign/agreements/{aid}`) and watch
> `status` move to `completed`. See [Webhooks](./12-webhooks-and-polling.md) for the
> roadmap and a polling pattern.

---

## Next steps

- [Authentication](./03-authentication.md) — keys, modes, rotation, and scoping.
- [Envelopes](./04-envelopes.md) — the full lifecycle: list, read, void, delete.
- [Signers & signing order](./05-signers-and-routing.md) — roles, `sequential` vs
  `parallel` routing, and signer authentication (`email`, `email_otp`,
  `access_code`).
- [Placing fields](./06-placing-fields.md) — anchor, absolute points, and
  normalized coordinates; every field type and its default size.
- [Templates & prefill](./07-templates-and-prefill.md) — build a document once and spin up
  ready-to-send drafts with `answers`.
- [Downloads & certificates](./09-downloads-and-certificates.md) — the source PDF, the executed
  PDF, and the audit certificate.
