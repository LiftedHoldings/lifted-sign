# Signers & routing

A **signer** is a person you invite to sign an envelope. You attach the whole signer set with a single call, choose how each one authenticates, and decide whether they sign all at once or one after another. This guide covers setting signers, the routing modes, the signer status vocabulary, and the `is_consumer` flag for B2C ESIGN disclosures.

Base URL: `https://sign.example.com` · Auth: `Authorization: Bearer $LIFTED_SIGN_KEY…` (or `sk_test_…`). See [Authentication](./03-authentication.md).

> **Draft-only.** Signers and the order mode can only be changed while the envelope is a `draft`. Once you [send](./08-sending-and-tracking.md), the signer set is frozen — these calls return `{"ok": false, "error": "locked — already sent"}` with HTTP **200**.

---

## Set the signers (replace-all)

`POST /api/mysign/agreements/{aid}/signers` **replaces the envelope's entire signer set** with the array you pass. It is not additive — send the complete list every time, including anyone already on the envelope. There is no per-signer add/remove/patch endpoint; the whole set is the unit of change.

Each signer needs a `name` and an `email`. Everything else is optional.

### Request body

```json
{
  "signers": [
    { "name": "Dana Client",  "email": "dana@example.com", "role": "Client",  "order": 1, "auth": "email" },
    { "name": "Sam Counsel",  "email": "sam@example.com",  "role": "Counsel", "order": 2, "auth": "access_code" }
  ]
}
```

### Signer input fields

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `name` | string | yes | — | Display name shown on the signing page and Certificate. |
| `email` | string | yes | — | Where the single-use signing link is sent. **Lowercased and trimmed** server-side — it is also how you reference the signer when [placing fields](./06-placing-fields.md) (`"signer": "dana@example.com"`). |
| `role` | string | no | `signer` | Free-text label (e.g. `Client`, `Counsel`, `Witness`). Cosmetic — never used for authorization. |
| `order` | integer | no | array position (1-based) | 1-based signing order. Only meaningful in `sequential` mode (see [Routing](#routing-sequential-vs-parallel)). |
| `auth` | string | no | `email` | Authentication method: `email`, `email_otp`, or `access_code`. An unrecognized value is coerced to `email`. |
| `is_consumer` | boolean | no | `false` | Marks a B2C signer so they receive the consumer ESIGN disclosure. See [`is_consumer`](#is_consumer-the-b2c-esign-disclosure). |

### curl

```bash
curl -sS -X POST \
  https://sign.example.com/api/mysign/agreements/42/signers \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "signers": [
          { "name": "Dana Client", "email": "dana@example.com", "role": "Client",  "order": 1, "auth": "email" },
          { "name": "Sam Counsel", "email": "sam@example.com",  "role": "Counsel", "order": 2, "auth": "email_otp" }
        ]
      }'
```

### Response

On success, `ok` is `true` and `signers` echoes the **stored rows** — note the field renames: your input `order` comes back as `sign_order`, and `auth` comes back as `auth_method`. Every new signer starts at `status: "pending"`, and the server assigns each a UI `color`.

```json
{
  "ok": true,
  "signers": [
    {
      "id": 101,
      "name": "Dana Client",
      "email": "dana@example.com",
      "role": "Client",
      "sign_order": 1,
      "status": "pending",
      "auth_method": "email",
      "color": "#2F6FED"
    }
  ]
}
```

### Python & Node

Both vendored SDKs expose this as `add_signers` / `addSigners` — the name reads additive, but the call **replaces** the full set (it posts to the same replace-all endpoint). Pass every field inline; the SDK forwards the JSON untouched.

```python
# lifted_sign.py
from lifted_sign import LiftedSign

ls = LiftedSign(api_key="sk_live_...")
ls.add_signers(42, [
    {"name": "Dana Client", "email": "dana@example.com", "role": "Client",  "order": 1, "auth": "email"},
    {"name": "Sam Counsel", "email": "sam@example.com",  "role": "Counsel", "order": 2, "auth": "access_code"},
])
```

```javascript
// lifted-sign.mjs
import { LiftedSign } from "./lifted-sign.mjs";

const ls = new LiftedSign({ apiKey: "sk_live_..." });
await ls.addSigners(42, [
  { name: "Dana Client", email: "dana@example.com", role: "Client",  order: 1, auth: "email" },
  { name: "Sam Counsel", email: "sam@example.com",  role: "Counsel", order: 2, auth: "access_code" },
]);
```

### Draft-lock (soft rejection)

Calling `/signers` on an already-sent envelope does not raise a 4xx — it returns HTTP **200** with a soft rejection body:

```json
{ "ok": false, "error": "locked — already sent" }
```

Always check `ok`, not just the HTTP status. (The Python and Node SDKs surface an `{"ok": false}` body as a raised `LiftedSignError`.)

---

## Authentication methods

`auth` selects how a signer proves who they are before signing. It defaults to `email`.

| `auth` value | How the signer authenticates | When to use |
|--------------|------------------------------|-------------|
| `email` (default) | Possession of the single-use tokenized link emailed to their address. The link **is** the factor. | The common case — low friction, still auditable (the authentication event is recorded). |
| `email_otp` | Email link **plus** a one-time passcode delivered to the same address. | A second challenge before the document opens. |
| `access_code` | Email link **plus** a shared secret code you communicate out of band (phone, in person). | Higher assurance where you don't want email possession alone to grant access. |

The chosen method is stored per-signer and echoed back as `auth_method`. It is also written into the audit trail at send time (a `SIGNER_AUTHENTICATED` event records `auth=<method>` for each signer), so the Certificate of Completion reflects exactly how each person was challenged.

---

## Routing: sequential vs. parallel

An envelope has an **order mode** that decides who gets notified when you [send](./08-sending-and-tracking.md). Set it with:

`POST /api/mysign/agreements/{aid}/order-mode`

```json
{ "mode": "sequential" }
```

| Mode | Meaning |
|------|---------|
| `parallel` (default) | Every signer is emailed their link **at once**. Anyone can sign in any order. |
| `sequential` | Signers are routed by their `order`. Only the **first order-group** is notified first; each later group is emailed automatically as the prior group finishes. |

### curl

```bash
curl -sS -X POST \
  https://sign.example.com/api/mysign/agreements/42/order-mode \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "mode": "sequential" }'
```

### Response

```json
{ "ok": true, "order_mode": "sequential" }
```

Errors come back **in-body with HTTP 200**, not as 4xx: `bad_mode` (a value other than `sequential`/`parallel`), `not_found` (no such draft you own), or `locked` (the envelope is already sent).

```json
{ "ok": false, "error": "bad_mode" }
```

> The order mode, like the signer set, is **draft-only** — `send()` reads it once to decide the first notification, so changing it after sending has no effect.

### How `send()` uses the order mode

This is the mechanism to keep in mind:

- **`parallel`** — on send, *all* signers receive their email immediately. `order` is ignored.
- **`sequential`** — on send, only the signers in the **lowest `order` group** (the smallest `order` value among signers who haven't signed) are emailed. When every signer in that group has signed, the next group up is emailed automatically, and so on until the last group completes and the envelope becomes `completed`.

Signers that share the same `order` value form **one group**: within a group they sign in parallel; across groups they sign in sequence. So `order: [1, 1, 2]` emails the two `order:1` signers together, then emails the `order:2` signer once both have signed.

One nuance worth knowing: on send, every signer immediately gets a minted token and moves to `status: "sent"`, but in `sequential` mode the **email** to a later group is held back until its turn. A later-group signer can therefore read `sent` before their invitation actually lands in their inbox.

### A complete two-signer sequential setup

```bash
# 1. add both signers with explicit order
curl -sS -X POST https://sign.example.com/api/mysign/agreements/42/signers \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" -H "Content-Type: application/json" \
  -d '{"signers":[
        {"name":"Dana Client","email":"dana@example.com","order":1,"auth":"email"},
        {"name":"Sam Counsel","email":"sam@example.com","order":2,"auth":"email"}
      ]}'

# 2. route them one-at-a-time
curl -sS -X POST https://sign.example.com/api/mysign/agreements/42/order-mode \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" -H "Content-Type: application/json" \
  -d '{"mode":"sequential"}'

# 3. send — only Dana (order 1) is emailed now; Sam is emailed after Dana signs
curl -sS -X POST https://sign.example.com/api/mysign/agreements/42/send \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" -H "Content-Type: application/json" -d '{}'
```

---

## Signer status vocabulary

A signer moves through these states. Read them on any envelope via `GET /api/mysign/agreements/{aid}` (the `signers[].status` field).

| Status | Meaning |
|--------|---------|
| `pending` | Added to a draft, not yet sent. The starting state for every new signer. |
| `sent` | The envelope was sent and a single-use token was minted for this signer. (In `sequential` mode a later-group signer is `sent` before their email actually goes out — see the nuance above.) |
| `viewed` | The signer opened their signing link. |
| `signed` | The signer completed and applied their signature. |
| `declined` | The signer declined to sign. |

These are the **signer** statuses. The **envelope** has its own separate lifecycle (`draft` · `out_for_signature` · `completed` · `declined` · `voided` · `cancelled`) — see [Envelopes](./04-envelopes.md) and [Sending & tracking](./08-sending-and-tracking.md).

---

## `is_consumer`: the B2C ESIGN disclosure

Set `is_consumer: true` on any signer who is an individual consumer (a B2C signer) rather than a business counterparty. It selects the **consumer** variant of the ESIGN/UETA electronic-records consent disclosure that the signer must agree to before signing, satisfying the ESIGN Act's consumer-disclosure requirements. Business signers (the default, `is_consumer: false`) get the standard business consent.

```json
{
  "signers": [
    { "name": "Jordan Buyer", "email": "jordan@personalmail.com", "role": "Buyer", "is_consumer": true },
    { "name": "Acme Corp",    "email": "legal@acme.com",          "role": "Seller" }
  ]
}
```

`is_consumer` is a property of the **signer**, so different recipients on the same envelope can get different disclosures. It also carries through templates: `recipients` on [`POST /templates/{tid}/use`](./07-templates-and-prefill.md) accepts `is_consumer` per recipient.

---

## Next steps

- [Placing fields](./06-placing-fields.md) — put signature, initial, date, and text fields where each signer signs (reference signers by the `email` you set here).
- [Sending & tracking](./08-sending-and-tracking.md) — freeze and dispatch the envelope, poll signer status, and remind pending signers.
- [Templates & prefill](./07-templates-and-prefill.md) — save a signer layout once and fill roles per use.
- [Errors & reliability](./10-errors-and-reliability.md) — the full soft-rejection vs. HTTP-status convention.
