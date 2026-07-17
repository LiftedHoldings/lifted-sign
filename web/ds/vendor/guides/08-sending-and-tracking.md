# Sending & tracking

You've created a draft, added signers, and placed fields ([Placing fields](./06-placing-fields.md)). This guide covers the second half of the lifecycle: **dispatching** the envelope for signature and **tracking** it to completion.

Everything here hits one base URL with a Bearer key:

```
https://sign.example.com
```

```http
Authorization: Bearer $LIFTED_SIGN_KEY
```

Use an `sk_test_…` key to rehearse the whole flow in sandbox first.

---

## Send for signature

`POST /api/mysign/agreements/{aid}/send` is the one-way door that turns a draft into a live signing request. In a single call it:

1. **Freezes the PDF** — snapshots the exact presented bytes into an immutable artifact and records its SHA-256 (`DOC_FROZEN`). Signers render from this frozen copy, so signed bytes == presented bytes. A freeze failure is fatal and aborts the send — nothing goes out.
2. **Mints a single-use token per signer** and stamps each signer `sent`.
3. **Emails each signer** their tokenized signing link.
4. **Moves the envelope** `draft → out_for_signature` and sets `sent_at`.

Send is **first-dispatch only** (`draft → out_for_signature`). There is no legitimate re-send — re-invoking it would rotate every token and 404 live links. To re-notify people who haven't signed, use [Remind](#remind-pending-signers).

### Request

The body is optional. Include a `message` to add a note to the invitation email (also stored on the envelope and surfaced to signers):

```bash
curl -X POST https://sign.example.com/api/mysign/agreements/42/send \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"message": "Please countersign by Friday. Thanks!"}'
```

| Field     | Type   | Required | Notes |
|-----------|--------|----------|-------|
| `message` | string | no       | Optional note included in the signing invitation email and stored on the envelope. |

### Response — `200 OK`

```json
{
  "ok": true,
  "emailed": 2,
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

| Field          | Type            | Meaning |
|----------------|-----------------|---------|
| `ok`           | boolean         | `true` when the envelope was dispatched. |
| `emailed`      | integer         | Number of invites the mailer accepted. |
| `email_errors` | array of string | Per-recipient mail errors, if any (the send still succeeds; use the returned `links` to deliver manually). |
| `links`        | array           | Per-signer signing links — one object per signer with `signer_id`, `name`, `email`, `token`, and `url`. |

**The `links` array is your integration hook.** Every signer's single-use URL is returned here, whether or not the email was delivered — capture it if you route your own notifications, drop a link into a chat app, or want to present the sender their own self-sign link.

> **Sequential order mode:** if the envelope is `sequential`, `send` returns a `url` for **every** signer, but only the **first** order-group is emailed now. Later signers are auto-emailed as each prior group finishes. In `parallel` (the default) everyone is emailed at once. See [Adding signers](./05-signers-and-routing.md) for order modes.

### Rejections

There are two distinct rejection channels — read the HTTP status to tell them apart.

**Hard `403` — blocks the send, sends nothing.** These are account-level gates checked *before* the freeze:

| HTTP | `error`                  | Extra          | Cause | Fix |
|------|--------------------------|----------------|-------|-----|
| 403  | `subscription_inactive`  | `billing: true`| The account's subscription is canceled or suspended. | Reactivate billing in the dashboard. |
| 403  | `email_unverified`       | —              | A password account whose sender email is not yet confirmed. (Google accounts are pre-verified.) | Verify the sender email address. |

```json
{ "ok": false, "error": "subscription_inactive", "billing": true }
```

**Soft in-body rejection — HTTP `200` with `ok: false`.** Business-rule problems come back with a 200 status and an explanatory `error` string:

| `error` (example)                                               | Cause |
|-----------------------------------------------------------------|-------|
| `add at least one signer`                                       | The draft has no signers. |
| `already sent — this agreement is out_for_signature; use Remind to re-notify pending signers` | The envelope was already sent (or is terminal). |
| `couldn't freeze the document for sending: …`                   | The PDF snapshot/flatten failed; nothing was dispatched. |

> Because a soft rejection is HTTP 200, **always check the `ok` field** — don't rely on the status code alone. The vendored SDKs do this for you and raise on `ok: false`.

### SDK

```python
from lifted_sign import LiftedSign

ls = LiftedSign(api_key="sk_live_...")   # or LIFTED_SIGN_KEY in the env
res = ls.send(42)                        # raises LiftedSignError on ok:false / 403
for link in res["links"]:
    print(link["email"], "→", link["url"])
```

```javascript
import { LiftedSign } from "./lifted-sign.mjs";

const ls = new LiftedSign({ apiKey: "sk_live_..." });
const res = await ls.send(42);
for (const link of res.links) console.log(link.email, "→", link.url);
```

> The SDK `send(aid)` posts an empty body. To attach a `message`, use `curl` (above) or POST the JSON body yourself.

---

## Remind pending signers

`POST /api/mysign/agreements/{aid}/remind` re-emails every **pending** signer of an `out_for_signature` envelope — a signer who hasn't signed yet and still holds a live token. It reuses the **same** signing link (no token rotation), and signers who've already signed are left untouched.

```bash
curl -X POST https://sign.example.com/api/mysign/agreements/42/remind \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"
```

### Response — `200 OK`

```json
{ "ok": true, "emailed": 1, "pending": 1, "errors": [] }
```

| Field     | Type            | Meaning |
|-----------|-----------------|---------|
| `ok`      | boolean         | `true` when at least one reminder was emailed. |
| `emailed` | integer         | Reminders successfully sent. |
| `pending` | integer         | Pending signers considered. |
| `errors`  | array of string | Per-recipient mail errors, if any. |

Remind is subject to the **same `403` gates** as send (`subscription_inactive`, `email_unverified`). It also rejects in-body (HTTP 200, `ok: false`) when there's nothing to do:

| `error` (example)                          | Cause |
|--------------------------------------------|-------|
| `no pending signers to remind`             | Everyone has signed, or no signer holds a live token. |
| `can't remind — agreement is completed`    | The envelope is `completed`, `voided`, `cancelled`, `draft`, or `expired` — remind only applies while `out_for_signature`. |

```python
ls.remind(42)
```

```javascript
await ls.remind(42);
```

---

## Void an envelope

`POST /api/mysign/agreements/{aid}/void` kills an in-flight envelope. It's **terminal**: the envelope's status becomes `voided`, every live signing session is revoked, and all outstanding token links stop working immediately. A voided envelope is a legal record — it can't be edited, re-sent, or deleted.

You can pass an optional `reason` (recorded on the `voided` audit event):

```bash
curl -X POST https://sign.example.com/api/mysign/agreements/42/void \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Superseded by a revised contract"}'
```

### Response — `200 OK`

```json
{ "ok": true }
```

```python
ls.void(42, reason="Superseded by a revised contract")
```

```javascript
await ls.void(42, "Superseded by a revised contract");
```

> **Void vs. delete.** Void is for a **sent** envelope — it revokes live links and preserves the legal record. `DELETE` only works on a **draft** that never went out (deleting a sent envelope returns `409`). Void when it's live; delete when it's an abandoned draft.

---

## Tracking an envelope

There are no webhooks yet — see [below](#no-webhooks-yet-poll-for-completion). Tracking is a read of the envelope object, which carries everything: envelope status, per-signer status, and the ordered audit trail.

### Get the full envelope

`GET /api/mysign/agreements/{aid}` returns the envelope with its `signers`, placed `fields`, and the ordered `events` audit trail.

```bash
curl https://sign.example.com/api/mysign/agreements/42 \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"
```

```json
{
  "id": 42,
  "name": "Master Services Agreement.pdf",
  "message": "Please countersign by Friday.",
  "status": "out_for_signature",
  "order_mode": "sequential",
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
      "color": "#2F6FED",
      "viewed_at": 1752624300.0,
      "signed_at": null
    }
  ],
  "fields": [ /* placed fields */ ],
  "events": [
    { "type": "sent",   "signer_id": 101, "detail": "to dana@example.com", "at": 1752624120.0 },
    { "type": "viewed", "signer_id": 101, "detail": "", "at": 1752624300.0 }
  ]
}
```

Requesting an envelope your account doesn't own returns `404 {"error":"not found"}` — existence is never leaked to non-owners.

### Envelope status

The top-level `status` is your headline state:

| Status              | Meaning |
|---------------------|---------|
| `draft`             | Being prepared; not yet sent. |
| `out_for_signature` | Sent; one or more signers still pending. |
| `completed`         | All signers signed; executed PDF + certificate available. |
| `declined`          | A signer declined. |
| `voided`            | Voided by the sender (terminal). |
| `cancelled`         | Cancelled (terminal). |

`sent_at` and `completed_at` are Unix epoch seconds (or `null` before that transition).

### Signer status

Each entry in `signers` tracks one person through their own state machine:

| Signer status | Meaning |
|---------------|---------|
| `pending`     | Created but not yet notified (a draft signer, or not their turn in sequential order). |
| `sent`        | Invite emailed; token is live. |
| `viewed`      | Opened the signing page (`viewed_at` set). |
| `signed`      | Completed their fields (`signed_at` set). |
| `declined`    | Declined to sign. |

`auth_method` echoes the signer's authentication method (`email`, `email_otp`, or `access_code`). To render a progress bar without the full object, the list endpoint (below) already includes `signed_n` / `signer_n` per envelope.

### The events audit trail

`events` is the ordered audit trail, ascending by `at` (Unix epoch seconds). Every state transition is recorded here — this is the same record that backs the Certificate of Completion.

| Event field | Type            | Meaning |
|-------------|-----------------|---------|
| `type`      | string          | Event kind (see below). |
| `signer_id` | integer \| null | The signer the event concerns, if any. |
| `detail`    | string          | Human-readable detail (e.g. `to dana@example.com`). |
| `at`        | number          | Unix epoch seconds. |

Common `type` values you'll see across the lifecycle (non-exhaustive):

| `type`                 | Emitted when |
|------------------------|--------------|
| `created`              | The draft was created. |
| `sent`                 | An invite was dispatched to a signer. |
| `SIGNER_AUTHENTICATED` | The single-use token link was issued as the signer's auth factor. |
| `DOC_FROZEN`           | The presented bytes were frozen at send (`detail` is the SHA-256). |
| `emailed`              | Invites were emailed (`detail` gives the count). |
| `viewed`               | A signer opened the document. |
| `reminded`             | A reminder was re-sent to a pending signer. |
| `signed`               | A signer completed their fields. |
| `voided`               | The envelope was voided (`detail` echoes the reason). |

### List envelopes (dashboard view)

`GET /api/mysign/agreements?limit=50&offset=0` returns the account's envelopes newest-first, each enriched with derived counts (`signed_n`, `signer_n`, `field_n`, `page_n`) and a lightweight `signers` array — enough to render a tracking dashboard without a per-row fetch.

```bash
curl "https://sign.example.com/api/mysign/agreements?limit=50&offset=0" \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"
```

```json
{
  "agreements": [
    {
      "id": 42,
      "name": "Master Services Agreement.pdf",
      "status": "out_for_signature",
      "signed_n": 0,
      "signer_n": 1,
      "field_n": 3,
      "page_n": 4,
      "signers": [ { "name": "Dana Client", "email": "dana@example.com", "status": "viewed" } ]
    }
  ],
  "total": 1,
  "offset": 0,
  "limit": 50,
  "has_more": false
}
```

`limit` is clamped to 1..200 (default 50); page with `offset` until `has_more` is `false`.

---

## No webhooks yet — poll for completion

Event delivery to your endpoint (`signed` / `completed` / `declined`) is on the roadmap but **not yet available**. Until it ships, **poll** `GET /api/mysign/agreements/{aid}` and watch the top-level `status`. When it flips to `completed` (and `completed_at` is set), the executed PDF and Certificate of Completion are ready to download.

```python
import time
from lifted_sign import LiftedSign

ls = LiftedSign(api_key="sk_live_...")

def wait_for_completion(aid, interval=30, timeout=7 * 24 * 3600):
    """Poll until the envelope reaches a terminal status."""
    deadline = time.time() + timeout
    terminal = {"completed", "declined", "voided", "cancelled"}
    while time.time() < deadline:
        env = ls.get(aid)
        if env["status"] in terminal:
            return env
        time.sleep(interval)
    raise TimeoutError(f"envelope {aid} still {env['status']} after {timeout}s")

env = wait_for_completion(42)
if env["status"] == "completed":
    ls.download(42, "signed.pdf")            # executed, sealed PDF
    ls.certificate(42, "certificate.pdf")    # Certificate of Completion
```

Polling guidance:

- **Poll on a sane interval** (e.g. every 30–60 s). The account limit is **120 requests/minute**; bursts over it get `429 Too Many Requests`, so back off with jitter.
- **Stop on any terminal status** — `completed`, `declined`, `voided`, or `cancelled` — not just `completed`.
- Once `completed`, retrieve the executed PDF (`GET …/download`) and the audit certificate (`GET …/certificate`). See [Downloads & certificate](./09-downloads-and-certificates.md).

---

## Quick reference

| Action                  | Endpoint                                   | Terminal? | Notes |
|-------------------------|--------------------------------------------|-----------|-------|
| Send for signature      | `POST /api/mysign/agreements/{aid}/send`   | no        | Freezes PDF, emails links, → `out_for_signature`; returns per-signer `links`. Optional `message`. `403` on inactive subscription / unverified sender. |
| Remind pending signers  | `POST /api/mysign/agreements/{aid}/remind` | no        | Re-emails unsigned signers; same link. Same `403` gates as send. |
| Void                    | `POST /api/mysign/agreements/{aid}/void`   | **yes**   | Revokes live links; → `voided`. Optional `reason`. |
| Get one envelope        | `GET /api/mysign/agreements/{aid}`         | —         | Status + signers + fields + ordered `events`. |
| List envelopes          | `GET /api/mysign/agreements`               | —         | Paginated, with per-envelope counts. |

The machine-readable contract for all of these lives in [`openapi.yaml`](../openapi.yaml).
