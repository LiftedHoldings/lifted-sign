# Webhooks

**Webhooks are live.** Register an HTTPS endpoint and Lifted Sign will POST a signed event to it the moment an envelope moves — sent, signed, completed, declined, voided, or expired — so you can react in real time instead of polling. Every delivery is HMAC-signed with a per-subscription secret, retried on failure, and written to a per-endpoint delivery log you can inspect.

This guide covers the event catalog, how to register a subscription, the exact delivery shape and headers, verifying the signature (Python **and** Node), retry/backoff behavior, the delivery log, and a short polling fallback.

Base URL: `https://sign.example.com`. Every management request is authenticated with a Bearer key — see [Authentication](./03-authentication.md).

---

## Event catalog

A subscription receives a signed POST for each of these envelope transitions:

| Event | Emitted when | `data` payload |
|---|---|---|
| `envelope.sent` | An envelope is dispatched for signature. | `{ agreement_id, envelope_id, status: "out_for_signature" }` |
| `signer.signed` | A signer finishes all their fields. | `{ agreement_id, signer_id, status: "signed" }` |
| `envelope.completed` | The last signer completes; executed PDF + certificate are ready. | `{ agreement_id, envelope_id, status: "completed" }` |
| `envelope.declined` | A signer declines (envelope → `declined`). | `{ agreement_id, signer_id, status: "declined", reason }` |
| `envelope.voided` | An in-flight envelope is voided. | `{ agreement_id, status: "voided", reason }` |
| `envelope.expired` | The signing window elapses and the envelope auto-expires. | `{ agreement_id, status: "expired" }` |

`agreement_id` is the envelope id you use everywhere else in the API (`GET /api/mysign/agreements/{id}`). Treat `data` as **open**: read the keys you need and ignore any you don't, because payloads may gain fields over time.

> `GET /api/mysign/webhooks` reports one additional selectable event, `envelope.viewed`. You may subscribe to it, but the signing engine does not emit it today — build against the six events above and treat `envelope.viewed` as reserved.

---

## Register a webhook

`POST /api/mysign/webhooks` with a JSON body of `url` and an optional `events` list. Omit `events` (or pass `["*"]`) to receive every event; otherwise pass the exact event names you want.

```bash
curl -sS -X POST https://sign.example.com/api/mysign/webhooks \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "url": "https://api.acme.com/hooks/lifted-sign",
        "events": ["envelope.completed", "envelope.declined", "signer.signed"]
      }'
```

The response returns the created subscription, including its signing secret:

```json
{
  "ok": true,
  "webhook": {
    "id": 3,
    "url": "https://api.acme.com/hooks/lifted-sign",
    "secret": "whsec_Vx9…redacted…",
    "events": ["envelope.completed", "envelope.declined", "signer.signed"],
    "active": true,
    "created_at": 1752624000.0,
    "last_status": null,
    "last_delivery_at": null,
    "failure_count": 0
  }
}
```

- **`url`** must be an absolute `http(s)` URL. HTTPS in production — deliveries are not encrypted at the application layer beyond TLS.
- **`secret`** (`whsec_…`) is what you use to [verify signatures](#verify-the-signature). Store it in your secret manager. It is shown on create, on list, and after a rotate. Redirects are **not** followed.
- **`events`** comes back as `["*"]` when you subscribed to everything, else the explicit list. An unknown event name is rejected with `400 {"ok": false, "error": "unknown event: …"}`.

### Managing subscriptions

| Call | Does |
|---|---|
| `GET /api/mysign/webhooks` | List your subscriptions (each includes its `secret`) plus the full selectable-event list. |
| `POST /api/mysign/webhooks` | Create one (above). |
| `DELETE /api/mysign/webhooks/{id}` | Delete a subscription. Idempotent. |
| `POST /api/mysign/webhooks/{id}/rotate` | Mint a new signing secret (invalidates the old one). |
| `POST /api/mysign/webhooks/{id}/test` | Send a sample `envelope.sent` ping so you can confirm your receiver + signature check before relying on live events. |
| `GET /api/mysign/webhooks/{id}/deliveries` | The [delivery log](#delivery-log) for one subscription. |

A `{id}` that isn't yours resolves to **`404 {"error": "not found"}`**, never `403` — existence is never leaked cross-account.

### Test your endpoint first

```bash
curl -sS -X POST https://sign.example.com/api/mysign/webhooks/3/test \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"
# → { "ok": true, "scheduled": 1 }
```

The ping is a real `envelope.sent` delivery (payload `{ "agreement_id": null, "status": "test", "ping": true }`), signed and logged exactly like a live event — the ideal way to validate your signature check end to end. Its outcome appears in the delivery log.

---

## The delivery request

Each delivery is an HTTP `POST` to your `url` with a compact JSON body:

```json
{
  "id": "evt_9f2c1b7e4a…",
  "event": "envelope.completed",
  "created": 1752624300,
  "data": { "agreement_id": 42, "envelope_id": "env_abc123", "status": "completed" }
}
```

| Field | Meaning |
|---|---|
| `id` | Unique event id (`evt_…`), shared by every subscription notified for this one transition. |
| `event` | The event name (matches the `X-Lifted-Event` header). |
| `created` | Unix timestamp (**integer seconds**) when the event was generated. |
| `data` | The event-specific payload from the [catalog](#event-catalog). |

### Headers

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `User-Agent` | `Lifted-Sign-Webhooks/1` |
| `X-Lifted-Event` | The event name, e.g. `envelope.completed`. |
| `X-Lifted-Delivery` | A per-delivery UUID. **Stable across the retries of one delivery** — key your idempotency/dedup on it. |
| `X-Lifted-Signature` | `sha256=<hex>` — the HMAC-SHA256 of the exact raw body under your subscription's secret. [Verify it.](#verify-the-signature) |

**Respond `2xx` quickly.** Any `2xx` status marks the delivery successful. Acknowledge fast (ideally under a second — the delivery timeout is 5 seconds) and do your real work asynchronously; a slow or non-`2xx` response is treated as a failure and [retried](#retries-and-backoff).

---

## Verify the signature

Every delivery carries `X-Lifted-Signature: sha256=<hex>`, where `<hex>` is the lowercase hex HMAC-SHA256 of the **exact raw request body** keyed by your subscription's `whsec_` secret. Recompute it over the bytes you received — **before** any JSON parse/re-serialize, which would change the bytes — and compare in constant time. Reject anything that doesn't match.

The algorithm mirrors the server exactly: `sig = "sha256=" + HMAC_SHA256(secret, raw_body).hexdigest()`, compared with a constant-time equality over the full header string.

### Python

```python
import hashlib
import hmac

WHSEC = "whsec_…"  # your subscription's signing secret

def verify(raw_body: bytes, signature_header: str | None) -> bool:
    """True iff X-Lifted-Signature authenticates raw_body under WHSEC."""
    if not signature_header:
        return False
    digest = hmac.new(WHSEC.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    expected = f"sha256={digest}"
    return hmac.compare_digest(expected, signature_header.strip())
```

Flask receiver — note it reads `request.get_data()` (raw bytes), not `request.json`:

```python
from flask import Flask, request, abort

app = Flask(__name__)

@app.post("/hooks/lifted-sign")
def hook():
    raw = request.get_data()  # exact bytes — do NOT use request.json here
    if not verify(raw, request.headers.get("X-Lifted-Signature")):
        abort(400, "bad signature")
    event = request.headers["X-Lifted-Event"]
    delivery_id = request.headers["X-Lifted-Delivery"]  # dedup key
    # ... enqueue by delivery_id, return fast ...
    return "", 200
```

### Node

`crypto.timingSafeEqual` throws when the buffers differ in length, so guard on length first.

```js
import crypto from "node:crypto";

const WHSEC = "whsec_…"; // your subscription's signing secret

function verify(rawBody, signatureHeader) {
  if (!signatureHeader) return false;
  const digest = crypto
    .createHmac("sha256", WHSEC)
    .update(rawBody) // rawBody is a Buffer/string of the exact bytes received
    .digest("hex");
  const expected = Buffer.from(`sha256=${digest}`);
  const got = Buffer.from(signatureHeader.trim());
  return expected.length === got.length && crypto.timingSafeEqual(expected, got);
}
```

Express receiver — capture the raw body so the signature is computed over the exact bytes:

```js
import express from "express";

const app = express();
// Preserve the raw bytes for signature verification.
app.use("/hooks/lifted-sign", express.raw({ type: "application/json" }));

app.post("/hooks/lifted-sign", (req, res) => {
  if (!verify(req.body, req.get("X-Lifted-Signature"))) {
    return res.status(400).send("bad signature");
  }
  const event = req.get("X-Lifted-Event");
  const deliveryId = req.get("X-Lifted-Delivery"); // dedup key
  const payload = JSON.parse(req.body.toString("utf8"));
  // ... enqueue by deliveryId, return fast ...
  res.sendStatus(200);
});
```

If you rotate the secret (`POST /api/mysign/webhooks/{id}/rotate`), start verifying with the new `whsec_` immediately — the old one stops signing at once.

---

## Retries and backoff

A delivery that doesn't get a `2xx` (any non-`2xx` status, a timeout, or a transport error) is retried:

- **Up to 3 attempts** per delivery, with short exponential backoff (~0.5s, then ~1s) between them. The delivery timeout is 5 seconds per attempt.
- `X-Lifted-Delivery` is **the same UUID across those attempts**, so your receiver can dedupe. Design side effects to be idempotent on it (or on the event `id`): the same delivery can legitimately arrive more than once.
- There is **no long-tail redelivery** hours later. If all three attempts fail — your endpoint was down for the whole ~1.5s window — that event is not re-sent. Reconcile misses by [polling](#polling-fallback) the envelope.
- A subscription that racks up **15 consecutive failed deliveries is auto-disabled** (`active` flips to `false`) so a dead endpoint stops burning delivery attempts. Re-enable by recreating the subscription (and rotate/verify your receiver first). A single success resets the failure counter.

Because delivery runs entirely in the background, a webhook failure never affects the signing flow itself — signers are unaffected by the state of your endpoint.

---

## Delivery log

Every attempt — success or failure — is recorded. Read the recent history for one subscription:

```bash
curl -sS "https://sign.example.com/api/mysign/webhooks/3/deliveries?limit=50" \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"
```

```json
{
  "deliveries": [
    {
      "id": 512,
      "webhook_id": 3,
      "event": "envelope.completed",
      "status_code": 200,
      "ok": true,
      "attempt": 1,
      "created_at": 1752624300.4,
      "response_ms": 84,
      "error": ""
    },
    {
      "id": 511,
      "webhook_id": 3,
      "event": "signer.signed",
      "status_code": 503,
      "ok": false,
      "attempt": 2,
      "created_at": 1752624120.9,
      "response_ms": 5001,
      "error": "HTTP 503"
    }
  ]
}
```

`limit` defaults to 50 and is clamped to 1..200, newest first. One row is written **per attempt**, so a retried delivery shows multiple rows (`attempt` 1, 2, …). Use this to debug a receiver: `status_code`, `response_ms`, and `error` tell you exactly why a delivery failed. The subscription's own `last_status`, `last_delivery_at`, and `failure_count` (from `GET /api/mysign/webhooks`) give the at-a-glance health.

---

## Polling fallback

Webhooks are a hint to go read; **the envelope is the source of truth.** Because failed deliveries are not redelivered hours later, reconcile any gaps by reading the envelope directly: **poll `GET /api/mysign/agreements/{id}`** and check its top-level `status` (and per-signer `status`). Do this on any ambiguity, after any downtime on your receiver, or instead of webhooks entirely if you prefer a pull model.

```bash
curl -sS https://sign.example.com/api/mysign/agreements/42 \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" | jq '.status'
```

The full production-shaped polling loop (curl, Python, Node), interval sizing, and the envelope `events` audit trail are in [Sending & tracking](./08-sending-and-tracking.md). Whichever model you choose, key your side effects idempotently — on `X-Lifted-Delivery` for webhooks, or on the last event you processed for polling — so re-processing the same state is a no-op.

---

## See also

- [Sending an envelope](./08-sending-and-tracking.md) — dispatch, remind, void, and the full polling loop + audit trail.
- [Downloads](./09-downloads-and-certificates.md) — executed PDF and Certificate of Completion, available once `completed`.
- [Errors & rate limits](./10-errors-and-reliability.md) — `429` handling and backoff.
- [Authentication](./03-authentication.md) — Bearer keys (`sk_live_…` / `sk_test_…`).
