# Webhooks & polling

**Webhooks are not available yet.** There is no endpoint to register a callback URL, and Lifted Sign will not POST to your server when an envelope changes. Anyone who tells you otherwise is reading a roadmap, not the API. Until webhooks ship, the supported way to know when a signer views, signs, declines, or an envelope completes is to **poll** `GET /api/mysign/agreements/{aid}` and read the envelope's `status`, its per-signer `status`, and its `events` audit trail.

This guide shows you a production-shaped polling loop (curl and Python), the exact event vocabulary you'll see, and what webhooks will add when they land.

Base URL: `https://sign.example.com`. Every request is authenticated with a Bearer key — see [Authentication](./03-authentication.md).

---

## The one call you poll

After you [send an envelope](./08-sending-and-tracking.md), track its progress with a single read:

```bash
curl -sS https://sign.example.com/api/mysign/agreements/42 \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"
```

`GET /api/mysign/agreements/{aid}` returns the full envelope — metadata, `signers`, placed `fields`, and the ordered `events` audit trail. Three parts tell you everything about progress:

| Field | What it tells you |
|---|---|
| `status` | The envelope's lifecycle state (see below). |
| `signers[].status` | Where each individual signer is. |
| `events[]` | The append-only audit trail — every state transition, in order. |

> The `events` array is only returned on the **single-envelope** `GET /api/mysign/agreements/{aid}`. The list endpoint (`GET /api/mysign/agreements`) returns a lightweight `signers` summary and derived counts (`signed_n`, `signer_n`) but **no** `events` — poll the single-envelope call when you need the trail.

### Envelope status

```
draft · out_for_signature · completed · declined · voided · cancelled
```

`completed`, `declined`, `voided`, and `cancelled` are **terminal** — stop polling when you reach one. `out_for_signature` means at least one signer still has work to do.

### Signer status

```
pending · sent · viewed · signed · declined
```

Poll until every signer is `signed` (envelope goes `completed`) or one is `declined`.

---

## A polling loop that stops when it should

Two rules keep you fast and within limits:

1. **Stop at a terminal status.** Don't poll a `completed` or `voided` envelope forever.
2. **Back off.** The API permits a sustained **120 requests/minute per account** (see [Rate limits & errors](./10-errors-and-reliability.md)); bursts above it get `429`. A single envelope does not need sub-second polling — start around 10s and grow the interval, with jitter, up to a ceiling.

### curl + bash

```bash
#!/usr/bin/env bash
set -euo pipefail
AID="${1:?usage: poll.sh <agreement_id>}"
BASE="https://sign.example.com"
interval=10          # seconds; grows with backoff
max_interval=120

while :; do
  body="$(curl -sS "$BASE/api/mysign/agreements/$AID" \
    -H "Authorization: Bearer $LIFTED_SIGN_KEY")"
  status="$(printf '%s' "$body" | jq -r '.status')"
  echo "status=$status  signers=$(printf '%s' "$body" | jq -c '[.signers[] | {name, status}]')"

  case "$status" in
    completed|declined|voided|cancelled)
      echo "terminal: $status"; break ;;
  esac

  # jittered exponential-ish backoff, capped
  jitter=$(( RANDOM % 5 ))
  sleep $(( interval + jitter ))
  interval=$(( interval * 2 )); (( interval > max_interval )) && interval=$max_interval
done
```

### Python (with the vendored SDK)

The [Python SDK](../../../web/ds/vendor/sdk/lifted_sign.py) wraps the same call as `client.get(aid)`:

```python
import os, random, time
from lifted_sign import LiftedSign

client = LiftedSign(api_key=os.environ["LIFTED_SIGN_KEY"])

TERMINAL = {"completed", "declined", "voided", "cancelled"}

def wait_for_terminal(aid: int, *, start: float = 10.0, ceiling: float = 120.0, deadline: float = 3600.0):
    """Poll one envelope until it reaches a terminal status (or the deadline)."""
    interval = start
    began = time.monotonic()
    while True:
        env = client.get(aid)                      # GET /api/mysign/agreements/{aid}
        signers = [(s["name"], s["status"]) for s in env["signers"]]
        print(f"status={env['status']}  signers={signers}")

        if env["status"] in TERMINAL:
            return env
        if time.monotonic() - began > deadline:
            raise TimeoutError(f"envelope {aid} still {env['status']} after {deadline}s")

        time.sleep(interval + random.uniform(0, 5))  # jitter avoids thundering herds
        interval = min(interval * 2, ceiling)        # back off, capped

env = wait_for_terminal(42)
if env["status"] == "completed":
    client.download(42, "executed.pdf")        # GET /api/mysign/agreements/42/download
    client.certificate(42, "certificate.pdf")  # GET /api/mysign/agreements/42/certificate
```

When the envelope is `completed`, fetch the executed PDF and Certificate of Completion — see [Downloads](./09-downloads-and-certificates.md).

### Node (with the vendored SDK)

The [Node SDK](../../../web/ds/vendor/sdk/lifted-sign.mjs) exposes `client.get(aid)`:

```js
import { LiftedSign } from "./lifted-sign.mjs";

const client = new LiftedSign({ apiKey: process.env.LIFTED_SIGN_KEY });
const TERMINAL = new Set(["completed", "declined", "voided", "cancelled"]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForTerminal(aid, { start = 10_000, ceiling = 120_000, deadline = 3_600_000 } = {}) {
  let interval = start;
  const began = Date.now();
  for (;;) {
    const env = await client.get(aid); // GET /api/mysign/agreements/{aid}
    console.log(env.status, env.signers.map((s) => `${s.name}:${s.status}`).join(", "));
    if (TERMINAL.has(env.status)) return env;
    if (Date.now() - began > deadline) throw new Error(`envelope ${aid} still ${env.status}`);
    await sleep(interval + Math.random() * 5_000); // jitter
    interval = Math.min(interval * 2, ceiling);     // back off, capped
  }
}
```

### Sizing your interval

You have a 120 req/min budget shared across your whole account. Don't spend it all polling one envelope:

| Envelopes in flight | Sensible steady-state interval | Approx. req/min |
|---|---|---|
| 1 | 10–30 s | 2–6 |
| ~10 | 30–60 s each (stagger them) | 10–20 |
| Many / batch | 1–5 min, staggered, terminal-pruned | keep well under 120 |

Poll each envelope only while it's non-terminal, stagger start times so requests don't align, and drop an envelope from the poll set the moment it hits a terminal status.

---

## Reading the audit trail (`events`)

Every state transition is appended to `agreement_events` and surfaced in the envelope's `events` array. Each event is:

```json
{ "type": "signed", "signer_id": 101, "detail": "Dana Client", "at": 1752624300.0 }
```

| Field | Type | Meaning |
|---|---|---|
| `type` | string | The event kind (table below). |
| `signer_id` | integer \| null | The signer the event concerns, if any. |
| `detail` | string | Human-readable detail (never contains secrets — no OTP, SSN, DOB, or access codes). |
| `at` | number | Unix epoch **seconds** (float). |

Events are ordered by `at`. To detect *new* activity between polls, remember the `at` (or index) of the last event you processed and act on anything after it — treat the trail as append-only.

### Event vocabulary

These are the `type` values you'll observe, in roughly lifecycle order. Lowercase types mirror the coarse status changes; `UPPER_SNAKE` types are the fine-grained ESIGN/UETA compliance and document-integrity events that populate the Certificate of Completion.

| `type` | Emitted when |
|---|---|
| `created` | Envelope created from an uploaded PDF (draft). |
| `edited` | Draft document pages were edited. |
| `sent` | Envelope dispatched; one event per signer notified. |
| `SIGNER_AUTHENTICATED` | A signer's single-use token link was issued / auth method recorded. |
| `DOC_FROZEN` | The presented bytes were frozen at send (detail = document hash). |
| `emailed` | Signing invite (or a sequential-turn invite) was emailed. |
| `self_sign` | A no-email signer is self-signing in place. |
| `viewed` | A signer opened the signing page. |
| `ECONSENT_ACCEPTED` | Signer accepted the ESIGN/UETA electronic-records consent. |
| `RECORDS_ACCESS_DEMONSTRATED` | Signer demonstrated they can access electronic records. |
| `ECONSENT_WITHDRAWN` | Signer withdrew e-sign consent. |
| `SIGNATURE_ADOPTED` | Signer adopted a signature/initials style. |
| `FIELD_SIGNED` | An individual signature/initials field was completed. |
| `signed` | A signer finished all their fields. |
| `reminded` | A pending signer was re-notified (via [remind](./08-sending-and-tracking.md)). |
| `declined` | A signer declined to sign (envelope → `declined`). |
| `ACCESS_CHALLENGE_CONFIGURED` | An access-code / knowledge challenge was set on a signer. |
| `expired` | The signing window elapsed and the envelope auto-expired. |
| `voided` | The envelope was [voided](./08-sending-and-tracking.md) (detail = reason). |
| `DOC_SEALED` | The executed document was cryptographically sealed. |
| `DOC_SEAL_DEGRADED` | PAdES certification failed; sealed with an AES fallback instead. |
| `completed` | All signers done; executed copy + certificate generated (envelope → `completed`). |
| `COMPLETED_COPY_DELIVERED` | A completed copy was emailed to / downloaded by a party. |

> This list reflects the event types emitted by the current signing engine (`server/esign.py`). Treat it as a **best-effort enumeration, not a frozen contract** — new fine-grained compliance events may be added over time, so make your consumer tolerant of unknown `type` values rather than asserting on an exact set. **UNVERIFIED:** the precise set is derived from the server source, not from a published event-schema doc; the OpenAPI `Event` schema documents the shape (`type`/`signer_id`/`detail`/`at`) but enumerates only a few example types.

### Deriving progress from events vs. status

You rarely need to parse events to know *whether* an envelope is done — `status` and `signers[].status` answer that directly, and they're cheaper to reason about. Use `events` when you need the **why/when**: a timestamped record of consent, authentication, per-field signing, and sealing for your own audit log or UI activity feed. The authoritative, court-ready version of that trail is the [Certificate of Completion](./09-downloads-and-certificates.md), downloadable once the envelope is `completed`.

---

## What webhooks will add (roadmap)

Webhooks are on the roadmap. The API's `Webhooks` tag is explicitly marked *"Coming soon — signed / completed / declined event delivery to your endpoint."* When they ship, you'll be able to register an HTTPS endpoint and receive a signed POST as events happen, instead of polling. Expect the delivery to carry the same event vocabulary described above.

**None of that exists today.** Until it does:

- There is **no** endpoint to register a callback URL.
- Lifted Sign will **not** call your server.
- The reliable signal is the poll loop above.

### Build now so the switch is trivial later

Structure your integration so that swapping polling for webhooks is a plumbing change, not a rewrite:

- **Centralize the handler.** Put "given an envelope's current `status` + `events`, advance my system" behind one function. Polling calls it on each tick; a webhook would call it per delivery.
- **Be idempotent.** Key side effects (mark deal closed, email the customer, file the PDF) on `(agreement_id, event type)` or the last-processed event `at`, so re-processing the same state is a no-op. This is mandatory for webhooks (deliveries can repeat) and it makes polling safe too.
- **Tolerate unknown event types.** Ignore `type` values you don't recognize instead of erroring — the event set will grow.
- **Treat the envelope as the source of truth.** Even after webhooks land, on any ambiguity re-fetch `GET /api/mysign/agreements/{aid}` and trust its `status`. A webhook is a hint to go read; the envelope is the fact.

---

## See also

- [Sending an envelope](./08-sending-and-tracking.md) — dispatch, remind, void.
- [Downloads](./09-downloads-and-certificates.md) — executed PDF and Certificate of Completion, available once `completed`.
- [Errors & rate limits](./10-errors-and-reliability.md) — `429` handling and backoff.
- [Authentication](./03-authentication.md) — Bearer keys (`sk_live_…` / `sk_test_…`).
