# Errors & reliability

Two things make an integration against Lifted Sign robust, and they are the whole of this
guide:

1. **Read the body, not just the status.** Mutating endpoints report business-rule failures
   *inside* a `200 OK` body with `ok: false` — not with a 4xx. If you branch on the HTTP
   status alone, a rejected signature request looks like a success.
2. **Retry the retryable, never the rest.** A `429` or a transient `5xx` is worth a backoff;
   a `400`, `403`, `404`, or `409` is a decision your code made — retrying it just repeats the
   mistake.

Everything below is concrete: the two error shapes you'll parse, exactly which status each
failure carries, and copy-paste retry code that gets the distinction right. Base URL for every
request is `https://sign.example.com`; every request carries
`Authorization: Bearer $LIFTED_SIGN_KEY…` (see [03 — Authentication](./03-authentication.md)).

---

## The two error shapes

Every error body is one of two shapes. Which one you get depends on the *kind* of endpoint,
not the specific error.

| Shape | Returned by | Example |
|-------|-------------|---------|
| **`{ "error": "…" }`** (bare) | Auth failures, ownership misses, and binary/download endpoints that have nothing to stream. | `{ "error": "unauthorized" }` |
| **`{ "ok": false, "error": "…" }`** | Every mutating JSON endpoint (create, signers, fields, send, remind, void, delete, templates). | `{ "ok": false, "error": "locked — already sent" }` |

The `{ok, error}` shape carries `ok: true` on success and `ok: false` on a rejection. A few
rejections add a third key — most notably `billing: true` on `subscription_inactive`, and
`field` / `detail` on a field-placement failure. Treat any unknown extra keys as advisory.

```json
// success
{ "ok": true, "id": 42 }

// in-body rejection
{ "ok": false, "error": "subscription_inactive", "billing": true }
```

> The bare `{error}` shape is used by the two auth/ownership responses (`401`, `404`) and by
> the binary endpoints (`/pdf`, `/download`, `/certificate`) when there's no document to
> return. Everything else that mutates speaks `{ok, error}`.

---

## Soft vs. hard: the status convention

This is the single most important rule for a reliable client.

**A business-rule rejection on a mutating endpoint is a *soft* rejection: HTTP `200` with
`ok: false`.** The request was well-formed and authorized; the *document* just wasn't in a
state that allowed the operation. The classic case is editing an envelope that has already
been sent:

```bash
# Try to change signers on an envelope that's already out for signature
curl -sS -X POST https://sign.example.com/api/mysign/agreements/42/signers \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"signers":[{"name":"Dana","email":"dana@example.com"}]}'
# HTTP/1.1 200 OK
# { "ok": false, "error": "locked — already sent" }
```

Soft rejections you'll actually hit:

| Endpoint | `error` | Why |
|----------|---------|-----|
| `POST /signers`, `POST /fields`, `POST /order-mode`, `POST /detect` | `locked — already sent` | The envelope left `draft`; its bytes are frozen. Edits are draft-only. |
| `POST /order-mode` | `bad_mode` | `mode` was neither `sequential` nor `parallel`. |
| `POST /detect` | `no_source` | The draft has no stored PDF to scan. |
| `POST /send` | no signers / already sent | Nothing to dispatch, or already dispatched. |
| `POST /remind` | nothing pending | No unsigned signers left to nudge. |

Because these are `200`, **a client that checks only the HTTP status will treat them as
success.** Always branch on `ok`:

```python
res = requests.post(url, headers=auth, json={"fields": fields}).json()
if not res.get("ok"):
    raise RuntimeError(f"placement rejected: {res['error']}")
```

The vendored SDKs do this for you — a `200` body with `ok: false` is raised as an error, never
dropped silently:

```python
# lifted_sign.py — LiftedSignError carries .status (200 here) and .body
from lifted_sign import LiftedSign, LiftedSignError

ls = LiftedSign(api_key="sk_live_XXXX")
try:
    ls.add_signers(42, [{"name": "Dana", "email": "dana@example.com"}])
except LiftedSignError as e:
    print(e.status, e.body)   # 200 {'ok': False, 'error': 'locked — already sent'}
```

```js
// lifted-sign.mjs — same contract in Node
import { LiftedSign, LiftedSignError } from "./lifted-sign.mjs";

const ls = new LiftedSign({ apiKey: "sk_live_XXXX" });
try {
  await ls.addSigners(42, [{ name: "Dana", email: "dana@example.com" }]);
} catch (e) {
  if (e instanceof LiftedSignError) console.log(e.status, e.body); // 200 { ok:false, ... }
}
```

By contrast, a **hard** failure — bad auth, a malformed request, a billing gate, an ownership
miss — carries a real 4xx status. See [SDKs & tools](./11-sdks-and-tools.md) for the full
client patterns.

---

## Status code reference

| Status | Shape | Meaning | Retry? |
|--------|-------|---------|--------|
| `200` + `ok:false` | `{ok,error}` | **Soft** business rejection (locked, bad mode, nothing to do). | No — fix the request or the envelope state. |
| `400` | `{ok,error}` | **Bad request**: unacceptable upload, an unresolvable field batch, or invalid template/page-edit input. | No. |
| `401` | `{error}` | **Unauthorized**: API key missing, malformed, or revoked. | No — fix the key. |
| `403` | `{ok,error}` | **Hard gate**: `subscription_inactive` (adds `billing:true`) or `email_unverified`. Send blocked, nothing dispatched. | No — resolve billing / verify email, then re-send. |
| `404` | `{error}` | **Not found / not owned**: the envelope or template isn't yours (or doesn't exist), or a binary endpoint has no document yet. | No. |
| `409` | `{ok,error}` | **Conflict**: `DELETE` on a sent envelope, or a page-edit on a non-draft. | No — `void` instead of delete. |
| `429` | `{error}` | **Rate limited**: per-account limits may apply on the managed cloud. | **Yes** — back off with jitter. |
| `5xx` / network | — | Transient server/transport error. | **Yes** — backoff, but verify state for non-idempotent calls. |

A few of these are worth spelling out.

### 401 vs. 404 — no existence oracle

A missing or invalid key is `401 {"error":"unauthorized"}`. But requesting an envelope your
account **doesn't own** returns `404 {"error":"not found"}` — **not** `403`. This is
deliberate: a `403` would confirm that envelope `42` exists but belongs to someone else. Lifted
Sign never leaks the existence of another tenant's objects, so cross-tenant access and a
genuinely missing id are indistinguishable — both are `404`. Don't write logic that expects a
`403` for "exists but forbidden"; it will never arrive.

### 403 — the billing and verification gates (send & remind only)

`POST /send` and `POST /remind` run two account-level checks *before* they freeze or email
anything. If either fails, **nothing is sent** and you get a hard `403`:

| `error` | Extra key | Fix |
|---------|-----------|-----|
| `subscription_inactive` | `billing: true` | The account's subscription is canceled or suspended — reactivate it. |
| `email_unverified` | — | A password account's sender email isn't confirmed yet (Google accounts are pre-verified). |

These are the only `403`s in the API, and they're on the two dispatch endpoints. Everything
else that could "fail for a business reason" is a soft `200`. See
[Sending & tracking](./08-sending-and-tracking.md) for the full send flow.

### 409 — delete vs. void

A `draft` that never went out can be `DELETE`d. A **sent** envelope is a legal record: deleting
it returns `409 {"ok":false,"error":"locked"}`. Retire a live envelope with
`POST /void` instead, which revokes outstanding signing links and preserves the audit trail.
The same `409`-when-locked rule applies to the draft page-edit operations
(`/pages/reorder`, `/pages/rotate`, `/pages/delete`, `/pages/add`, `/text`, `/edit-text`).

### 400 — malformed input

`400` is for a request the server can't act on at all:

- **Upload rejected** (`POST /agreements`): `file required`, `file too large (max 60 MB)`,
  `not a PDF`, or an engine validation message (encrypted, zero-page, or corrupt PDF). The
  file is validated at the door — no half-written envelope is created.
- **Field batch rejected** (`POST /fields`): see [fail-closed placement](#fail-closed-field-placement) below.
- **Template** (`POST /templates`, `.../use`): e.g. `agreement not found` (source not owned by
  you), `source document not allowed`, `template has no source document`.

---

## Fail-closed field placement

`POST /fields` replaces your **entire** field layout in one batch, and it is **fail-closed**:
if *any* field can't be resolved — anchor text not in the document, an unknown signer email, or
a missing signer when the envelope has more than one — the **whole batch is rejected and
nothing is written.** Your previous layout is left exactly as it was; there are no partial
placements to clean up. This is what makes placement safe to retry after you fix the input.

A batch rejection is an HTTP **`400`** carrying a machine `error` code, the **0-based `field`
index** of the offender, and a `detail` echoing the unresolved value where it applies:

```json
{ "ok": false, "error": "anchor_not_found", "field": 0, "detail": "Signature:" }
```

| `error` | Meaning | `detail` |
|---------|---------|----------|
| `anchor_not_found` | The anchor text isn't real, selectable text in the document. | The anchor you sent. |
| `signer_not_found` | No signer on the envelope has that email. | The email you sent. |
| `signer_required` | A field omitted the signer and the envelope has more than one. | — |
| `no fields` | The `fields` array was empty. | — |

The draft-lock case is different — placing fields on an *already-sent* envelope is a **soft**
rejection: HTTP `200` with `{"ok": false, "error": "locked — already sent"}`. So `/fields` can
answer with either a hard `400` (couldn't resolve the batch) or a soft `200` (envelope already
frozen) — one more reason to branch on `ok`. Full placement mechanics are in
[06 — Placing fields](./06-placing-fields.md).

---

## Rate limits & backing off

Per-account request limits may apply on the managed cloud tier; a client should handle
`429 Too Many Requests` defensively when it sees one. File uploads are independently capped at
**60 MB** per PDF (a larger upload is a `400`, not a `429`).

The correct response to a `429` is **exponential backoff with jitter** — never a tight retry
loop, and never a fixed delay (fixed delays make every client retry in lockstep and re-collide).
Retry only `429` and transient `5xx`/network errors; never retry a `400`/`401`/`403`/`404`/`409`
— those are deterministic and will fail identically.

```python
import random, time
from lifted_sign import LiftedSign, LiftedSignError

def with_retry(fn, *, tries=5, base=0.5, cap=30.0):
    for attempt in range(tries):
        try:
            return fn()
        except LiftedSignError as e:
            # Retry only rate-limit / transient server errors. A 200-with-ok:false
            # (business rejection) or any 4xx is deterministic — re-raise immediately.
            retryable = e.status == 429 or (e.status is not None and e.status >= 500)
            if not retryable or attempt == tries - 1:
                raise
            sleep = min(cap, base * 2 ** attempt) * (0.5 + random.random())  # full jitter
            time.sleep(sleep)

ls = LiftedSign(api_key="sk_live_XXXX")
env = with_retry(lambda: ls.list_agreements(limit=50))   # a safe, idempotent GET
```

```js
import { LiftedSign, LiftedSignError } from "./lifted-sign.mjs";

async function withRetry(fn, { tries = 5, base = 500, cap = 30_000 } = {}) {
  for (let attempt = 0; attempt < tries; attempt++) {
    try {
      return await fn();
    } catch (e) {
      const retryable =
        e instanceof LiftedSignError && (e.status === 429 || (e.status ?? 0) >= 500);
      if (!retryable || attempt === tries - 1) throw e;
      const sleep = Math.min(cap, base * 2 ** attempt) * (0.5 + Math.random()); // full jitter
      await new Promise((r) => setTimeout(r, sleep));
    }
  }
}

const ls = new LiftedSign({ apiKey: "sk_live_XXXX" });
await withRetry(() => ls.listAgreements({ limit: 50 }));
```

A raw-`curl` client should read the same signal: on `429`, sleep `base · 2^attempt` seconds
plus a random fraction, and cap the total. There is no `Retry-After` header to rely on — use
your own schedule.

---

## Idempotency

Lifted Sign has **no idempotency-key header**. Whether a retry is safe depends entirely on the
endpoint, and the split is clean:

**Naturally idempotent — safe to retry.** The "set" endpoints are **replace-all**: they
overwrite the whole collection rather than appending, so running them twice with the same input
lands on the same state.

| Endpoint | Why it's idempotent |
|----------|---------------------|
| `POST /signers` | Replaces the entire signer set. |
| `POST /fields` | Replaces the entire field layout (fail-closed — see above). |
| `POST /order-mode` | Sets a single value. |
| `POST /detect` | Dedupes by `field_key`; re-running adds nothing already present. |
| `GET …`, `PUT`-style reads | Side-effect-free. |

**Not idempotent — do not blind-retry.** These *create* new state on every call:

| Endpoint | Hazard on retry |
|----------|-----------------|
| `POST /agreements` | Each call creates a **new** envelope. A blind retry after a timeout makes a duplicate. |
| `POST /templates/{tid}/use` | Each call mints a **new** draft. |
| `POST /send` | Re-sending a *draft* dispatches it; on an *already-sent* envelope it's a soft `200` no-op, but `POST /remind` **does** re-email — don't loop it. |

The practical rule: **track your own ids.** When you create an envelope, capture the returned
`id` before doing anything else. If a create or `use` call times out with no response, **don't
retry it** — you don't know whether the server committed. Instead reconcile: `GET
/api/mysign/agreements` (newest first) and check whether your document is already there before
issuing another create. Client-side, tag each logical document with your own correlation id
(e.g. store it as the envelope `name` or in your own DB keyed to the returned `id`) so a
duplicate is detectable.

```python
# Safe create: don't retry the POST — reconcile by listing.
try:
    env = ls.create_agreement("contract.pdf", name="MSA · order-7841")
    aid = env["id"]
except LiftedSignError as e:
    if e.status is None or e.status >= 500:      # timeout / transport — unknown outcome
        listing = ls.list_agreements(limit=20)
        match = next((a for a in listing["agreements"] if a["name"] == "MSA · order-7841"), None)
        aid = match["id"] if match else ls.create_agreement("contract.pdf", name="MSA · order-7841")["id"]
    else:
        raise
```

---

## Staying in sync

**Two ways to stay in sync — webhooks (preferred) or polling.** Register an endpoint with
`POST /api/mysign/webhooks` and Lifted Sign delivers a signed POST (`envelope.sent`,
`signer.signed`, `envelope.completed`, `envelope.declined`, `envelope.voided`,
`envelope.expired`) as each transition happens — verify the `X-Lifted-Signature` HMAC and
respond `2xx`. Failed deliveries retry a few times over seconds but are **not** redelivered
later, so reconcile gaps by **polling**: `GET /api/mysign/agreements/{aid}` returns the current
`status`, per-signer `status`, and the ordered `events` audit trail; `GET /api/mysign/agreements`
pages the whole account. Poll on a sane interval (seconds-to-minutes, not a hot loop —
managed-cloud rate limits may apply), and stop once `status` reaches a terminal value (`completed`,
`declined`, `voided`, `expired`). See [12 — Webhooks](./12-webhooks-and-polling.md) for the
delivery contract, signature verification, and the polling fallback.

---

## Checklist

- [ ] Branch on the `ok` field for every mutating call — a rejection can be a `200`.
- [ ] Treat `404` as "not found *or* not yours" — never expect a `403` for cross-tenant access.
- [ ] Handle the two send gates (`subscription_inactive`, `email_unverified`) as hard `403`s.
- [ ] `void` sent envelopes; only `DELETE` drafts (a sent delete is `409`).
- [ ] Retry only `429` and transient `5xx`/network — with exponential backoff **and jitter**.
- [ ] Never blind-retry `POST /agreements` or `/templates/{tid}/use`; reconcile by listing.
- [ ] Keep uploads under 60 MB.
- [ ] Stay in sync via webhooks (verify the `X-Lifted-Signature` HMAC), and poll to reconcile.

**Related:** [03 — Authentication](./03-authentication.md) ·
[06 — Placing fields](./06-placing-fields.md) ·
[08 — Sending & tracking](./08-sending-and-tracking.md) ·
[11 — SDKs & tools](./11-sdks-and-tools.md) ·
[12 — Webhooks & polling](./12-webhooks-and-polling.md) ·
[OpenAPI spec](../openapi.yaml)
