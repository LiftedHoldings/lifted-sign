# Authentication & API keys

Every call to the Lifted Sign API is authenticated with a **developer API key** sent as a Bearer token. There are no request signatures, no OAuth dance, no session to juggle — you attach one header and you're in:

```http
Authorization: Bearer $LIFTED_SIGN_KEY
```

The base URL is `https://sign.example.com`. A key resolves to exactly one account, and it grants no more authority than a logged-in user of that account. That's the whole model. The rest of this guide is the details worth knowing before you ship.

## Live vs. test keys

Keys come in two modes, distinguished by their prefix:

| Prefix | Mode | Use for |
| --- | --- | --- |
| `sk_live_…` | Production | Real envelopes that email real signers and produce legally binding, sealed documents. |
| `sk_test_…` | Test / sandbox | Development, staging, and CI, where you don't want to touch production credentials. |

Both prefixes authenticate against the **same account**, flow through the same authorization checks, and are validated identically by the server. The prefix is primarily an operational signal: it lets you tell at a glance whether a leaked or mis-deployed key is a production credential, and it lets you keep your CI secret (`sk_test_…`) distinct from the one that sends real contracts. Treat both as equally sensitive secrets.

> Test mode marks *intent*, not a separate isolated data store — a `sk_test_…` key reads and writes the same account objects a `sk_live_…` key would. Use a dedicated throwaway account for sandbox work if you need true isolation from production envelopes.

## Minting a key

Keys are created in the **Developers** view of your Lifted Sign dashboard (sign in at `https://sign.example.com`):

1. Open **Developers**.
2. Click **Create key**, give it a descriptive label (e.g. `ci-staging`, `billing-worker`), and pick **live** or **test**.
3. The full key is displayed **exactly once**.

### The key is shown once — copy it now

There is no "reveal" button and no way to retrieve the secret later. The server stores only a PBKDF2 hash of the key plus a short, non-secret prefix for lookup; the plaintext is never persisted and cannot be recovered from a database dump. When you create a key, the response looks like this:

```json
{
  "ok": true,
  "key": "sk_live_Xk9…full-secret-shown-once…",
  "meta": {
    "id": 7,
    "label": "billing-worker",
    "prefix": "sk_live_Xk9wQ2",
    "mode": "live",
    "created_at": 1752600000.0,
    "last_used_at": null,
    "revoked": false
  }
}
```

Copy the `key` value straight into your secret manager (AWS Secrets Manager, Vault, GitHub Actions secrets, a `.env` outside version control — whatever you already use). If you lose it, you don't recover it — you revoke it and mint a new one.

The `meta` object (and the listing endpoint) only ever exposes the non-secret `prefix`, never the full key. That prefix is how you match a row in the dashboard to a key in your infrastructure.

## Using the key

Attach the `Authorization: Bearer <key>` header to every request. The vendored SDKs do this for you.

### curl

```bash
curl https://sign.example.com/api/mysign/agreements \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY"
```

### Python

The zero-dependency [`lifted_sign.py`](../../../web/ds/vendor/sdk/lifted_sign.py) client reads the key from the constructor or the `LIFTED_SIGN_KEY` environment variable:

```python
from lifted_sign import LiftedSign

ls = LiftedSign(api_key="sk_live_…")   # or set LIFTED_SIGN_KEY in the environment
resp = ls.account()                    # GET /api/mysign/account — a cheap authed sanity check
print(resp["account"]["email"])        # the profile is wrapped: {"account": {...}}
```

### Node

The [`lifted-sign.mjs`](../../../web/ds/vendor/sdk/lifted-sign.mjs) client (Node 18+, no npm install) mirrors it:

```js
import { LiftedSign } from "./lifted-sign.mjs";

const ls = new LiftedSign({ apiKey: process.env.LIFTED_SIGN_KEY });
const resp = await ls.account();       // { account: {...} } — the profile is wrapped
console.log(resp.account.email);
```

## Server-side only

**API keys are backend secrets.** A key that authenticates one request can create, send, void, and download every envelope on your account. Never do any of the following:

- Embed a key in a browser bundle, single-page app, or any JavaScript the client can view.
- Ship a key inside a mobile or desktop app binary.
- Put a key in a public repository, a client-side config, or a URL query string.
- Log the full key. (Logging the `prefix` is fine — it's not a secret.)

If you need a browser to interact with a signing flow, that happens through the tokenized signer links Lifted Sign emails to each signer — not through your API key. Your key stays on your server.

## One key, one account — cross-tenant reads are impossible

A key is bound to a single account at creation and there is no way to widen its scope. Every object in the API — envelopes, templates, signers, fields, certificates — is checked against the owning account on every request. If you ask for an envelope your account doesn't own, you get a `404`, not a `403`:

```json
{ "error": "not found" }
```

The `404` (rather than `403 Forbidden`) is deliberate: it means the API never confirms that some other account's envelope id even exists. Object ids are not an enumeration oracle. Concretely, `GET /api/mysign/agreements/42` returns the envelope if your account owns id 42, and `404 {"error":"not found"}` in every other case — whether 42 belongs to another tenant or doesn't exist at all. You cannot read, mutate, or probe another tenant's data with your key, full stop.

## If a key leaks: revoke instantly

If a key is exposed — committed to a repo, pasted into a ticket, logged somewhere it shouldn't be — revoke it in the **Developers** view. Revocation is **instant and irreversible**: the very next request bearing that key gets a `401`. There's no propagation delay and no grace window to clean up. The standard rotation is:

1. Mint a new key (live or test to match).
2. Deploy it to your secret manager and roll your services.
3. Revoke the old key.

Do them in that order so you never have a gap where no valid key is deployed. Revoking a key never affects your other keys or any envelope already created with it — the documents stand; only that credential stops working.

## Key management is cookie-only — you can't mint a key with a key

Creating, listing, and revoking keys is done by a **signed-in human** in the dashboard, authenticated by the session cookie — **not** by an API key. This is intentional: a developer key is logged, committed, and handed to third-party backends, so it must never be able to escalate by minting fresh keys or rotating away from an owner's control. The management endpoints (`GET`/`POST /api/mysign/api-keys`, `POST /api/mysign/api-keys/{id}/revoke`) reject Bearer auth and require the cookie session. Practically: **do your key lifecycle in the Developers view**, and use your Bearer key only for the document API (`/api/mysign/agreements`, `/api/mysign/templates`, and friends).

The one account-level endpoint that *does* accept your Bearer key is `GET /api/mysign/account`, which returns your account profile and agreement count — handy as a liveness/credential check from your backend.

## The 401 shape

A missing, malformed, revoked, or otherwise invalid key on any document endpoint returns:

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{ "error": "unauthorized" }
```

That's the exact body — a single `error` field. The two failure modes to keep straight:

| You get | It means |
| --- | --- |
| `401 {"error":"unauthorized"}` | Your key is missing, malformed, or revoked. Fix the credential. |
| `404 {"error":"not found"}` | Your key is valid, but the object you asked for isn't owned by your account (or doesn't exist). |

If you're seeing `401`, check that the header is literally `Authorization: Bearer <key>` (the word `Bearer`, one space, the full `sk_…` value) and that the key hasn't been revoked in the dashboard. If you're seeing `404` on something you expect to exist, you're almost certainly authenticated as a different account than the one that owns it.

## Related

- [Placing fields](./06-placing-fields.md) — anchor-based field placement on a draft envelope.
- [Errors & status codes](./10-errors-and-reliability.md) — the full error vocabulary beyond `401`/`404`.
- [Webhooks](./12-webhooks-and-polling.md) — **roadmap.** There are no webhooks yet; poll `GET /api/mysign/agreements/{id}` for status changes in the meantime.
- [OpenAPI reference](../openapi.yaml) — the machine-readable source of truth for every endpoint, field, and status code.
