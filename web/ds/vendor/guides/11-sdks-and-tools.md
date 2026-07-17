# SDKs & tools

The whole Lifted Sign API is plain HTTPS + JSON, so any HTTP client works. But you don't have to build one. We ship three **zero-dependency, single-file clients** — one Python, one Node, one bash — plus the machine-readable OpenAPI spec and a Postman collection. Every one of them does the same four things: create an envelope from a PDF, add a signer, place a signature **by anchor**, and send.

There is no package to install and no version to pin. **Installing = copying one file into your repo.** No `pip install`, no `npm install`, no lockfile churn, no transitive-dependency CVEs to chase.

Base URL for everything below is `https://sign.example.com`. Every request authenticates with a Bearer key — `sk_live_…` in production, `sk_test_…` in sandbox (see [Authentication](./03-authentication.md)).

## Pick a file

| File | Runtime | Dependencies | Download |
|------|---------|--------------|----------|
| `lifted_sign.py` | Python 3.8+ | none — standard library only (`urllib`) | [`/static/ds/vendor/sdk/lifted_sign.py`](https://sign.example.com/static/ds/vendor/sdk/lifted_sign.py) |
| `lifted-sign.mjs` | Node 18+ | none — built-in `fetch` / `FormData` / `Blob` | [`/static/ds/vendor/sdk/lifted-sign.mjs`](https://sign.example.com/static/ds/vendor/sdk/lifted-sign.mjs) |
| `quickstart.sh` | bash | `curl` + `jq` | [`/static/ds/vendor/sdk/quickstart.sh`](https://sign.example.com/static/ds/vendor/sdk/quickstart.sh) |
| `README.md` | — | starter-kit readme | [`/static/ds/vendor/sdk/README.md`](https://sign.example.com/static/ds/vendor/sdk/README.md) |

All three clients read your key from the `LIFTED_SIGN_KEY` environment variable (or you pass it in the constructor), and every one doubles as a runnable CLI: hand it a PDF and a signer email and it sends a document in a single command.

> The downloadable files are checked out **LF-only** (`.gitattributes` forces `eol=lf`) so the shell script and Python shebang work on Linux and macOS. If you copy-paste on Windows, keep Unix line endings.

## Install = copy one file

### Python

```bash
# "install"
curl -O https://sign.example.com/static/ds/vendor/sdk/lifted_sign.py
export LIFTED_SIGN_KEY=sk_live_xxx

# send a document straight from the shell
python lifted_sign.py contract.pdf dana@example.com "Dana Client"
```

Or use it as a library:

```python
from lifted_sign import LiftedSign

ls  = LiftedSign(api_key="sk_live_...")          # or omit and set LIFTED_SIGN_KEY
env = ls.create_agreement("contract.pdf", name="Master Services Agreement")
ls.add_signers(env["id"], [{"name": "Dana Client", "email": "dana@example.com"}])
ls.place_fields(env["id"], [
    {"signer": "dana@example.com", "type": "signature", "anchor": "Signature:"},
    {"signer": "dana@example.com", "type": "date",      "anchor": "Date:"},
])
ls.send(env["id"])                               # emails each signer a single-use link
```

### Node

```bash
# "install"
curl -O https://sign.example.com/static/ds/vendor/sdk/lifted-sign.mjs
export LIFTED_SIGN_KEY=sk_live_xxx

node lifted-sign.mjs contract.pdf dana@example.com "Dana Client"
```

As a module:

```js
import { LiftedSign } from "./lifted-sign.mjs";

const ls  = new LiftedSign({ apiKey: "sk_live_..." });   // or set LIFTED_SIGN_KEY
const env = await ls.createAgreement("contract.pdf", { name: "Master Services Agreement" });
await ls.addSigners(env.id, [{ name: "Dana Client", email: "dana@example.com" }]);
await ls.placeFields(env.id, [
  { signer: "dana@example.com", type: "signature", anchor: "Signature:" },
  { signer: "dana@example.com", type: "date",      anchor: "Date:" },
]);
await ls.send(env.id);
```

### curl + jq

```bash
curl -O https://sign.example.com/static/ds/vendor/sdk/quickstart.sh
chmod +x quickstart.sh
export LIFTED_SIGN_KEY=sk_live_xxx

./quickstart.sh contract.pdf dana@example.com "Dana Client"
```

`quickstart.sh` is the API with the covers off — four `curl` calls piped through `jq`. Read it top to bottom if you want to see exactly which endpoint each step hits before you write your own integration.

## How the clients map to the REST API

Each client is a thin, faithful passthrough. There is no hidden state and no client-side validation that diverges from the server — every method is one HTTP call. Here's the map:

| `lifted_sign.py` | `lifted-sign.mjs` | HTTP request | Guide |
|------|------|------|------|
| `create_agreement(pdf, name=)` | `createAgreement(pdf, {name})` | `POST /api/mysign/agreements` (multipart) | [Creating an envelope](./04-envelopes.md) |
| `list_agreements(limit, offset)` | `listAgreements({limit, offset})` | `GET /api/mysign/agreements` | [Listing envelopes](./04-envelopes.md) |
| `get(aid)` | `get(aid)` | `GET /api/mysign/agreements/{aid}` | [Reading status](./04-envelopes.md) |
| `delete(aid)` | `delete(aid)` | `DELETE /api/mysign/agreements/{aid}` | [The envelope lifecycle](./04-envelopes.md) |
| `add_signers(aid, signers)` | `addSigners(aid, signers)` | `POST /api/mysign/agreements/{aid}/signers` | [Adding signers](./05-signers-and-routing.md) |
| `place_fields(aid, fields)` | `placeFields(aid, fields)` | `POST /api/mysign/agreements/{aid}/fields` | [Placing fields](./06-placing-fields.md) |
| `send(aid)` | `send(aid)` | `POST /api/mysign/agreements/{aid}/send` | [Sending](./08-sending-and-tracking.md) |
| `remind(aid)` | `remind(aid)` | `POST /api/mysign/agreements/{aid}/remind` | [Sending](./08-sending-and-tracking.md) |
| `void(aid, reason=)` | `void(aid, reason)` | `POST /api/mysign/agreements/{aid}/void` | [The envelope lifecycle](./04-envelopes.md) |
| `download(aid, out)` | `download(aid, out)` | `GET /api/mysign/agreements/{aid}/download` → PDF bytes | [Downloads](./09-downloads-and-certificates.md) |
| `certificate(aid, out)` | `certificate(aid, out)` | `GET /api/mysign/agreements/{aid}/certificate` → PDF bytes | [Downloads](./09-downloads-and-certificates.md) |
| `account()` | `account()` | `GET /api/mysign/account` | [Authentication](./03-authentication.md) |

### Two things the clients do for you

Both the Python and Node clients handle the one non-obvious wrinkle of the API for you: **soft, in-body rejections.** The placement and mutation endpoints return `{"ok": false, "error": "…"}` with **HTTP 200** when they refuse a request — for example `{"ok": false, "error": "locked — already sent"}` when you try to edit an envelope that's already out for signature. A naive client that only checks the status code would treat that as success and silently drop your change on a legal document. Both SDKs inspect the body and raise (`LiftedSignError` in Python, `LiftedSignError` in Node) whenever `ok` is `false`, so a refused edit never passes silently. See [Errors](./10-errors-and-reliability.md) for the full status/rejection matrix.

The clients also unwrap PDF downloads: `download()` and `certificate()` request the raw bytes and write them to the path you give, returning the path.

### What the clients don't wrap (yet)

The single-file clients cover the create → sign → download core. A handful of endpoints have no named helper method:

- **Templates** — `POST /api/mysign/templates`, `.../templates/{tid}`, `.../templates/{tid}/use`, `.../templates/{tid}/archive` ([Templates](./07-templates-and-prefill.md))
- **Auto-detect prefill fields** — `POST /api/mysign/agreements/{aid}/detect`
- **Order mode** — `POST /api/mysign/agreements/{aid}/order-mode`
- **Page geometry** — `GET /api/mysign/agreements/{aid}/pages`
- **Source (presented) PDF** — `GET /api/mysign/agreements/{aid}/pdf`

You don't need a different tool for these — the clients are one file you own, so call the low-level request helper directly. In Python that's `_json` / `_request`; in Node the same:

```python
# Auto-detect prefill fields on a draft, then read them back
ls._json("POST", f"/api/mysign/agreements/{aid}/detect", {})
tpl = ls._request("GET", f"/api/mysign/templates/{tid}")
```

```js
await ls._json("POST", `/api/mysign/agreements/${aid}/detect`, {});
const tpl = await ls._request("GET", `/api/mysign/templates/${tid}`);
```

Or just reach for `curl` — every endpoint is documented with a copy-paste `curl` example in its guide.

## The OpenAPI 3.1 spec (for codegen)

The full API is described by a single **OpenAPI 3.1** document, served live at:

```
https://sign.example.com/developers/openapi.json
```

This is the machine-readable source of truth — every endpoint, request body, response shape, status code, and error code in these guides is generated from it. Point your codegen at that URL to generate a typed client in any language:

```bash
# fetch it
curl -o lifted-sign.openapi.json https://sign.example.com/developers/openapi.json

# generate a typed client (examples — any OpenAPI 3.1 generator works)
npx @openapitools/openapi-generator-cli generate \
  -i lifted-sign.openapi.json -g typescript-fetch -o ./lifted-sign-client

openapi-generator-cli generate \
  -i lifted-sign.openapi.json -g python -o ./lifted-sign-python
```

You can also drop the URL straight into Swagger UI, Insomnia, or [the interactive docs](https://sign.example.com/developers), which render this same spec.

> Note it's an **OpenAPI 3.1** document (JSON Schema 2020-12). A few generators still default to 3.0 — pick a 3.1-aware generator or version, or some nullable/`type: [number, "null"]` fields won't map cleanly.

## The Postman collection

Prefer to click? Import the ready-made Postman collection and environment:

- Collection: [`/static/ds/vendor/postman/lifted-sign.postman_collection.json`](https://sign.example.com/static/ds/vendor/postman/lifted-sign.postman_collection.json)
- Environment: [`/static/ds/vendor/postman/lifted-sign.postman_environment.json`](https://sign.example.com/static/ds/vendor/postman/lifted-sign.postman_environment.json)

Import both, open the environment, set your `sk_live_…` / `sk_test_…` key, and every request is pre-wired with the `Authorization: Bearer` header and the base URL. Insomnia and Bruno import the same collection.

## Everything in one place

| Resource | URL |
|----------|-----|
| Interactive developer docs | [`/developers`](https://sign.example.com/developers) |
| OpenAPI 3.1 spec (JSON) | [`/developers/openapi.json`](https://sign.example.com/developers/openapi.json) |
| Python client | [`/static/ds/vendor/sdk/lifted_sign.py`](https://sign.example.com/static/ds/vendor/sdk/lifted_sign.py) |
| Node client | [`/static/ds/vendor/sdk/lifted-sign.mjs`](https://sign.example.com/static/ds/vendor/sdk/lifted-sign.mjs) |
| bash quickstart | [`/static/ds/vendor/sdk/quickstart.sh`](https://sign.example.com/static/ds/vendor/sdk/quickstart.sh) |
| Starter-kit README | [`/static/ds/vendor/sdk/README.md`](https://sign.example.com/static/ds/vendor/sdk/README.md) |
| Postman collection | [`/static/ds/vendor/postman/lifted-sign.postman_collection.json`](https://sign.example.com/static/ds/vendor/postman/lifted-sign.postman_collection.json) |
| Postman environment | [`/static/ds/vendor/postman/lifted-sign.postman_environment.json`](https://sign.example.com/static/ds/vendor/postman/lifted-sign.postman_environment.json) |

All the single-file clients are MIT-licensed — copy, vendor, and modify them freely.

## A note on webhooks

There is **no webhook delivery yet** — the API can't POST `signed` / `completed` / `declined` events to your endpoint today (the `Webhooks` tag in the spec is a roadmap placeholder). Until it ships, poll `GET /api/mysign/agreements/{aid}` (or `ls.get(aid)`) and watch the envelope `status` move to `completed`. See [Webhooks (roadmap)](./12-webhooks-and-polling.md) for the polling pattern.
