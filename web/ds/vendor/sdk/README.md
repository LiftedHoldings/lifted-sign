# Lifted Sign — plug-and-play starter kit

Drop-in clients for the [Lifted Sign API](https://sign.example.com/developers). Every file
here is **self-contained and dependency-free** — copy the one you want into your project and run it.
All three do the same thing: create an envelope from a PDF, add a signer, place a signature **by
anchor** (name text that already exists in the document — no coordinate math), and send it.

| File | Runtime | Install |
|------|---------|---------|
| [`lifted_sign.py`](./lifted_sign.py) | Python 3.8+ | none — standard library only |
| [`lifted-sign.mjs`](./lifted-sign.mjs) | Node 18+ | none — built-in `fetch`/`FormData` |
| [`quickstart.sh`](./quickstart.sh) | bash | `curl` + `jq` |

## 30-second start

```bash
export LIFTED_SIGN_KEY=sk_live_xxx          # mint a key in your dashboard → Developers

python lifted_sign.py    contract.pdf dana@example.com "Dana Client"
# or
node   lifted-sign.mjs   contract.pdf dana@example.com "Dana Client"
# or
./quickstart.sh          contract.pdf dana@example.com "Dana Client"
```

Each prints the four steps and the new envelope id. Your signer gets a single-use signing link by
email.

## Use it as a library

```python
from lifted_sign import LiftedSign

ls  = LiftedSign(api_key="sk_live_...")
env = ls.create_agreement("contract.pdf", name="Master Services Agreement")
ls.add_signers(env["id"], [{"name": "Dana Client", "email": "dana@example.com"}])
ls.place_fields(env["id"], [
    {"signer": "dana@example.com", "type": "signature", "anchor": "Signature:"},
    {"signer": "dana@example.com", "type": "date",      "anchor": "Date:"},
])
ls.send(env["id"])
```

```js
import { LiftedSign } from "./lifted-sign.mjs";

const ls  = new LiftedSign({ apiKey: "sk_live_..." });
const env = await ls.createAgreement("contract.pdf", { name: "Master Services Agreement" });
await ls.addSigners(env.id, [{ name: "Dana Client", email: "dana@example.com" }]);
await ls.placeFields(env.id, [
  { signer: "dana@example.com", type: "signature", anchor: "Signature:" },
  { signer: "dana@example.com", type: "date",      anchor: "Date:" },
]);
await ls.send(env.id);
```

## Placing fields

Three ways, most-programmatic first:

```jsonc
// anchor (recommended) — snap to text that already exists in the PDF
{ "signer": "dana@example.com", "type": "signature", "anchor": "Signature:" }
// options: "anchor_index" (nth match), "place" ("right"|"left"|"below"|"above"|"over"), "dx"/"dy" (points)

// absolute PDF points
{ "signer": "dana@example.com", "type": "signature", "page": 0, "x": 100, "y": 200, "unit": "pt" }

// normalized 0..1 of the page
{ "signer": "dana@example.com", "type": "signature", "page": 0, "x": 0.5, "y": 0.5 }
```

Field types: `signature`, `initials`, `date`, `text`, `name`, `email`, `checkbox`.
Placement is **fail-closed** — if any field can't be resolved, the whole batch is rejected (never a
silent drop on a legal document).

## Full reference

- Interactive docs: <https://sign.example.com/developers>
- OpenAPI 3.1 spec: <https://sign.example.com/developers/openapi.json>
- Postman collection: [`lifted-sign.postman_collection.json`](../postman/lifted-sign.postman_collection.json)

MIT licensed. Use freely.
