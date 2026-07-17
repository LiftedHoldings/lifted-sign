# Lifted Sign — developer guides

Task-focused guides for building on the **[Lifted Sign](https://sign.example.com)** API:
turn a PDF into a legally binding, tamper-sealed, certificate-backed signed document —
programmatically. Start with the overview, then follow the envelope lifecycle from create to
completed. Every guide is self-contained with copy-paste `curl` examples.

> ### ⏱️ 5-minute quickstart
> New here? Skip straight to **[02 — Quickstart](./02-quickstart.md)**. Mint a key, create an
> envelope from a PDF, add a signer, place a signature field, and send — your first signature
> request goes out before your coffee's cold. Come back for the concepts once it works.

**Prefer to click?** The full interactive API reference (try-it console + live key management)
lives at **<https://sign.example.com/developers>**. The machine-readable
**[OpenAPI 3.1 spec](../openapi.yaml)** is the source of truth for every endpoint, field, and
error — import it into Redoc, Swagger UI, Stoplight, or your codegen.

---

## Get started

| Guide | What it covers |
|-------|----------------|
| [01 — Overview](./01-overview.md) | What Lifted Sign is, the envelope lifecycle, and how the pieces fit together. |
| [02 — Quickstart](./02-quickstart.md) | Send your first envelope end-to-end in five minutes with plain `curl`. |
| [03 — Authentication](./03-authentication.md) | Bearer API keys, live vs. test mode, and keeping secrets server-side. |

## Core concepts

| Guide | What it covers |
|-------|----------------|
| [04 — Envelopes](./04-envelopes.md) | Create, read, void, and delete the container that holds your document and signers. |
| [05 — Signers & routing](./05-signers-and-routing.md) | Add recipients, set roles, and choose parallel vs. sequential signing order. |
| [06 — Placing fields](./06-placing-fields.md) | Position signature, initial, date, and text fields on the page by coordinates. |
| [07 — Templates & prefill](./07-templates-and-prefill.md) | Reuse a saved layout and merge in per-recipient data to skip manual field placement. |
| [08 — Sending & tracking](./08-sending-and-tracking.md) | Freeze and send an envelope, then poll status and remind pending signers. |

## Reference

| Guide | What it covers |
|-------|----------------|
| [09 — Downloads & certificates](./09-downloads-and-certificates.md) | Retrieve the executed PDF and its Certificate of Completion. |
| [10 — Errors & reliability](./10-errors-and-reliability.md) | Error shapes, HTTP status conventions, idempotency, rate limits, and retries. |

## Tools

| Guide | What it covers |
|-------|----------------|
| [11 — SDKs & tools](./11-sdks-and-tools.md) | Postman collection, OpenAPI-driven codegen, and language client patterns. |
| [12 — Webhooks & polling](./12-webhooks-and-polling.md) | Stay in sync with envelope events — subscribe to webhooks or poll for status changes. |

---

## Also in this docs folder

- [`../openapi.yaml`](../openapi.yaml) — hand-authored **OpenAPI 3.1** spec, the source of truth.
- [`../lifted-sign.postman_collection.json`](../lifted-sign.postman_collection.json) — runnable Postman collection with a Quickstart folder.
- [`../lifted-sign.postman_environment.json`](../lifted-sign.postman_environment.json) — Postman environment (`base_url`, `api_key`, `agreement_id`).

Questions or a key to revoke? **<https://sign.example.com/developers>** or email
[support@example.com](mailto:support@example.com).
