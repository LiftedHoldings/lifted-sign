# Placing fields

Fields are the boxes a signer fills in — a signature, a date, a checkbox. You place them all in one call:

```
POST /api/mysign/agreements/{aid}/fields
```

This is the headline of the Lifted Sign developer experience. The usual way to stamp a signature box onto a contract is to render the PDF, eyeball pixel coordinates, and hope the layout never changes. You don't have to. **Name the text that's already in the document and the field snaps to it** — no rendering, no coordinate math, and the placement survives edits to the document above it.

The endpoint is **draft-only** and **replace-all**: every call sets the envelope's *entire* field layout, so send the full list each time. Once the envelope is sent the layout is frozen (see [Draft immutability](#already-sent-envelopes) below).

```bash
curl -X POST https://sign.example.com/api/mysign/agreements/42/fields \
  -H "Authorization: Bearer $LIFTED_SIGN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "fields": [
      { "signer": "dana@example.com", "type": "signature", "anchor": "Signature:" },
      { "signer": "dana@example.com", "type": "date",      "anchor": "Date:" }
    ]
  }'
```

```json
{
  "ok": true,
  "count": 2,
  "fields": [
    { "type": "signature", "anchor": "Signature:", "signer_id": 101, "page": 0, "x": 0.217, "y": 0.347, "w": 0.294, "h": 0.056, "placed": true },
    { "type": "date",      "anchor": "Date:",      "signer_id": 101, "page": 0, "x": 0.612, "y": 0.347, "w": 0.180, "h": 0.043, "placed": true }
  ]
}
```

Every field in the response reports where it landed in **normalized 0..1 coordinates** — `(x, y)` is the box's top-left corner as a fraction of the page, origin top-left, `y` increasing downward. Whatever mode you sent, the server always answers in normalized form.

---

## The three placement modes

Each field picks **one** of three ways to say *where* it goes. Anchor is the one to reach for; the other two exist for when you already have geometry.

| Mode | You supply | When to use |
|---|---|---|
| **1. Anchor** *(recommended)* | `anchor` (+ `place`, `dx`, `dy`, `anchor_index`) | Almost always. No rendering, no coordinates. |
| **2. Absolute points** | `page`, `x`, `y`, `unit: "pt"` (+ `width`, `height`) | You have a PDF-points layout from a design tool. |
| **3. Normalized 0..1** | `page`, `x`, `y`, `w`, `h` | You've rendered the page yourself and computed fractions. |

The mode is inferred from the keys you send: if `anchor` is present it's mode 1; otherwise it's points vs. normalized based on `unit` and the magnitude of your coordinates (details in [mode 2](#mode-2--absolute-points)).

---

### Mode 1 — Anchor (recommended)

Give the field a piece of text that already exists in the document. The field snaps to it. The match is **case-insensitive** and spans word boundaries within a line, so `"signature:"`, `"Signature:"`, and `"SIGNATURE :"` all find the same label.

```json
{ "signer": "dana@example.com", "type": "signature", "anchor": "Signature:" }
```

By default the field sits just to the **right** of the anchor text, vertically centered on it. Tune the placement with four optional keys:

| Key | Type | Default | What it does |
|---|---|---|---|
| `place` | string | `right` | Where the field sits relative to the anchor: `right`, `left`, `below`, `above`, `over`. An unrecognized value falls back to `right`. |
| `dx` | number (points) | `6` | Horizontal offset from the anchor. |
| `dy` | number (points) | `0` | Vertical offset from the anchor. |
| `anchor_index` | integer (1-based) | `1` | Which occurrence to use when the label repeats. |

**Placing relative to a label, nudged over:**

```json
{ "signer": "dana@example.com", "type": "date", "anchor": "Date:", "place": "right", "dx": 6 }
```

**Repeated labels** — a two-party contract with two `"Signature:"` lines. `anchor_index` counts matches in reading order (page, then top-to-bottom):

```json
{
  "fields": [
    { "signer": "dana@example.com", "type": "signature", "anchor": "Signature:", "anchor_index": 1 },
    { "signer": "sam@example.com",  "type": "signature", "anchor": "Signature:", "anchor_index": 2 }
  ]
}
```

**Stamping directly onto a token** with `place: "over"` — handy for `{{sign_here}}` style placeholders you've dropped into the document:

```json
{ "signer": "dana@example.com", "type": "signature", "anchor": "{{sign_here}}", "place": "over" }
```

Because anchoring reads the document's own text, you never render the PDF and you never do coordinate arithmetic. This is the integration we recommend.

---

### Mode 2 — Absolute points

Give the field a page and a position in **PDF points from the top-left**, and set `unit: "pt"`.

```json
{
  "signer": "dana@example.com",
  "type": "signature",
  "page": 0,
  "unit": "pt",
  "x": 150,
  "y": 620,
  "width": 200,
  "height": 48
}
```

| Key | Type | Notes |
|---|---|---|
| `page` | integer | 0-based page index. |
| `x`, `y` | number (points) | Top-left corner, measured from the page's top-left. |
| `unit` | `"pt"` | Marks `x`/`y`/`width`/`height` as points. |
| `width`, `height` | number (points) | Optional; default to the [per-type size](#field-types-and-default-sizes). |

Pull page dimensions from [`GET /api/mysign/agreements/{aid}/pages`](../openapi.yaml) (points, rotation applied) so your `y` lands where you expect on a non-letter page.

> **Auto-detection:** you don't strictly need `unit: "pt"` — the server also treats coordinates as points when any of `x`, `y`, or `width` is greater than `1.0`. The flip side matters for mode 3: keep **normalized** coordinates at or below `1.0`, or a stray `x: 1.5` will be read as points. When in doubt, be explicit with `unit`.

---

### Mode 3 — Normalized 0..1

Give the field a page and `x`/`y`/`w`/`h` as **fractions of the page** — origin top-left, `y` increasing downward. This is the advanced path; use it when you've already rendered the page and computed fractions yourself.

```json
{
  "signer": "dana@example.com",
  "type": "signature",
  "page": 3,
  "x": 0.12,
  "y": 0.78,
  "w": 0.30,
  "h": 0.06
}
```

`(x, y)` is the box's top-left corner. If you omit `w`/`h` they default to `0.2` / `0.04`. All four are clamped into the page, so a box that would overflow is nudged back inside.

---

## Field types and default sizes

`type` is one of nine kinds. Each has a sensible default box size (in points) that you can override with `width`/`height` in anchor and points modes:

| `type` | Default W × H (pt) |
|---|---|
| `signature` | 180 × 44 |
| `initials` | 72 × 44 |
| `date` | 110 × 26 |
| `text` | 170 × 26 |
| `name` | 180 × 26 |
| `email` | 200 × 26 |
| `title` | 170 × 26 |
| `company` | 180 × 26 |
| `checkbox` | 18 × 18 |

An unknown `type` falls back to `text` sizing. Set `required: false` on a field the signer may skip (fields are required by default).

---

## Resolving the signer

Every field is bound to exactly one signer. There are three ways to say who, checked in this order:

1. **`signer`** — the signer's **email** (recommended). Resolved strictly against the envelope's signer list, case-insensitively.
2. **`signer_id`** — the signer's integer id, if you already have it.
3. **Omit both** — allowed only when the envelope has **exactly one** signer; the field binds to that sole signer automatically.

```json
{ "signer": "dana@example.com", "type": "signature", "anchor": "Signature:" }
```

If you supply a `signer` email that isn't on the envelope, the field fails with `signer_not_found`. If you omit the signer on an envelope with more than one, it fails with `signer_required`. Add your signers first — see [Adding signers](./05-signers-and-routing.md).

---

## Fail-closed batch semantics

The whole request is one **fail-closed batch**. If *any* field can't be resolved — anchor text not in the document, unknown signer, or an ambiguous missing signer — the **entire batch is rejected and nothing is written**. Your existing layout is left exactly as it was. There are no partial placements to clean up.

A rejection is an HTTP **400** carrying a machine `error` code and the **0-based `field` index** of the offender, plus a `detail` echoing the unresolved value where it applies:

```json
{ "ok": false, "error": "anchor_not_found", "field": 0, "detail": "Signature:" }
```

| `error` | Meaning | `detail` |
|---|---|---|
| `anchor_not_found` | The anchor text isn't present in the document (check spelling, and that it's real text, not an image). | The anchor text you sent. |
| `signer_not_found` | The `signer` email doesn't match any signer on the envelope. | The email you sent. |
| `signer_required` | A field omitted the signer and the envelope has more than one — pick one explicitly. | — |
| `no fields` | The `fields` array was empty or missing. | — |

A field that isn't a JSON object at all is also rejected (as `bad_field` at that index). Fix the offending field and resubmit the full batch.

### Already-sent envelopes

Placing fields is only legal while the envelope is a **draft**. On a sent, completed, or voided envelope the call is a **soft** rejection — HTTP **200** with:

```json
{ "ok": false, "error": "locked — already sent" }
```

Note this is *not* a 4xx: check `ok` in the body, not just the status code. A sent envelope's presented bytes are frozen and its layout can never change — [void](./08-sending-and-tracking.md) it and start a new draft if you need a different layout.

---

## Prefill fields (sender-filled)

Most fields are filled by the *signer*. A **prefill** field is filled by *you*, the sender — think a "Company name" or "Effective date" you know at send time. You mark a field as prefill when you place it:

```json
{
  "signer": "dana@example.com",
  "type": "company",
  "anchor": "Company Name:",
  "prefill": true,
  "field_key": "company",
  "prompt": "Company name"
}
```

| Key | Purpose |
|---|---|
| `prefill: true` | Marks the field as sender-filled rather than signer-filled. |
| `field_key` | A stable key you'll supply the value under. |
| `prompt` | The human-readable question shown for the field. |

Prefill fields come into their own with **templates**: save a document once with its prefill fields, then mint a ready-to-send draft by passing `answers` keyed by each field's `field_key`. You can also let Lifted Sign auto-detect prefill fields from `{{tokens}}` and labels with `POST /api/mysign/agreements/{aid}/detect`. Both are covered in [Templates & prefill](./07-templates-and-prefill.md).

---

## SDK examples

The vendored SDKs wrap this endpoint as `place_fields` (Python) / `placeFields` (Node). Fields are plain dicts/objects in exactly the shapes above.

**Python** (`web/ds/vendor/sdk/lifted_sign.py`):

```python
from lifted_sign import LiftedSign

ls = LiftedSign(api_key="sk_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXX")

res = ls.place_fields(42, [
    {"signer": "dana@example.com", "type": "signature", "anchor": "Signature:"},
    {"signer": "dana@example.com", "type": "date",      "anchor": "Date:", "place": "right", "dx": 6},
    {"signer": "dana@example.com", "type": "company",   "anchor": "Company Name:",
     "prefill": True, "field_key": "company", "prompt": "Company name"},
])
print(res["count"], "fields placed")
```

**Node** (`web/ds/vendor/sdk/lifted-sign.mjs`):

```js
import { LiftedSign } from "./lifted-sign.mjs";

const ls = new LiftedSign({ apiKey: "sk_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXX" });

const res = await ls.placeFields(42, [
  { signer: "dana@example.com", type: "signature", anchor: "Signature:" },
  { signer: "dana@example.com", type: "date",      anchor: "Date:", place: "right", dx: 6 },
]);
console.log(`${res.count} fields placed`);
```

---

## Next

- **Before this:** [Adding signers](./05-signers-and-routing.md) — you can't bind a field to a signer that doesn't exist yet.
- **After this:** [Sending for signature](./08-sending-and-tracking.md) — freeze the layout and email each signer their link.
- **Reuse:** [Templates & prefill](./07-templates-and-prefill.md) — build the layout once, fill prefill fields per send.
