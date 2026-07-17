# How Lifted Sign compares

A fair, factual look at where Lifted Sign sits next to three well-known e-signature
tools: **DocuSign** and **Dropbox Sign** (proprietary, cloud-only SaaS) and
**Documenso** (the closest open-source peer).

All four collect legally-binding e-signatures with audit trails. The differences are
about *ownership, deployment, and how you integrate* — which is where Lifted Sign is
deliberately different.

## At a glance

| | **Lifted Sign** | DocuSign | Dropbox Sign | Documenso |
|---|:---:|:---:|:---:|:---:|
| **Self-hostable** | ✅ Yes | ❌ No (SaaS only) | ❌ No (SaaS only) | ✅ Yes |
| **Zero-config DB (SQLite default)** | ✅ Yes | — (managed SaaS) | — (managed SaaS) | ❌ Requires Postgres |
| **PAdES / PKCS#7 certification** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| **REST API + SDKs** | ✅ Python, Node | ✅ Many languages | ✅ Many languages | ✅ API + SDK |
| **License** | AGPL-3.0 (SDKs MIT) | Proprietary | Proprietary | AGPL-3.0 |
| **Price** | Free self-host · free hosted beta | Paid¹ | Paid¹ | Free self-host · paid hosted |

¹ DocuSign and Dropbox Sign are commercial products with published list plans that
change over time and vary by seats and volume — see their pricing pages for current
figures. The point of this row is *free vs paid*, not a specific number.

## What actually sets Lifted Sign apart

Each competitor is strong on its own terms. Lifted Sign's edge is the **combination** of
four things in one package:

1. **Self-hostable — and trivial to run.** Documenso is also open source and
   self-hostable, but it requires a PostgreSQL database and external SMTP to stand up.
   Lifted Sign boots on **SQLite with a single secret** and console email, so "try it"
   and "run it in production on a small box" are the same short path. Add Postgres later
   with one env var — you're never forced into it on day one.

2. **Real PAdES certification, built in and free.** Completed PDFs get a PKCS#7/PAdES
   digital signature that any PDF reader can validate and that visibly breaks if the file
   is tampered with — not a flattened image of a signature. It's included when you
   self-host, with no per-signature or per-seat metering. (Without a certificate
   installed yet, documents still get a tamper-evident AES-integrity seal.)

3. **Developer-first, no sales call.** A REST API, an OpenAPI spec, and vendored
   **Python and Node SDKs** ship in the repo. The SDKs are MIT-licensed, so integrating
   against Lifted Sign never pulls the AGPL into your application.

4. **AGPL, genuinely free to self-host.** No seat caps, no volume policing, no
   "enterprise tier" gate on core signing. The hosted service is free during beta and
   never a lock-in: because the software is open, you can move to self-hosting at any
   time.

## When another tool is the better call

Being fair cuts both ways. Reach for something else when:

- **You want zero infrastructure and don't need to self-host.** A fully-managed
  commercial SaaS (DocuSign, Dropbox Sign) removes all operational responsibility, and
  their hosted tiers are mature. Lifted Sign's own hosted tier is in beta.
- **You need breadth Lifted Sign doesn't have yet** — e.g. a large library of official
  SDK languages, deep CRM/marketplace integrations, notarization, or specific regulated
  certifications (21 CFR Part 11, eIDAS QES). The incumbents have years of surface area
  here.
- **You're already standardized on a TypeScript/Next.js stack** and want a self-hosted
  OSS tool in that ecosystem — Documenso may fit your team better.

Lifted Sign is for teams who want to **own the whole signing pipeline** — the data, the
audit trail, and the integration — on infrastructure they control, without a database to
babysit or a license that reaches into their app.

---

*Comparisons reflect publicly documented behavior of each product at the time of writing.
Competitor products evolve; verify current specifics against their own documentation.
Corrections via [pull request or issue](https://github.com/LiftedHoldings/lifted-sign)
are welcome — accuracy matters more than favorable framing.*
