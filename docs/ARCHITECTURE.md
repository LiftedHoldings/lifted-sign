# Lifted Sign — Architecture

> A self-hostable, ESIGN/UETA-compliant e-signature server. Upload a PDF, place
> fields, send single-use signing links, and receive a cryptographically sealed
> executed copy with a Certificate of Completion. One codebase runs three ways —
> self-host, hosted, or embedded — driven entirely by environment configuration.
>
> Author: **Daniel Wilson Kemp**. License: **AGPL-3.0-or-later** (client SDKs: MIT).

This document is the map a reviewer needs to judge the design: what the system
promises legally, how it keeps that promise cryptographically, and why the
structural choices are what they are. Every claim below points at a real module.

---

## 1. What it is, and the compliance model it implements

Lifted Sign is a complete signing service, not a PDF-stamping library. Its reason
to exist is the part most "add a signature to a PDF" tools skip: producing a
record that stands up as an **electronic signature under the U.S. ESIGN Act
(15 U.S.C. §7001) and UETA**. That statutory model drives the whole backend, and
four mechanisms carry it.

### 1.1 Disclosure + consent, hashed to the exact bytes shown

Before anyone can sign, ESIGN §7001(c) requires an *E-Records & Signatures
Disclosure* (ERSD) and affirmative consent. The disclosure is the single source
of truth in [`esign_disclosure.py`](../sign/esign_disclosure.py): two verbatim
forms — a short **B2B** consent and the full **consumer** disclosure carrying all
five statutorily required elements (paper-copy right, right to withdraw, scope,
contact-update procedure, hardware/software requirements). It ships a `VERSION`
stamp (`ERSD-2026-06-01`) and computes a **SHA-256 hash of the exact text bytes**
(`disclosure()` → `text_hash`).

The signer page renders those *same bytes*; consent capture in
`esign.record_consent()` persists `consent_at`, `consent_ip`, the
`disclosure_version`, and the **`disclosure_text_hash`** the signer echoed back,
plus `access_demonstrated` / `access_method` (proof the signer could actually open
the electronic record). Because the certificate later embeds the same version and
hash, you can prove *which disclosure text this signer agreed to* — even after the
canonical text is revised, since older consents keep their old hash. Withdrawal is
a first-class, timestamped action (`withdraw_consent()`), as ESIGN requires.

### 1.2 Tamper-evident certification: PAdES first, AES fallback

When the last signer submits, `esign.finalize()` → `_seal_and_complete()` burns
the field values onto the **frozen** presented bytes (so *signed == presented*),
appends the Certificate of Completion, and seals. Sealing has two tiers, chosen by
`pdf_sign.material_ok()` *before* the certificate is rendered so the certificate's
own wording is truthful:

- **PAdES certification signature** (the real lock) —
  [`pdf_sign.certify_pdf()`](../sign/pdf_sign.py) applies an ETSI.CAdES.detached
  signature at **DocMDP level 1 (`MDPPerm.NO_CHANGES`)** via pyHanko. Any later
  edit — a one-byte change or an appended incremental revision — invalidates the
  signature in Acrobat and every compliant viewer. This is the DocuSign
  "certified copy" model.
- **AES-256 integrity seal** (`pdf_edit.secure_pdf()`) — the fallback when no
  signing certificate is available. The document is still tamper-evident via the
  recorded hash chain; it simply can't be *attested* by a PDF validator.

Two hashes bracket the seal: `preseal_hash` (the stamped bytes) and `sealed_hash`
(the delivered bytes), both persisted on the agreement. The `seal_method` column
records which tier ran, and `pdf_sign.validate()` reports `{valid, certified,
tampered, docmdp_ok, …}` for any executed file — an unparseable or truncated file
is reported as a *detected tamper*, never a crash.

**Fail-honest degrade.** If PAdES was provisioned but signing throws at the last
step, the seal never ships an AES file wearing "certified" wording: the code
re-renders the certificate with AES wording, re-seals with AES, and writes a
distinct, alertable `DOC_SEAL_DEGRADED` audit event
([`esign.py` `_seal_and_complete`](../sign/esign.py)).

### 1.3 The audit event trail

Every legally relevant action appends an immutable row to `agreement_events`
(`type`, `signer_id`, `ip`, `user_agent`, `detail`, `at`): `viewed`,
`ECONSENT_ACCEPTED`, `RECORDS_ACCESS_DEMONSTRATED`, `ENVELOPE_ACCESS_VERIFIED`,
the `ACCESS_CHALLENGE_*` family, `DOC_SEALED`, `completed`, and
`COMPLETED_COPY_DELIVERED`. A hard rule is enforced at the call sites: event
`detail` is **type-only** — a raw challenge value, SSN, DOB, or OTP is never
written into an event (`_CHALLENGE_EVENTS`, see the CHAL-6 comments). The
Certificate of Completion renders this trail alongside signer identity,
timestamps, IPs, the disclosure text+version+hash, and the pre-seal document hash.

### 1.4 The seal, end to end

```
last signer submits ──▶ esign.submit_signature()
                          │  records values, marks signed
                          ▼
                        esign.finalize()
                          │  ┌─ idempotent: already 'completed' ─▶ return True
                          │  ├─ refuse if any signer's access-lock unmet (CHAL-4)
                          │  └─ ATOMIC CLAIM: UPDATE ... SET status='sealing'
                          │        (self-heals a stale/abandoned 'sealing' claim)
                          ▼
                        _seal_and_complete()
   presented bytes ──▶ stamp_fields ──▶ preseal_hash = sha256(stamped)
        (frozen)          │
                          ├─ material_ok? ── yes ─▶ append cert(PAdES wording)
                          │                          sanitize (last re-serialize)
                          │                          certify_pdf  ── DocMDP L1
                          │                             └─ throws ─▶ degrade to AES
                          │                                          + DOC_SEAL_DEGRADED
                          └─ no ──────────────▶ append cert(AES wording) ─▶ secure_pdf
                          ▼
        sealed_hash = sha256(executed) ─▶ store executed_path, seal_method,
                                          hashes ─▶ status='completed'
                          ▼
        email SIGNED copy + cert to every signer AND the sender
```

---

## 2. One codebase, three runtimes

The [package docstring](../sign/__init__.py) states the contract: *self-host*,
*hosted*, and *embedded* share the identical HTTP surface, signing engine, and PDF
stack — **only the injected adapters differ**, and they are selected by the
environment, never by a build flag or a code fork.

| | Self-host (default) | Hosted | Embedded |
|---|---|---|---|
| **Database** | SQLite file (zero config) | Postgres (`DATABASE_URL`) | Host-injected DSN |
| **Email** | Console print / SMTP | Transactional SMTP | Host mailer via seam |
| **Sign-in** | Email **magic-link** | Google + phone-OTP | Host auth |
| **Billing** | None | Stripe seam (`SIGN_HOSTED_MODE`) | Host billing |
| **Trigger** | Nothing but `SIGN_SECRET` | Env vars set | Mounted as sub-app |

Three seams make this work:

**Env-driven configuration.** [`config.py`](../sign/config.py) reads *everything*
from the process environment and preserves the two accessors the engine was
written against — `local()` (a nested settings dict with an `"esign"` block) and
`REPO_ROOT`. Crucially, every hosted-service default is **blank**, never a
hardcoded domain or company: `LEGAL_ENTITY`, `MAIL_FROM`, `SUPPORT_EMAIL`,
`OPERATOR_NAME`, `PUBLIC_BASE_URL` all resolve from config, with neutral fallbacks
(`OPERATOR_NAME` → `LEGAL_ENTITY` → the product display name). Page shells carry
`{{OPERATOR_NAME}}`/`{{PUBLIC_BASE_URL}}` tokens substituted at serve time
(`app._page`), so a fresh install never leaks a placeholder like `example.com`.

**The billing seam.** [`sign_accounts.py`](../sign/sign_accounts.py) is the paywall
without a payment processor. `can_send()` is the single server-side gate the send
and remind routes consult; `activate_subscription()` is the *exact* point a real
charge is later inserted — and it deliberately refuses to reactivate a
canceled/past-due account without one. This module imports **no** payment SDK. The
hosted tier's Stripe dependency is an *optional* extra
([`pyproject.toml`](../pyproject.toml) `[hosted]`) imported lazily only when
`SIGN_HOSTED_MODE=true`, so the self-host build carries zero payment code on its
import path.

**Optional auth add-ons.** `sign_portal_auth.available_methods()` probes the
environment and reports which sign-in methods this install can actually offer:
**magic-link is always available** (it needs nothing but `SIGN_SECRET`); Google
and phone-OTP light up only when their env groups are present. The SPA renders
only the usable buttons, so a self-hoster never sees a dead control.

---

## 3. Module map: the request path

```
                         ┌───────────────────────────────────────────┐
   HTTP request ─────────▶  sign/app.py  (FastAPI ASGI app)          │
                         │   _gate middleware, per request:           │
                         │    1. OWASP Origin CSRF check              │
                         │    2. public-route allowlist / session     │
                         │       or Bearer presence                   │
                         │    3. strict CSP + security headers        │
                         └───────┬───────────────────────────────────┘
                                 │ include_router
        ┌────────────────────────┼───────────────────────────────────┐
        ▼            ▼            ▼           ▼           ▼            ▼
  routers/       routers/     routers/    routers/    routers/     routers/
  portal.py      mysign.py    signer.py   envelope.py developers   ops.py
  auth/login     tenant API   public      proven-id   API docs +   operator
  (magic/        (envelopes,  signer      signer      OpenAPI      console
  google/phone)  templates,   page +      session                 (ADMIN_
                 API keys)    token acts   (Google/OTP)            EMAILS)
        │            │            │           │                       │
        └────────────┴─────┬──────┴───────────┴───────────────────────┘
                           ▼
                 sign/esign.py  — the signing engine
      create_agreement · set_signers · set_fields · place_fields (anchors)
      send · signing_payload · record_consent · submit_signature
      finalize → _seal_and_complete · sweep_expired
                           │
             ┌─────────────┼───────────────────────────┐
             ▼             ▼                            ▼
     sign/pdf_edit.py   sign/esign_access.py     sign/db.py
     (PDF facade)       (challenge + envelope    (SQLite-first
             │           sessions, identity)      persistence)
   ┌─────────┼─────────────────────┐
   ▼         ▼          ▼           ▼
 pdf_render pdf_stamp pdf_cert   pdf_redact ── pdf_sign.py (PAdES)
 (rasterize (burn     (cert +    (rasterize    (pyHanko PKCS#7
  + inspect) values)  seal ops)   redaction)    certification)
```

### The layers

- **HTTP / [`app.py`](../sign/app.py).** A single FastAPI app with no host
  coupling — no admin Google gate, no activity feed, no telemetry sink. One
  `@app.middleware("http")` folds three concerns into a single choke-point: an
  Origin-based CSRF check on mutating `/api/*` calls, a public-route allowlist
  (everything non-public needs a session cookie *or* a Bearer key just to reach a
  handler), and hardened response headers. Table bootstrap and a self-signed cert
  provision run once in the lifespan; an hourly background task
  (`_esign_expiry_poller`) sweeps expired envelopes.

- **Routers.** Thin: they parse the request, call an authn/authz helper from
  [`http_helpers.py`](../sign/http_helpers.py), delegate to the engine (off the
  event loop via `asyncio.to_thread`), and return JSON. Six routers cover the
  whole surface — `portal` (signup/login), `mysign` (the tenant product API),
  `signer` (public token-gated signing), `envelope` (proven-identity signer
  sessions), `developers` (API docs), `ops` (operator console).

- **Engine / [`esign.py`](../sign/esign.py).** The stateful core: agreements,
  signers, fields, templates, the send/consent/sign/seal lifecycle, and the
  expiry sweep. It owns its own tables (`ensure_tables()` self-runs at import) and
  carries additive `db._columns` migrations for every column added over time.

- **PDF stack.** [`pdf_edit.py`](../sign/pdf_edit.py) is a thin facade whose only
  job is to keep every caller stable while the implementation lives in
  permissive-licensed modules: `pdf_render` (rasterize + text-span inspection),
  `pdf_stamp` (burn field values / author text), `pdf_cert` (Certificate of
  Completion + the `sanitize`/`secure`/`append` post-ops), `pdf_redact` (true
  rasterizing redaction), `pdf_editext` (in-place text replacement), and
  `pdf_sign` (the PAdES layer). Coordinates are normalized `0..1`, origin
  top-left, in the page's rotated visual frame — the same convention the SPA
  editor uses.

- **Persistence / [`db.py`](../sign/db.py).** See §5.

---

## 4. Security model

Authentication and authorization funnel through a few deliberate choke-points.

**HMAC tokens keyed off one secret.** [`webauth.py`](../sign/webauth.py) `_sign` /
`_unsign` sign every token as `body.sig` where `sig = HMAC-SHA256(SIGN_SECRET,
body)`. Each token carries a `k` (kind) field and is validated against it, so a
token minted for one purpose can never be replayed as another:

| Kind | Purpose | Module |
|---|---|---|
| `signacct` | SPA session (7-day) | `sign_portal_auth.make_session` |
| `signacct2fa` | Half-session, TOTP pending | `sign_portal_auth.make_2fa_pending` |
| `signacctphone` | Phone-OTP half-session (phone baked at send) | `sign_portal_auth.make_phone_pending` |
| `signmagic` | One-time email magic-link (15-min) | `sign_portal_auth.make_magic_token` |
| `signverify` | Email-verification link | `sign_portal_auth.make_verify_token` |
| `envsess` | Proven-identity envelope session (30-min) | `esign_access` |

**`__Host-` cookies.** Session and envelope cookies use the `__Host-` prefix
(`__Host-ls_sign`, `__Host-ls_env`, …), which browsers accept only over HTTPS with
`Secure`, `Path=/`, and no `Domain`. `_set_sign_cookie` sets `httponly`,
`secure`, `samesite=lax` (lax, not strict, so a top-level Google redirect returns
the cookie).

**Owner-scoping, 404 not 403.** Every tenant row carries `owner_account_id`
(`NULL` legacy rows are invisible to every tenant, since `NULL` never satisfies
`owner_account_id = ?`). All `/api/mysign/*` handlers pass through the single IDOR
choke-point `_require_owned()`, which returns **404, not 403**, when an account
requests an agreement it doesn't own — so an object's existence is never an oracle.
Bearer API keys resolve to the same account and flow through the identical
choke-point, granting no authority a logged-in user lacks — and *account-security*
routes (2FA, billing) use `_require_sign_cookie` (cookie-only), so a leaked API key
can never re-arm the 2FA phone.

**Signer access control.** [`esign_access.py`](../sign/esign_access.py) governs the
public signing side. An *envelope session* is a proven-identity token minted
**only** after a Google email match or a self-issued email-OTP approval — never
from knowledge of an envelope ID or a signer token — and is scoped to exactly one
`{envelope_id, signer_id}` pair. A sender-set *access challenge* (code/text/DOB/
SSN-last4) is stored as a salted **PBKDF2** digest, **Fernet-wrapped at rest**;
compares are constant-time and a full PBKDF2 runs even when no record exists, to
deny a timing/existence oracle. The module is explicit that for low-entropy
identity types the real defense is the online rate-limit + lockout, not the KDF.

**Rate limiting + lockout.** [`db.py`](../sign/db.py) implements fixed-window rate
limiting (`auth_rate_allowed`) and brute-force lockout (`auth_limit_*`), each doing
its read-modify-write atomically in a single upsert with `RETURNING` so counters
stay correct on Postgres under READ COMMITTED (and `BEGIN IMMEDIATE` is a real
write lock on SQLite). These guard signup, magic-link and OTP sends, TOTP/SMS
factors, and the signer access challenge.

**Fernet at rest.** [`crypto.py`](../sign/crypto.py) derives a Fernet key
(`base64(sha256(SIGN_SECRET))`) with no separate key to manage, and encrypts
secrets like TOTP seeds. Ciphertext carries a version prefix so a reader can tell
it from legacy plaintext; a wrong key fails *soft* (returns the token unchanged)
because a secret rotation is an intentional break, not a hard lock-out.

**Password + API-key hashing.** Sender passwords and API keys are PBKDF2-HMAC-
SHA256, 200k iterations, per-record salt, constant-time compare; `verify_password`
always runs a full PBKDF2 against a dummy record when none exists, killing the
user-existence timing oracle. API keys are shown once and stored only as a hash
plus a short indexed prefix — a DB leak recovers no usable key.

**Strict CSP, no CDN.** [`http_helpers.STRICT_CSP`](../sign/http_helpers.py) is
`default-src 'self'` with `object-src 'none'`, `base-uri 'none'`, and
`frame-ancestors 'none'`. The only concessions are `worker-src blob:` (the
vendored PDF.js worker) and `img-src data:` (rendered pages + adopted-signature
data URIs). No external fonts, scripts, or styles — everything is first-party
under `/static`.

---

## 5. Persistence: SQLite-first, translated up to Postgres

[`db.py`](../sign/db.py) makes a deliberate choice most projects invert: **SQLite
is the canonical dialect**. Every query in the app is written in SQLite SQL. Only
when `DATABASE_URL` is set does the layer translate those statements on the fly for
Postgres — `psycopg` is imported *lazily*, so a self-host SQLite install never
needs it installed.

- **Statement translation.** `_translate_sql` rewrites `?` placeholders to `%s` and
  escapes literal `%`, skipping the contents of quoted string literals; `_to_pg`
  maps `INSERT OR IGNORE` → `ON CONFLICT DO NOTHING` and fails loudly on the few
  constructs that need an explicit rewrite. `_translate_ddl` maps
  `INTEGER PRIMARY KEY AUTOINCREMENT` → an identity column, `REAL` → `double
  precision`, `BLOB` → `bytea`.
- **Work-alike shims.** `PgConnection` / `PgCursor` present a `sqlite3`-shaped API
  (context manager, `execute`, `lastrowid`) backed by psycopg, and a `_Row` type
  supports both positional and by-name access like `sqlite3.Row`. `insert_returning`
  appends `RETURNING id` on Postgres and falls back to `lastrowid` on SQLite —
  callers never branch on backend.
- **Additive migrations, never a raw PRAGMA.** Each table-owning module keeps its
  own `ensure_tables()` with column-add migrations gated on `db._columns()`, which
  branches on the backend (`PRAGMA table_info` on SQLite, `information_schema` on
  Postgres) — a raw `PRAGMA` would be a syntax error on Postgres.
- **Safe cross-process bootstrap.** `db.ensure_tables()` creates the shared infra
  tables and delegates to every sign module's `ensure_tables()`, taking a Postgres
  session **advisory lock** so a web + worker booting together can't deadlock on
  concurrent `CREATE`/`ALTER`. An optional `psycopg_pool` connection pool is used
  when available and degrades to connect-per-call when not.

### Data model

| Table | Owner module | Holds |
|---|---|---|
| `agreements` | `esign.py` | Envelope: status, order mode, source/frozen/executed paths, `owner_account_id`, hash chain (`preseal_hash`, `sealed_hash`), `seal_method`, expiry, `env_session_epoch` |
| `agreement_signers` | `esign.py` | Per-signer identity, token, status, viewed/signed timestamps, IP/UA, ESIGN consent columns, Fernet-wrapped access challenge |
| `agreement_fields` | `esign.py` | Placed fields (type, normalized x/y/w/h, page, required, value, prefill/prompt) |
| `agreement_events` | `esign.py` | Immutable audit trail (type, signer, IP, UA, type-only detail, timestamp) |
| `esign_templates` | `esign.py` | Reusable snapshots: blank source + signer roles + field layout as JSON |
| `sign_accounts` | `sign_accounts.py` | Sender tenants: email, PBKDF2 password, Google sub, TOTP/phone 2FA, subscription status, revocation epoch |
| `sign_api_keys` | `sign_api_keys.py` | Developer Bearer keys (hash + indexed prefix, mode, revocation) |
| `settings`, `auth_limits`, `auth_rate_limits` | `db.py` | Key/value settings, lockout + rate-limit counters |

---

## 6. Key design decisions, and why

**SQLite-first with up-translation (not an ORM).** A self-hoster's first run must
need *nothing* — no database to provision, no driver to install. Writing SQLite as
the canonical dialect and translating up to Postgres keeps the zero-config default
honest while still serving a managed multi-tenant deployment from the same query
text. An ORM would have added a dependency and a leaky abstraction over exactly the
two dialects that matter; the thin translator is smaller and fully legible.

**AGPL server, MIT SDKs.** The server is AGPL-3.0 so hosted derivatives stay open.
But the network-copyleft must not reach a *user's* application just because they
call the API, so the vendored Python and Node clients under
[`sdks/`](../sdks/) are MIT — integrating against Lifted Sign never touches your
licensing.

**A permissive PDF stack — no PyMuPDF.** The entire PDF engine is deliberately free
of AGPL PyMuPDF/MuPDF. `pdf_edit` is a facade over reportlab (BSD), pypdf (BSD),
pikepdf (MPL), pypdfium2 (BSD/Apache), pdfplumber (MIT), fontTools (MIT), Pillow
(HPND), and pyHanko (MIT). This is what lets the *whole product* ship under a
single clean license story instead of inheriting a second, stricter one through a
rendering dependency.

**Anchor-based field placement.** Fields can be placed by text anchor, not just by
pixel — `esign._anchor_hits()` / `detect_prefill_fields()` / `place_fields()` find
label text in the extracted spans and drop fields relative to it, so a template
survives a document whose layout shifts. Placement uses the same normalized `0..1`
top-left coordinate frame as the editor, so the same field definition renders
identically at any DPI.

**Fail-closed on a weak secret.** `config._require_secret()` refuses to boot
(`SystemExit(78)`, EX_CONFIG) if `SIGN_SECRET` is missing, under 16 chars, or a
known placeholder. Because every session, signer cookie, and OTP HMAC is keyed off
it, a booted-but-weak-secret server is an account-takeover risk — so the failure is
loud and early rather than silent.

**Self-signed PAdES auto-provisioning.** On first boot, when no signing material is
configured, `esign.ensure_signing_material()` generates a self-signed RSA-2048
cert+key into the gitignored data dir (0600 key) so a zero-config install still
produces *real* PKCS#7/PAdES certification signatures — not an AES-only seal that a
validator can't attest. A self-signed cert secures integrity and certification; it
simply won't chain to Adobe's trust store until you install a CA-issued one. Key
hygiene is enforced: `pdf_sign` never writes a key under the repo, and its
`provision` CLI refuses an output path inside the worktree.

**No external font or CDN dependencies + strict CSP.** Fonts, PDF.js, and the
design system are all vendored and served first-party, which is what makes the
`default-src 'self'` CSP viable. The payoff is an install that works air-gapped and
has no third-party asset host in its trust boundary.

---

## 7. Operational surface

- **Run it.** `python -m sign` (or `docker compose up`). The default is SQLite +
  console email + magic-link — nothing but `SIGN_SECRET` required.
- **Health.** `GET /health` / `/healthz` → `{"ok": true, "service":
  "lifted-sign"}`.
- **Operator console.** `/api/sign-ops/*` is closed by default and opens only to a
  signed-in account whose email is in `ADMIN_EMAILS`; empty `ADMIN_EMAILS` means
  every operator route returns 403, so a fresh self-host exposes no unauthenticated
  operator surface.
- **Developer API.** `/api/mysign/*` with cookie *or* `Bearer sk_live_…` auth;
  `/developers` serves human docs and an OpenAPI spec.

For the full environment reference, SMTP/Postgres/PAdES setup, and running behind
nginx with TLS, see [**docs/self-hosting.md**](./self-hosting.md).

---

Built by Daniel Wilson Kemp.
