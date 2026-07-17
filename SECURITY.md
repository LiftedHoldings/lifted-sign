# Security Policy

Lifted Sign handles legally binding documents, signer identity data, and the
cryptographic material that seals completed agreements. Security is a first-class
concern of the project, and vulnerability reports are handled with priority. Thank you
for helping keep the project and the people who rely on it safe.

## Supported versions

Security fixes are provided for the latest released `0.x` line. Because the project is
pre-1.0, only the most recent release receives patches — self-hosters should track
releases and upgrade promptly to stay covered.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.** Public disclosure before a fix ships puts every
self-hosted install at risk.

Instead, report privately by either of:

- **GitHub Security Advisories** — open a private advisory from the repository's
  **Security → Report a vulnerability** tab (preferred; keeps the report attached to
  the code).
- **Email** — `security@liftedholdings.com` (for the canonical project); general product
  questions go to `support@liftedholdings.com`.

> **Operators / forks:** if you run your own deployment, use your own monitored security
> address here and set `SUPPORT_EMAIL` in your environment for the user-facing support
> contact. The two are intentionally distinct: one receives coordinated disclosures, the
> other answers ordinary product questions.

Please include as much of the following as you can:

- A description of the vulnerability and its impact.
- Steps to reproduce, or a proof-of-concept.
- Affected version(s) and configuration — SQLite vs. Postgres, self-host vs. hosted,
  and which optional sign-in methods (Google, phone, PAdES certificate) are enabled.
- Any suggested remediation.

### What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity classification within 10 business days.
- Regular updates as a fix is developed.
- Public credit for the disclosure, if you would like it, once a fix has shipped.

Please give a reasonable window to release a fix before any public disclosure. A
coordinated timeline will be agreed with you.

## Scope

**In scope:** the Lifted Sign server in this repository and the vendored client SDKs
under `sdks/`.

**Out of scope:** vulnerabilities in third-party dependencies (report those upstream;
tell us if Lifted Sign uses them in a way that materially amplifies the impact),
findings that require a pre-compromised host, physical access, or a stolen
`SIGN_SECRET`, and denial-of-service that requires privileged network position.

---

# Threat model

This section documents the defenses that actually exist in the code so that reviewers,
operators, and contributors share one mental model of *what protects what*. Every claim
below points at the module that implements it. When you change one of these modules,
update this section in the same pull request.

## Trust boundaries

Lifted Sign serves three distinct classes of principal, each with its own session kind
and its own guarantees:

| Principal            | What they are                                              | Session token                     |
| -------------------- | --------------------------------------------------------- | --------------------------------- |
| **Sender account**   | An authenticated user who creates and sends envelopes     | `__Host-ls_sign` (kind `signacct`) |
| **Signer**           | A recipient acting on one specific envelope via a link    | `__Host-ls_env` (kind `envsess`)  |
| **API client**       | A program holding a developer API key (`sk_live_…`)       | `Authorization: Bearer` header    |

Every session token is a compact HMAC-SHA256-signed JSON blob with an `exp` claim,
minted and verified by `webauth._sign` / `webauth._unsign` and keyed off the single
process secret `SIGN_SECRET`. Each kind carries a distinct `"k"` discriminator
(`signacct`, `envsess`, `signmagic`, `signverify`, `signacct2fa`, `signacctphone`), and
every consumer pins the kind it expects. A token minted for one purpose therefore
**cannot be replayed as another** — an envelope-signer token is rejected by the account
gate, and an account token is rejected by `require_env_session`.

## The root secret: fail-closed by design

`SIGN_SECRET` keys *every* session cookie, signer-access token, self-issued OTP HMAC,
and the at-rest encryption key. It is the single most sensitive value in the system, so
the server **refuses to boot** without a real one.

- `config._require_secret()` rejects a missing value, anything shorter than 16
  characters, and a set of known placeholders (`change-me`, `dev`, `secret`, …), exiting
  with `EX_CONFIG` (78) and a loud message.
- There is deliberately **no insecure fallback** anywhere downstream. Because a weak
  secret can never reach the auth layer, `webauth._secret()` and the session verifiers
  contain no dev-mode special case to bypass.

**Threat addressed:** a self-hoster who copies `.env.example` verbatim and forgets to
set a secret gets a hard failure at boot, not a server that silently signs every token
with a publicly known key.

## Cookies and transport

Session cookies use the `__Host-` prefix (`__Host-ls_sign`, `__Host-ls_env`, and the
short-lived 2FA/OAuth-state cookies). Browsers only accept a `__Host-`-prefixed cookie
when it is set `Secure`, `Path=/`, and with **no `Domain`** attribute — which pins the
cookie to the exact origin over HTTPS and blocks subdomain injection. `_set_sign_cookie`
sets `secure=True` and `httponly=True` unconditionally; `samesite=lax` is used (not
`strict`) only so a top-level Google sign-in redirect returns the cookie.

**Operator requirement:** run Lifted Sign behind TLS. Over plain HTTP the browser will
reject the cookies and sign-in cannot complete — this is intentional, not a bug.

## Owner scoping and IDOR defense

Everything a sender owns is scoped to their `owner_account_id`. Every `/api/mysign/*`
handler authenticates through the single choke-point `_require_sign_acct` and then
authorizes through `_require_owned(aid, acct)`, which resolves the agreement with
`esign.get_agreement_owned(aid, account_id)` — an ownership-scoped lookup.

A cross-owner request returns **404, not 403** (`http_helpers._require_owned`). Returning
403 would confirm that the ID exists; 404 makes a valid-but-not-yours ID
indistinguishable from a non-existent one, so the endpoint is not an object-enumeration
oracle.

Developer API keys resolve to the same account and flow through the *same*
`_require_owned` gate, so a key grants no authority a logged-in user lacks. Conversely,
account-security routes (2FA enroll/disable, billing) use `_require_sign_cookie` —
**cookie session only, never Bearer** — so a developer key (which is logged, committed,
and shared with third parties) can never alter the account's security configuration.

## Signer identity: envelope sessions

A signer never authenticates with an account. Instead, acting on a link produces an
*envelope session* (`__Host-ls_env`), which is a **proven-identity** token, not a
capability derived from knowing an envelope ID. It is defined and enforced in
`esign_access.py`:

- **Minted only after proof of identity** — either an exact, lowercased Google
  email-match against a signer on *this* envelope (`match_google_signer`) or an approved
  self-issued email OTP (`check_env_otp`). Knowing an `envelope_id` or a signer token is
  never sufficient.
- **Scoped to exactly one `{envelope_id, signer_id}` pair** and bound to the agreement's
  current *epoch*.
- **Short-lived** — a 30-minute absolute TTL.
- **Re-authorized on every request** via `require_env_session()`, which trusts the
  signed token for authz and uses the path's `env_id` *only* to detect a token/path
  mismatch (a cross-envelope attempt), which it denies. A sender void or revoke bumps the
  agreement epoch and instantly invalidates all live signer sessions.

## Signer access challenges

A sender can put an access lock on a signer (a shared code, or an identity check such as
date of birth or last-4 of SSN). Handled by `esign_access.verify_challenge`:

- The challenge secret is stored as a salted **PBKDF2-HMAC-SHA256** digest at 200,000
  iterations, then **Fernet-encrypted at rest** — the database never holds a usable hash.
- Comparisons are **constant-time** (`hmac.compare_digest` on fixed-length digests), and
  a full PBKDF2 runs even when no matching record exists, so neither a wrong value nor a
  non-existent signer is distinguishable by timing — there is no existence oracle.
- Failure responses never reveal *which* field was wrong, the challenge type, or whether
  the signer exists.

Low-entropy identity challenges (`ssn_last4` ≈ 10⁴ possibilities, `dob` ≈ 36,500) are
brute-forceable offline in well under a second, so the **PBKDF2 hash is not their real
protection** — the online rate-limit and lockout is. The code and admin UI steer senders
toward a high-entropy `code`/`text` secret shared out-of-band and label `ssn` "not
recommended." Treat identity challenges as a light "is this the right person" gate, never
as a secret.

## Rate limiting and lockout

The database-backed limiter (`db.auth_limit_locked` / `auth_limit_record` /
`auth_rate_allowed`) is the primary defense for every guessable secret. Counters are
incremented under a `BEGIN IMMEDIATE` transaction so the cap cannot be corrupted by
concurrent writers. Concrete limits, all in code:

- **Access challenges** — 5 failures per IP → 15-minute lockout (the primary control),
  plus a coarse 40/hour per-signer speed-bump against many-IP brute force.
- **Envelope OTP** — 5 sends/hour; 5 wrong codes → 15-minute lockout; a verify is
  rejected unless a code was actually *sent* to that signer within the last 10 minutes,
  which blocks cold-check abuse and griefing lockouts.
- **Account sign-up** — 5 new accounts per IP per 24 hours.
- **Magic-link sign-in** — 10/hour per IP and 5 per 15 minutes per target email
  (mailbomb / enumeration guard).
- **Phone OTP** — 8/hour per IP and 5 per 15 minutes per number, on top of Twilio's own
  limits.
- **TOTP / SMS second factor** — 5 failures → 15-minute lockout, per account.

## One-time codes and 2FA

- **Self-issued email OTP** (`esign_access._send_email_otp`) — a 6-digit code is
  generated server-side; the database stores only an **HMAC of the code keyed by the
  server secret** (not by any value in the database), so a database leak alone cannot
  recover live codes. Codes are single-use with a 10-minute TTL, and a delivery failure
  clears the live code rather than leaving it valid.
- **TOTP** (`webauth`, RFC 6238) — authenticator 2FA with no external dependency, with
  single-use replay protection: a code whose 30-second step is at or below the highest
  step already consumed is rejected, and if the consumed step cannot be persisted the
  verify fails closed rather than allowing a replayable acceptance. Per-account callers
  keep a per-account replay marker so one account's accepted code can never block another.
- **TOTP seeds** are encrypted at rest (`crypto.encrypt`) and never leave the server.

## CSRF and request origin

- **Origin-based CSRF defense** (`http_helpers._csrf_origin_ok`) — state-changing `/api/`
  requests are rejected when an `Origin` header is present and its host is not one of
  ours (derived from `PUBLIC_BASE_URL` plus the request's own `Host`, never a hardcoded
  domain). Absent-`Origin` requests (curl, server-to-server) are allowed because they are
  not a browser CSRF vector; public token-gated signer endpoints are exempt because the
  signer token independently authenticates them.
- **OAuth CSRF** — the Google sign-in redirect carries a one-time, unguessable `state`
  echoed back and compared constant-time; a missing cookie or parameter fails closed.

## At-rest encryption

`crypto.py` provides Fernet (AES-128-CBC + HMAC authentication) for secrets at rest —
TOTP seeds and Fernet-wrapped challenge digests. The 32-byte key is derived from
`SIGN_SECRET` (`base64.urlsafe_b64encode(sha256(SECRET))`), so there is no second key to
manage. Rotating `SIGN_SECRET` intentionally invalidates prior ciphertext (decrypt fails
soft rather than raising). Values carry a version prefix so ciphertext is always
distinguishable from legacy plaintext.

## Tamper-evident seal and Certificate of Completion

Completed documents are sealed so any later modification is detectable:

- **PAdES certification signature** (`pdf_sign.py`) — a PKCS#7 / ETSI.CAdES.detached
  *certification* signature applied at DocMDP level 1 (`NO_CHANGES`). Any post-signing
  edit — a one-byte change or an appended incremental revision — invalidates the
  signature in any compliant PDF viewer. With no certificate configured, the server
  auto-provisions a self-signed pair on first boot (into the gitignored data directory)
  so a zero-config install still produces a real, verifiable certification signature; it
  simply will not chain to a public trust store until you install a CA-issued cert.
- **AES-integrity fallback** (`pdf_cert.secure_pdf`) — when signing material is
  unavailable, the document is still sealed tamper-evident.
- **Certificate of Completion** (`pdf_cert.make_certificate`) — every completed envelope
  ships with the ESIGN/UETA audit trail: signer identities, timestamps, IP addresses, and
  consent records.

**Signing-key hygiene (non-negotiable):** the private key is never written under the git
worktree. Callers pass PEM material loaded at runtime from the environment
(`SIGN_PADES_KEY_PEM`) or a gitignored path outside the repo (`SIGN_PADES_KEY_PATH`), and
the provisioning path refuses to write under the repository root. A leaked signing key
forges unlimited certifications — treat it accordingly.

## Content-Security-Policy and dependency posture

Every page and API response carries a strict CSP (`http_helpers.STRICT_CSP`):
`default-src 'self'`, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`,
`form-action 'self'`. There is **no CDN and no external font/script host** — the design
system, PDF.js, and fonts are all vendored and first-party. `worker-src blob:` and
`img-src data:` are the only relaxations, required by the vendored PDF.js worker and by
rendered page / adopted-signature data URIs. Responses also set `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`
(`_apply_security_headers`).

## Audit-trail integrity

The client IP recorded in the legal audit trail is the socket peer by default.
`X-Forwarded-For` is attacker-controllable, so it is honored **only** when the direct
connection originates from a proxy listed in `SIGN_TRUSTED_PROXIES`, taking the right-most
hop that is not itself a trusted proxy (`http_helpers._client_ip`). With no proxy
configured, the header is ignored entirely, so a client cannot forge its recorded IP.

## Secrets never logged

Raw challenge values, normalized inputs, SSNs, dates of birth, and OTP codes are never
stored, returned, or logged. Audit events record the challenge **type only**. Exception
handlers on the secret-handling paths are catch-and-generic so a raw value can never
escape through an error message.

---

*Threat model maintained alongside the code by Daniel Wilson Kemp. If you find a gap
between this document and the implementation, that gap is itself a bug — please report
it.*
