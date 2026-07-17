# Embedding Lifted Sign in a host application

Lifted Sign runs three ways off **one codebase** (see [ARCHITECTURE.md](./ARCHITECTURE.md)):
self-host, managed cloud, and **embedded inside a larger host application**. This document is the
plan for the third — specifically for consuming Lifted Sign as the single source of truth for
e-signature inside another product (the "host") so a fix lands once here and the host picks it up.

> **Status.** The self-host and managed builds are complete and tested. The embedded/host path is
> designed here and the app is already import-mountable; the host-side adapter wiring and the
> production cutover are staged for review, not yet executed (see "Rollout" at the end).

## The two ways to consume it

### 1. Git submodule (recommended — one repo to work from)

Vendor this repo into the host at a fixed path and pin a commit:

```bash
# in the host repo
git submodule add <lifted-sign-repo-url> server/vendor/lifted_sign
git -C server/vendor/lifted_sign checkout <sha>
git commit -m "Vendor lifted-sign @ <sha>"
```

To pull a fix: `git -C server/vendor/lifted_sign pull` → pin the new sha → commit. The host always
builds against a known revision, and CI can gate on the submodule sha.

> The submodule URL is the only thing that needs to change when the canonical repo moves — until
> then it can point at a local path (`git submodule add /abs/path/to/lifted-sign …`) to prove the
> wiring end-to-end without a hosted remote.

### 2. Versioned package

`pip install lifted-sign==X.Y.Z` from a private index (or PyPI). Cleaner dependency boundary, but
every fix requires cutting a release — more ceremony than a submodule sha bump.

## Mounting the app

Lifted Sign exposes a self-contained ASGI app (`sign.app.app`). The simplest embed mounts it as a
sub-application so it owns its own routes, static assets, and lifespan:

```python
from server.vendor.lifted_sign.sign.app import app as sign_app

host_app.mount("/sign", sign_app)   # serves the whole Sign surface under /sign
```

This works today and is the fastest path to "the host serves Sign off the OSS code." Its limitation
is isolation: the sub-app uses **its own** SQLite/SMTP/local-auth config, not the host's database,
mailer, or identity. That is correct for a loosely-coupled embed; it is *not* what an estate that
wants Sign to share its Postgres, transactional email, and single sign-on needs. For that, use the
adapter seams below.

## Adapter seams (sharing the host's infrastructure)

Every external dependency Lifted Sign has is already funnelled through a small number of modules,
each reading from `sign.config`. Full host integration means letting the host **inject** its own
implementations at these seams instead of the env-driven defaults:

| Seam | Default (self-host) | Host injects |
| --- | --- | --- |
| **Database** — `sign.db` | SQLite at `SIGN_DATA_DIR`; optional PG via `DATABASE_URL` | the host's connection/pool so Sign tables live in the host DB (its own schema/namespace) |
| **Mailer** — `sign.mailer` | SMTP, console fallback | the host's transactional-email sender (same `send_html(to, subject, html, attachments=…)` contract) |
| **Auth / sessions** — `sign.sign_portal_auth`, `sign.http_helpers` | magic-link + `SIGN_SECRET` HMAC cookies | the host's session/identity — map a signed-in host user to a Sign account, skip the standalone sign-in UI |
| **Secrets** — `sign.config` | process env | the host's secret store (vault) resolved into the same config values |
| **Telemetry** (optional) | stdlib logging | the host's structured logging / event bus |

**Design principle:** the seams are already isolated by module, and `config` is the single place
values are resolved — so the refactor is *additive*: introduce an optional `Adapters` object (a
small protocol with `db`, `mailer`, `auth`, `secrets` fields) that, when provided at mount time,
overrides the env defaults; when absent, behaviour is exactly today's. This keeps the self-host and
managed builds byte-identical while letting a host supply its own infrastructure. No route, engine,
or PDF code changes — only the resolution of these five values.

The billing seam (`sign_accounts.can_send`) is already processor-free and flag-gated
(`SIGN_HOSTED_MODE`), so a host can wire its own entitlement check there without touching the
signing flow.

## Rollout (staged — requires review)

Replacing a host's existing, in-production e-signature with the consumed OSS code removes/replaces a
working, customer-facing feature. That is a deliberate checkpoint, done in order, not a big-bang:

1. **Add the submodule** at a pinned sha; mount `sign.app.app` under a path in a **non-production**
   environment and confirm the full golden path (create → place → send → sign → sealed PDF) works.
2. **Introduce the `Adapters` seam** (additive; default behaviour unchanged) with tests proving the
   self-host and managed builds are unaffected.
3. **Wire the host adapters** (its DB, mailer, SSO) behind a feature flag, running the consumed Sign
   **alongside** the existing one, and verify data parity + tenant isolation.
4. **Cut over** one environment at a time, with the old path still available to roll back, and only
   after a live verification on real infrastructure.
5. **Remove the host's duplicated Sign code** once the consumed path is proven in production.

Steps 1–2 are safe to do now. Steps 3–5 touch production and should be reviewed and sequenced
deliberately — the whole point of the submodule is that, once wired, every future fix is a one-line
sha bump, so there is no need to rush the cutover.
