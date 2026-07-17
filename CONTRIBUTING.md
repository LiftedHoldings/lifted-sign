# Contributing to Lifted Sign

Thanks for your interest in improving Lifted Sign. Contributions of every kind are
welcome — bug reports, documentation, tests, and code. This guide covers how to get a
development environment running, the checks your change must pass, and the conventions
that keep the project clean and self-contained.

## Ground rules

- By contributing, you agree that your contributions are licensed under the project's
  [AGPL-3.0](./LICENSE) (or MIT for anything under `sdks/`).
- Be respectful. This project follows the [Code of Conduct](./CODE_OF_CONDUCT.md).
- **Never commit secrets** — API keys, certificates, private keys, `.env` files, or real
  customer data. `.gitignore` already excludes the common offenders; re-read your diff
  before you push.
- **Never hardcode identity.** Hosted-service addresses, company names, email addresses,
  and domains are *configuration, not code*. Every such value reads from an env var with
  a blank (or neutral) default — see `sign/config.py`.
- **No host coupling.** Lifted Sign is a standalone package. Do not add a dependency on
  any external services or private infrastructure (secret vaults, mail-provider
  SDKs beyond the ones already vendored, telemetry sinks, activity feeds). Everything a
  self-hoster runs must be in this repository and configurable from the environment.

## Development setup

Requires Python 3.11 or 3.12.

```bash
git clone https://github.com/Lifted-Holdings/lifted-sign.git
cd lifted-sign

python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate

pip install -e '.[dev]'         # editable install + ruff & pytest
```

Set the one required secret. The server **refuses to boot** without a real
`SIGN_SECRET` (it keys every session, signer-access token, OTP, and the at-rest
encryption key):

```bash
cp .env.example .env
python -c "import secrets; print('SIGN_SECRET=' + secrets.token_urlsafe(48))" >> .env
```

Run it:

```bash
python -m sign                  # serves http://localhost:8080
```

With nothing but `SIGN_SECRET` set you get SQLite storage, console email (login links
print to the terminal), and passwordless magic-link sign-in — enough to develop the
whole product locally. SMTP, Postgres, Google/phone sign-in, and PAdES certificates are
optional add-ons documented in [`.env.example`](./.env.example) and
[`docs/self-hosting.md`](./docs/self-hosting.md).

## Running the checks

Your change must pass the same checks CI runs (`.github/workflows/ci.yml`):

```bash
ruff check .                    # lint
ruff format --check .           # formatting (drop --check to auto-format)
pytest                          # test suite
```

`pytest` needs a secret set even for tests, because config fails closed at import:

```bash
SIGN_SECRET=dev-only-not-a-real-secret-0123456789 pytest -q
```

Run all three before opening a pull request. If `ruff format --check` fails, run
`ruff format .` to fix it.

## Project layout

```
sign/                    The application package
  __main__.py            `python -m sign` entrypoint (uvicorn)
  app.py                 FastAPI app, middleware, page shells, router mounting
  config.py              All configuration, read from the environment
  db.py                  SQLite-first persistence (optional Postgres); ensure_tables()
  webauth.py             HMAC token signing + TOTP + Twilio Verify primitives
  http_helpers.py        Request-scoped auth/authorization/hardening choke-points
  esign.py               Envelope / signer / field / event model and persistence
  esign_access.py        Signer access control: challenges, OTP, envelope sessions
  esign_disclosure.py    ESIGN/UETA consent copy
  sign_accounts.py       Sender-account records
  sign_portal_auth.py    Sender-account auth (sessions, magic link, 2FA, OAuth)
  sign_api_keys.py       Developer API keys (Bearer)
  crypto.py              Fernet at-rest encryption, keyed off SIGN_SECRET
  mailer.py, integrations.py   Email rendering + delivery
  pdf_*.py               PDF engine: edit, stamp, render, redact, seal, certificate, PAdES
  routers/               FastAPI routers (mysign, envelope, signer, portal, developers, ops)
  assets/                Vendored server-side assets
web/                     SPA shells, signer page, vendored design system + PDF.js
sdks/                    MIT-licensed client SDKs (Python + Node)
docs/                    Self-hosting + hosted-terms docs
tests/                   pytest suite
```

Persistence tables are owned by their module: `db.py` owns the shared infra tables
(`settings`, `auth_limits`, `auth_rate_limits`); `sign_accounts`, `sign_api_keys`, and
`esign` each own their own tables. Every module with tables provides an `ensure_tables()`
that self-runs at import, and schema changes are **additive** via `db._columns` — never
raw `PRAGMA` (it passes the SQLite suite but crashes Postgres at boot). Use `?`
placeholders; `RETURNING` / `ON CONFLICT` are fine.

## Coding standards

- **Type hints** on function signatures. The codebase uses
  `from __future__ import annotations` throughout — match it.
- **Docstrings** that explain intent, not mechanics. Security-relevant modules
  (`esign_access.py`, `http_helpers.py`, `webauth.py`, `sign_portal_auth.py`) open with a
  threat-model comment — when you touch the behavior, keep that comment true.
- **Ruff-clean**, line length 100 (configured in `pyproject.toml`). Let the formatter own
  layout; don't fight it.
- **Auth flows through the choke-points.** Authenticate `/api/mysign/*` with
  `_require_sign_acct`, authorize with `_require_owned` (which returns 404, not 403, for
  cross-owner access), and gate account-security routes with `_require_sign_cookie`
  (cookie only, never Bearer). Don't re-implement these inline.
- **Fail closed.** When a security decision is ambiguous, deny. Never add a try/except,
  fallback, retry, or default that silences an error you can't explain — find the root
  cause. Never store, return, or log a raw secret (challenge value, SSN, DOB, OTP code).
- **The smallest diff that fully solves the problem.** Search for an existing helper
  before adding one, and match the local idiom of the file you're editing.

## Commit and pull-request conventions

- Keep pull requests focused — one logical change each.
- Write commit messages in the imperative mood with a concise subject line
  (e.g. `Fix envelope-session epoch check on void`), and a body explaining *why* when the
  change isn't self-evident.
- Add or update tests for any behavior change; a bug fix should come with a regression
  test that fails before the fix.
- Update the docs and [`CHANGELOG.md`](./CHANGELOG.md) in the **same** pull request when
  your change is user-facing.
- In the PR description, state what changed, why, and **how you verified it** — the
  commands you ran and what you observed, not "should work."
- CI (ruff + pytest on Python 3.11 and 3.12) must be green before merge.

## Reporting bugs and requesting features

Open an issue using the templates under
[`.github/ISSUE_TEMPLATE`](./.github/ISSUE_TEMPLATE). For a bug, include steps to
reproduce, expected vs. actual behavior, your Python version, and whether you're on
SQLite or Postgres.

## Security issues

**Do not** open a public issue for a security vulnerability. Follow the
responsible-disclosure process in [SECURITY.md](./SECURITY.md).

## Licensing of contributions (CLA / AGPL note)

Lifted Sign is licensed under the **GNU Affero General Public License v3.0**; the client
SDKs under `sdks/` are **MIT**. By submitting a contribution you certify that you wrote
it (or have the right to submit it) and that you license it to the project under the
license of the file you're changing — AGPL-3.0 for the server, MIT for `sdks/`. This is
the same lightweight assurance as the [Developer Certificate of Origin](https://developercertificate.org/);
there is no separate CLA to sign. Because the project is AGPL, anyone who runs a modified
version as a network service must offer their users the corresponding source — keep that
in mind when building on top of it.
