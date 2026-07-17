# Contributing to Lifted Sign

Thanks for your interest in improving Lifted Sign! Contributions of all kinds are
welcome — bug reports, documentation, tests, and code.

## Ground rules

- By contributing, you agree that your contributions are licensed under the project's
  [AGPL-3.0](./LICENSE) (or MIT for anything under `sdks/`).
- Be respectful. This project follows the [Code of Conduct](./CODE_OF_CONDUCT.md).
- **Never commit secrets** — API keys, certificates, private keys, `.env` files,
  or real customer data. The `.gitignore` already excludes the common offenders;
  double-check your diff before pushing.
- **Never hardcode identity.** Hosted-service addresses, company names, and email
  addresses are configuration, not code. Every such value must come from an env var
  with a blank default.

## Development setup

```bash
git clone https://github.com/Lifted-Holdings/lifted-sign.git
cd lifted-sign
python -m venv .venv && . .venv/bin/activate    # or .venv\Scripts\activate on Windows
pip install -e '.[dev]'

cp .env.example .env
python -c "import secrets; print('SIGN_SECRET=' + secrets.token_urlsafe(48))"  # add to .env

python -m sign      # http://localhost:8080
```

## Before you open a PR

Run the same checks CI runs:

```bash
ruff check .
ruff format --check .
pytest
```

- Keep PRs focused — one logical change per pull request.
- Add or update tests for behavior changes.
- Update the docs and `CHANGELOG.md` in the same PR when your change is user-facing.
- Write a clear PR description: what changed, why, and how you verified it.

## Reporting bugs

Open an issue with steps to reproduce, what you expected, and what actually happened.
Include your Python version and whether you're on SQLite or Postgres.

## Security issues

**Do not** open a public issue for security vulnerabilities. See
[SECURITY.md](./SECURITY.md) for responsible-disclosure instructions.
