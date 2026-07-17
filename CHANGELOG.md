# Changelog

All notable changes to Lifted Sign are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-16

Initial public release.

### Added

- Self-hostable e-signature server: upload a PDF, add signers, place fields by anchor
  (or absolute/normalized coordinates), and send single-use signing links.
- ESIGN/UETA-aligned signing flow with a consent disclosure gate and a Certificate of
  Completion (signer identities, timestamps, IP addresses, and consent records).
- Real PAdES/PKCS#7 certification sealing of completed PDFs, with a tamper-evident
  AES-integrity fallback when no signing certificate is configured.
- SQLite as the zero-config default datastore; optional Postgres via `DATABASE_URL`.
- Environment-driven configuration with a documented [`.env.example`](./.env.example)
  and a hard fail-closed check on a missing or weak `SIGN_SECRET`.
- Console email in development; SMTP delivery for invites, reminders, and OTPs.
- Optional Google OAuth and Twilio Verify (phone OTP + SMS 2FA) sign-in add-ons.
- Developer REST API under `/api/mysign/*`, an in-app `/developers` reference, and an
  OpenAPI spec.
- Vendored, dependency-free client SDKs under [`sdks/`](./sdks/) — Python
  (`lifted_sign.py`) and Node (`lifted-sign.mjs`), MIT-licensed.
- Docker and Docker Compose deployment, plus a
  [self-hosting guide](./docs/self-hosting.md).

[0.1.0]: https://github.com/Lifted-Holdings/lifted-sign/releases/tag/v0.1.0
