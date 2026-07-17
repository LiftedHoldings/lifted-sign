# Security Policy

Lifted Sign handles legally binding documents and signer identity data, so security
reports are taken seriously. Thank you for helping keep the project and its users safe.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Instead, email a detailed report to:

> **security@example.com**

*(Self-hosters: replace this placeholder with the address that reaches your team, and
set `SUPPORT_EMAIL` in your environment for user-facing contact.)*

Please include as much of the following as you can:

- A description of the vulnerability and its impact.
- Steps to reproduce, or a proof-of-concept.
- Affected version(s) and configuration (SQLite vs Postgres, hosted vs self-host).
- Any suggested remediation.

## What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity classification within 10 business days.
- Regular updates as we work on a fix.
- Public credit for the disclosure, if you'd like it, once a fix has shipped.

Please give us a reasonable window to release a fix before any public disclosure. We
will coordinate a disclosure timeline with you.

## Supported versions

Security fixes are provided for the latest released version. Self-hosters should stay
current with releases to receive them.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Scope

In scope: the Lifted Sign server (this repository) and the vendored SDKs under
`sdks/`. Out of scope: vulnerabilities in third-party dependencies (report those
upstream) and issues that require a pre-compromised host or physical access.
