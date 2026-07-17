"""Lifted Sign — a self-hostable, ESIGN/UETA-compliant e-signature server.

A single package that runs three ways off one codebase:

* **Self-host** (the default) — SQLite, console/SMTP email, and passwordless email
  magic-link sign-in. One command, zero external services.
* **Hosted** — Postgres, transactional email, Google + phone sign-in, and a
  paid tier gated by the billing seam. The same code, driven by environment.
* **Embedded** — mounted as a sub-application inside a larger host, which
  injects its own database, mailer, and auth through the adapter seams.

The public HTTP surface, the signing engine, and the PDF stack are identical in
all three; only the injected adapters differ.
"""

__version__ = "0.1.0"
