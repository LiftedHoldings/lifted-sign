# Self-hosting Lifted Sign

This guide covers running Lifted Sign in production: configuring the environment,
sending real email, switching to Postgres, installing a PAdES signing certificate, and
putting the server behind nginx with TLS.

Everything is configured through environment variables — a `.env` file, real env vars,
or your orchestrator's secret store. There is no config file to edit and no dependency
on any external service beyond what you explicitly turn on.

---

## 1. Environment reference

Copy the template and fill it in:

```bash
cp .env.example .env
```

### Required

| Variable | Purpose |
|----------|---------|
| `SIGN_SECRET` | Keys every login session, signer-access cookie, and one-time code. The server **refuses to boot** if it is missing, shorter than 16 chars, or a known placeholder. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. |

### Core

| Variable | Default | Purpose |
|----------|---------|---------|
| `PUBLIC_BASE_URL` | `http://localhost:8080` | External URL of this install. Builds signer links + email content **and** fills the marketing landing's canonical/OpenGraph/Twitter URLs and hero mockup — set it to your real HTTPS URL in production. Session cookies use the `__Host-` prefix, which browsers accept only over HTTPS (localhost is exempt), so a non-localhost plain-`http` host cannot hold a login session — terminate TLS in front (see [§5](#5-behind-nginx-with-tls)). |
| `PORT` | `8080` | HTTP port the server listens on. |
| `SIGN_DATA_DIR` | `./data` | Directory for the SQLite database and sealed PDFs. Created on boot. Put this on a persistent volume. |
| `DATABASE_URL` | *(blank ⇒ SQLite)* | Optional Postgres DSN. See [§3](#3-switching-to-postgres). |
| `SIGN_TRUSTED_PROXIES` | *(blank)* | Comma-separated IPs of your reverse proxy. **Required for a correct audit trail behind a proxy:** signer IPs on the Certificate of Completion come from `X-Forwarded-For` only when the direct peer is a trusted proxy — otherwise the app records the proxy's own IP. Set this to your nginx/load-balancer IP. |

### Email

| Variable | Default | Purpose |
|----------|---------|---------|
| `SMTP_HOST` | *(blank)* | SMTP server. **With this blank, email is printed to the console** — fine for local dev, never for production. |
| `SMTP_PORT` | — | SMTP port (commonly `587` for STARTTLS). |
| `SMTP_USER` | — | SMTP username. |
| `SMTP_PASSWORD` | — | SMTP password. |
| `SMTP_STARTTLS` | — | `true` to negotiate STARTTLS. |
| `MAIL_FROM` | *(blank)* | From-address for invites, reminders, and OTPs. |
| `MAIL_FROM_NAME` | `Lifted Sign` | Display name on outgoing email. |
| `MAIL_REPLY_TO` | — | Optional Reply-To address. |

### Legal identity

These appear in disclosures, the Certificate of Completion, and email footers. All
blank by default — fill in **your own** entity, never someone else's.

| Variable | Purpose |
|----------|---------|
| `LEGAL_ENTITY` | Your legal company/entity name. |
| `LEGAL_ADDRESS` | Your business address. |
| `SUPPORT_EMAIL` | User-facing support/contact address. |

### PAdES signing material (optional)

See [§4](#4-pades-signing-certificate).

| Variable | Purpose |
|----------|---------|
| `SIGN_PADES_CERT_PATH` / `SIGN_PADES_CERT_PEM` | Signing certificate (path or inline PEM). |
| `SIGN_PADES_KEY_PATH` / `SIGN_PADES_KEY_PEM` | Private key (path or inline PEM). |
| `SIGN_PADES_KEY_PASSPHRASE` | Passphrase for the private key, if it is encrypted. |

### Public-page identity

Shown on the marketing landing (head metadata, footer, the "your-domain" hero pill). Both
have sensible defaults so a fresh build never ships a placeholder.

| Variable | Default | Purpose |
|----------|---------|---------|
| `OPERATOR_NAME` | `LEGAL_ENTITY` → `MAIL_FROM_NAME` (`Lifted Sign`) | Operator name in `<meta>`, footer, and copyright. |
| `OPERATOR_URL` | `PUBLIC_BASE_URL` | Operator website linked from the footer + structured-data publisher. |

### Sign-in methods

Passwordless **email magic-link** sign-in is always available and needs no configuration —
a self-hoster with only `SIGN_SECRET` set can create an account and log in (with SMTP unset,
the link prints to the server console). Google and phone below are **optional** extra methods;
the sign-in page shows only the methods that are actually configured.

| Variable | Purpose |
|----------|---------|
| `GOOGLE_OAUTH_CLIENT_ID` / `_SECRET` / `_REDIRECT` | Enable Google login (optional). |
| `TWILIO_ACCOUNT_SID` / `_AUTH_TOKEN` / `_VERIFY_SERVICE_SID` | Enable phone OTP + SMS 2FA (Twilio Verify, optional). |

Any add-on whose variables are unset is simply disabled.

### Deployment mode

| Variable | Default | Purpose |
|----------|---------|---------|
| `SIGN_SIGNUPS_OPEN` | `true` | Whether new accounts may self-register. Set `false` for a private install. |
| `ADMIN_EMAILS` | *(blank)* | Comma-separated emails allowed to reach the operator console. |
| `SIGN_HOSTED_MODE` | `false` | Enables the hosted-tier billing seam (Stripe). Leave `false` for self-hosting. |

---

## 2. SMTP setup

By default (no `SMTP_HOST`), Lifted Sign prints every email to the server console so you
can develop without a mail provider. For a real deployment, configure SMTP so signers
actually receive their links:

```env
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_USER=your-smtp-username
SMTP_PASSWORD=your-smtp-password
SMTP_STARTTLS=true
MAIL_FROM=sign@yourdomain.com
MAIL_FROM_NAME=Your Company Signing
```

Use a provider that lets you authenticate your sending domain (SPF/DKIM/DMARC) — signing
invites are transactional email and land in spam without proper domain authentication.
Send yourself a test envelope after configuring, and confirm the link resolves against
your `PUBLIC_BASE_URL`.

---

## 3. Switching to Postgres

SQLite is the zero-config default and is perfectly fine for small and single-node
installs. For higher concurrency or managed backups, switch to Postgres:

1. Install the Postgres extra:

   ```bash
   pip install '.[postgres]'
   ```

2. Set the DSN in your `.env`:

   ```env
   DATABASE_URL=postgresql://user:password@host:5432/liftedsign
   ```

3. Restart. The schema is created on boot.

### With Docker Compose

The bundled [`docker-compose.yml`](../docker-compose.yml) ships a commented-out
`postgres` service. Uncomment it (and the `depends_on` / `volumes` blocks), then set:

```env
DATABASE_URL=postgresql://sign:sign@postgres:5432/liftedsign
```

> There is no automatic data migration from SQLite to Postgres. Choose your backend
> before you take real signatures, or export/re-import deliberately.

### Running from the published image

CI builds a multi-arch (`linux/amd64` + `linux/arm64`) image and pushes it to the GitHub
Container Registry on every push to `main` (tagged `:latest`) and on each tagged release
(`:vX.Y.Z`, `:X.Y`, `:X`). Pull and run it directly — no clone, no build:

```bash
docker run --rm \
  -e SIGN_SECRET=$(openssl rand -base64 48) \
  -p 8080:8080 \
  ghcr.io/liftedholdings/lifted-sign
```

> **After the first CI publish, make the package Public.** GHCR packages default to
> private, so anonymous `docker pull` fails with `denied`/`not found` until you flip it.
> In the repository on GitHub open **Packages → `lifted-sign` → Package settings →
> Change visibility → Public**. This is a one-time step per package.

For a persistent database and sealed PDFs, mount a volume onto `SIGN_DATA_DIR`
(`-v lifted-sign-data:/app/data`) and set the production env vars from
[§1](#1-environment-reference) rather than relying on the ephemeral defaults.

---

## 4. PAdES signing certificate

Without a certificate, Lifted Sign still seals completed PDFs with a self-signed /
AES-integrity seal — documents remain tamper-evident, but a self-signed certificate will
not chain to Adobe's Approved Trust List, so Acrobat shows "signature validity unknown."

To seal with a certificate that validates in standard PDF readers, obtain a document-
signing certificate (from a CA whose roots are in the AATL, or your own internal CA for
internal use) as a PEM certificate + private key, then point the server at them:

```env
SIGN_PADES_CERT_PATH=./secrets/signing-cert.pem
SIGN_PADES_KEY_PATH=./secrets/signing-key.pem
SIGN_PADES_KEY_PASSPHRASE=your-key-passphrase   # if the key is encrypted
```

Alternatively provide the material inline with `SIGN_PADES_CERT_PEM` /
`SIGN_PADES_KEY_PEM` (useful with a secret store that injects env vars).

Keep these files out of version control. The default `.gitignore` already excludes
`secrets/`, `*.pem`, `*.key`, `*.p12`, and `*.pfx` — mount them at runtime rather than
baking them into an image.

---

## 5. Behind nginx with TLS

Run Lifted Sign on `127.0.0.1:8080` and terminate TLS at nginx. Set
`PUBLIC_BASE_URL=https://sign.yourdomain.com` so links and email use the public HTTPS
URL.

```nginx
server {
    listen 443 ssl;
    server_name sign.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/sign.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sign.yourdomain.com/privkey.pem;

    # PDFs can be several MB; allow generous uploads.
    client_max_body_size 25m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name sign.yourdomain.com;
    return 301 https://$host$request_uri;
}
```

Obtain and auto-renew the certificate with certbot:

```bash
certbot --nginx -d sign.yourdomain.com
```

The `X-Forwarded-For` / `X-Forwarded-Proto` headers matter: signer IP addresses are
recorded on the Certificate of Completion, so the app needs the real client IP and the
correct scheme from your proxy. **`X-Forwarded-For` is only trusted when the direct peer
is listed in `SIGN_TRUSTED_PROXIES`** — set it to your nginx/proxy IP, or the audit trail
will record the proxy's address instead of the signer's.

### Evaluating over plain HTTP (no TLS yet)

Session cookies use the `__Host-` prefix, which browsers accept only over HTTPS (`localhost`
is exempt). So on a plain-`http://` LAN IP — e.g. kicking the tyres at
`http://192.168.1.50:8080` — the login cookie is silently dropped and sign-in appears to do
nothing. For that **trusted-network / development** case only, set:

```bash
SIGN_INSECURE_COOKIES=true
```

This drops the `__Host-` prefix and the `Secure` attribute so cookies work over HTTP. It
disables secure-transport protection, so **never** use it in production — put the app behind
TLS (above) instead. It exists purely so a first-run evaluation on a LAN isn't blocked by a
cookie you can't see.

---

## 6. Checklist before taking real signatures

- [ ] `SIGN_SECRET` set to a long random value (not a placeholder).
- [ ] `PUBLIC_BASE_URL` is your real HTTPS URL.
- [ ] SMTP configured and a test invite received (also makes magic-link sign-in deliver by email instead of the console).
- [ ] `SIGN_DATA_DIR` (or Postgres) is on persistent, backed-up storage.
- [ ] `LEGAL_ENTITY`, `LEGAL_ADDRESS`, `SUPPORT_EMAIL` filled in with your own details.
- [ ] `OPERATOR_NAME` / `OPERATOR_URL` set (or left to their defaults) — no `example.com` on your public pages.
- [ ] TLS terminating in front of the app; forwarded-IP headers passed through, `SIGN_TRUSTED_PROXIES` set to your proxy IP.
- [ ] PAdES certificate installed if you need reader-validated (certified) signatures.
