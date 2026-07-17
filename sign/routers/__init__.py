"""HTTP route modules for the Lifted Sign server.

Each module exposes a FastAPI ``router`` (an ``APIRouter``) that :mod:`sign.app` mounts:

* :mod:`sign.routers.mysign`     — ``/api/mysign/*`` tenant product API (envelopes, templates,
  API keys, account).
* :mod:`sign.routers.portal`     — ``/api/sign-portal/auth/*`` Google + phone-OTP signup/login.
* :mod:`sign.routers.signer`     — ``/sign/*`` public signer page + ``/api/sign/token/*`` actions.
* :mod:`sign.routers.envelope`   — ``/api/envelope/*`` proven-identity signer-session API.
* :mod:`sign.routers.developers` — ``/developers`` public API docs + OpenAPI spec.
* :mod:`sign.routers.ops`        — ``/api/sign-ops/*`` operator console (gated by ADMIN_EMAILS).
"""
