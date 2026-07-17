"""``python -m sign`` — the uvicorn entrypoint.

Boots the Lifted Sign ASGI app on the configured host/port. Config (SIGN_SECRET, PUBLIC_BASE_URL,
PORT, DATABASE_URL, …) is read from the environment via :mod:`sign.config`, which fails hard if
SIGN_SECRET is missing or weak — so a misconfigured boot is loud, never silently insecure.
"""

from __future__ import annotations

import os

from . import config


def main() -> None:
    import uvicorn

    # Bind 127.0.0.1 by default (put a TLS-terminating reverse proxy in front); override with
    # SIGN_BIND_HOST=0.0.0.0 for containerized deployments that terminate TLS at the edge.
    host = os.environ.get("SIGN_BIND_HOST", "127.0.0.1").strip() or "127.0.0.1"
    uvicorn.run("sign.app:app", host=host, port=config.PORT, reload=False)


if __name__ == "__main__":
    main()
