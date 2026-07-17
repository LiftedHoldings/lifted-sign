# syntax=docker/dockerfile:1

FROM python:3.12-slim

# Fail fast on errors, never buffer stdout/stderr so logs stream in real time,
# and never write .pyc files into the image layer.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# curl is required by the container HEALTHCHECK probe below; python:3.12-slim ships without it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install the package. Copy metadata first would let us cache deps, but pyproject
# reads the version from the package, so we copy the source and install in one step.
COPY . /app
RUN pip install --no-cache-dir .

# Run as an unprivileged user; give it ownership of the writable data directory.
RUN useradd --create-home --uid 10001 sign \
    && mkdir -p /app/data \
    && chown -R sign:sign /app/data
USER sign

# SQLite database and sealed PDFs live here by default (override with SIGN_DATA_DIR).
ENV SIGN_DATA_DIR=/app/data

EXPOSE 8080

# Liveness probe: /healthz never touches the DB, so a DB blip can't restart-storm the fleet
# (readiness /readyz pulls an instance from LB rotation instead). Use liveness for the container.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

CMD ["python", "-m", "sign"]
