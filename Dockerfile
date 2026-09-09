# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: build a virtualenv with the runtime dependencies.
# Kept separate so the final image doesn't carry pip's build cache or wheels.
# ---------------------------------------------------------------------------
# Base image is pinned (Python minor + Debian release) so the build is
# reproducible -- an unpinned `latest` recently jumped to Python 3.14 and broke
# a dependency. Pin now; revisit deliberately.
FROM python:3.13-slim-bookworm AS builder

WORKDIR /app

# Install into a self-contained venv we can copy wholesale into the next stage.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: the runtime image -- just Python, the venv, and our app code.
# ---------------------------------------------------------------------------
FROM python:3.13-slim-bookworm

WORKDIR /app

# Bring in the ready-made virtualenv from the builder stage.
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Application code (see .dockerignore for what stays out).
COPY app ./app

# DEMO WEAKNESS (fixed in F9): no `USER` instruction, so the container runs as
# root. Trivy's config scan (F6) flags this as DS002 "Image user should not be
# root". F9 adds a dedicated unprivileged user.

EXPOSE 8000

# Uses only the Python stdlib -- the slim base image has no curl.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# 0.0.0.0 is correct inside a container: the port is only reachable via the
# ports Docker explicitly publishes.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
