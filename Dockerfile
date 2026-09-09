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

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Current pip/setuptools for the build itself.
RUN pip install --no-cache-dir --upgrade pip setuptools

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: the runtime image -- just Python, the venv, and our app code.
# ---------------------------------------------------------------------------
FROM python:3.13-slim-bookworm

# Dedicated unprivileged account -- the container must not run as root
# (Trivy config DS-0002).
RUN useradd --create-home --uid 10001 appuser

WORKDIR /app

# Bring in the ready-made virtualenv from the builder stage.
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Harden: the runtime image never needs pip (the venv is already built).
# Dropping pip also removes its *vendored* copies of setuptools and msgpack,
# which image scanners report even though they are not importable packages.
RUN rm -rf \
      /usr/local/lib/python3.13/site-packages/pip* \
      /usr/local/lib/python3.13/site-packages/setuptools* \
      /usr/local/lib/python3.13/site-packages/pkg_resources \
      /usr/local/lib/python3.13/site-packages/_distutils_hack \
      /usr/local/bin/pip* \
      /opt/venv/lib/python3.13/site-packages/pip* \
      /opt/venv/bin/pip*

# Application code (see .dockerignore for what stays out).
COPY app ./app

USER appuser

# Keep the SQLite file in the user's home; /app stays read-only to the app.
ENV DATABASE_URL="sqlite:////home/appuser/notes.db"

EXPOSE 8000

# Uses only the Python stdlib -- the slim base image has no curl.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# 0.0.0.0 is correct inside a container: the port is only reachable via the
# ports Docker explicitly publishes.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
