"""API-key authentication.

The key is read from the ``API_KEY`` environment variable. A non-secret
fallback keeps local development and the test suite working out of the box;
real deployments set ``API_KEY`` (see ``.env.example``).

The header is compared with :func:`hmac.compare_digest` so a wrong key cannot
be recovered by measuring response time.
"""

import hmac
import os

from fastapi import Header, HTTPException, status

# Safe to commit: this is a placeholder, not a real credential. Deployments
# override it via the environment.
API_KEY = os.environ.get("API_KEY", "local-dev-key-change-me")


def require_api_key(x_api_key: str = Header(default="")) -> None:
    """Reject the request unless the X-API-Key header matches (constant-time)."""
    if not hmac.compare_digest(x_api_key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
        )
