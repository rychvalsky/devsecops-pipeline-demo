"""API-key authentication.

NOTE: this module deliberately contains two planted weaknesses so the security
pipeline has something real to catch. Both are fixed in phase F9:

  1. The key is hard-coded in source instead of read from the environment
     -> flagged by Bandit in the SAST stage (B105 "hardcoded password string").
  2. The comparison is a plain `!=`, not constant-time
     -> called out in the code-review notes; F9 switches to hmac.compare_digest.
"""

from fastapi import Header, HTTPException, status

# DEMO WEAKNESS (fixed in F9): secret committed to the repo instead of read from
# the environment. Named with "secret" so Bandit's B105 recognises it.
SECRET_API_KEY = "super-secret-demo-key-please-change"


def require_api_key(x_api_key: str = Header(default="")) -> None:
    """Reject the request unless the X-API-Key header matches."""
    # DEMO WEAKNESS (fixed in F9): non-constant-time string comparison.
    if x_api_key != SECRET_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
        )
