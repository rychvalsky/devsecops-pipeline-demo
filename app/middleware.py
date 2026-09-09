"""HTTP middleware adding baseline security response headers.

Added in F9 to clear the OWASP ZAP baseline warnings (missing
``X-Content-Type-Options`` / ``Cross-Origin-Resource-Policy`` and freely
cacheable responses).
"""

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Swagger UI (/docs) loads its assets from jsdelivr and runs a small inline
# bootstrap, so script-/style-src have to allow that much for the docs to work.
_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
    "Content-Security-Policy": _CONTENT_SECURITY_POLICY,
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach the headers above to every response, without overriding a
    header a route already set for itself."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response
