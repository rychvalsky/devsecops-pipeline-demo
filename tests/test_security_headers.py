"""The SecurityHeadersMiddleware should cover every response, errors included."""

from fastapi.testclient import TestClient

from app.middleware import SECURITY_HEADERS


def test_headers_present_on_a_normal_response(client: TestClient) -> None:
    response = client.get("/health")
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value


def test_headers_present_on_an_error_response(client: TestClient) -> None:
    response = client.get("/notes")  # 401, no API key
    assert response.status_code == 401
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"


def test_csp_allows_the_swagger_cdn(client: TestClient) -> None:
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "cdn.jsdelivr.net" in csp
    assert "frame-ancestors 'none'" in csp
