"""The open, unauthenticated endpoints: / and /health."""

from fastapi.testclient import TestClient


def test_root_lists_entry_points(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "Notes API"
    assert body["docs"] == "/docs"
    assert body["health"] == "/health"


def test_root_needs_no_api_key(client: TestClient) -> None:
    assert client.get("/").status_code == 200


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_needs_no_api_key(client: TestClient) -> None:
    # No X-API-Key header at all -> still fine.
    assert client.get("/health").status_code == 200
