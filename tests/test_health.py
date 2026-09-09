"""The /health endpoint: always open, always cheap."""

from fastapi.testclient import TestClient


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_needs_no_api_key(client: TestClient) -> None:
    # No X-API-Key header at all -> still fine.
    assert client.get("/health").status_code == 200
