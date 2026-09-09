"""The X-API-Key gate on every /notes endpoint."""

import pytest
from fastapi.testclient import TestClient

PROTECTED_REQUESTS = [
    ("get", "/notes"),
    ("post", "/notes"),
    ("get", "/notes/1"),
    ("delete", "/notes/1"),
]


@pytest.mark.parametrize(("method", "path"), PROTECTED_REQUESTS)
def test_missing_api_key_is_rejected(client: TestClient, method: str, path: str) -> None:
    response = client.request(method, path)
    assert response.status_code == 401


@pytest.mark.parametrize(("method", "path"), PROTECTED_REQUESTS)
def test_wrong_api_key_is_rejected(client: TestClient, method: str, path: str) -> None:
    response = client.request(method, path, headers={"X-API-Key": "not-the-key"})
    assert response.status_code == 401


def test_correct_api_key_is_accepted(client: TestClient, auth: dict[str, str]) -> None:
    assert client.get("/notes", headers=auth).status_code == 200
