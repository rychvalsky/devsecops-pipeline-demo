"""CRUD behaviour of the /notes endpoints (all already assumed authenticated)."""

from fastapi.testclient import TestClient


def test_create_returns_201_and_the_stored_note(client: TestClient, auth: dict[str, str]) -> None:
    response = client.post("/notes", headers=auth, json={"title": "shopping", "body": "milk, eggs"})
    assert response.status_code == 201
    data = response.json()
    assert data["id"] == 1
    assert data["title"] == "shopping"
    assert data["body"] == "milk, eggs"
    assert "created_at" in data


def test_body_defaults_to_empty_string(client: TestClient, auth: dict[str, str]) -> None:
    response = client.post("/notes", headers=auth, json={"title": "title only"})
    assert response.status_code == 201
    assert response.json()["body"] == ""


def test_empty_title_is_rejected(client: TestClient, auth: dict[str, str]) -> None:
    response = client.post("/notes", headers=auth, json={"title": "", "body": "x"})
    assert response.status_code == 422


def test_overlong_title_is_rejected(client: TestClient, auth: dict[str, str]) -> None:
    response = client.post("/notes", headers=auth, json={"title": "a" * 201})
    assert response.status_code == 422


def test_list_is_empty_initially(client: TestClient, auth: dict[str, str]) -> None:
    response = client.get("/notes", headers=auth)
    assert response.status_code == 200
    assert response.json() == []


def test_list_returns_notes_in_id_order(client: TestClient, auth: dict[str, str]) -> None:
    for title in ("first", "second", "third"):
        client.post("/notes", headers=auth, json={"title": title})

    titles = [note["title"] for note in client.get("/notes", headers=auth).json()]
    assert titles == ["first", "second", "third"]


def test_get_single_note(client: TestClient, auth: dict[str, str]) -> None:
    created = client.post("/notes", headers=auth, json={"title": "one"}).json()
    response = client.get(f"/notes/{created['id']}", headers=auth)
    assert response.status_code == 200
    assert response.json() == created


def test_get_missing_note_is_404(client: TestClient, auth: dict[str, str]) -> None:
    response = client.get("/notes/999", headers=auth)
    assert response.status_code == 404
    assert response.json()["detail"] == "Note not found"


def test_delete_removes_the_note(client: TestClient, auth: dict[str, str]) -> None:
    created = client.post("/notes", headers=auth, json={"title": "temp"}).json()

    assert client.delete(f"/notes/{created['id']}", headers=auth).status_code == 204
    assert client.get(f"/notes/{created['id']}", headers=auth).status_code == 404


def test_delete_missing_note_is_404(client: TestClient, auth: dict[str, str]) -> None:
    assert client.delete("/notes/999", headers=auth).status_code == 404
