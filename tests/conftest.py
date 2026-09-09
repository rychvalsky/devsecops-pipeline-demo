"""Shared pytest fixtures.

Each test runs against its own throwaway in-memory SQLite database, so tests
never touch the real ``notes.db`` and never interfere with one another.

The trick with in-memory SQLite is that a normal connection pool would give
every checkout a *fresh* (empty) database. ``StaticPool`` forces a single shared
connection, so the schema created in the fixture is visible to every request.
"""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from app.auth import SECRET_API_KEY
from app.db import get_session
from app.main import app


@pytest.fixture(name="session")
def session_fixture() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session) -> Iterator[TestClient]:
    """A TestClient whose requests use the test session instead of the real DB."""

    def get_session_override() -> Session:
        return session

    app.dependency_overrides[get_session] = get_session_override
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture(name="auth")
def auth_fixture() -> dict[str, str]:
    """Headers that satisfy the X-API-Key check."""
    return {"X-API-Key": SECRET_API_KEY}
