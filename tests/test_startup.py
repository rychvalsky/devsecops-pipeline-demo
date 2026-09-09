"""Startup wiring: the bits that only run when the real app boots.

The CRUD tests swap the database out via dependency overrides, so the real
``init_db`` / ``get_session`` code never runs there. These two tests exercise
that glue directly against a temporary database.
"""

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, create_engine

import app.db as db_module
import app.main as main_module


def test_init_db_and_get_session_use_the_module_engine(tmp_path, monkeypatch) -> None:
    test_engine = create_engine(
        f"sqlite:///{tmp_path / 'startup.db'}",
        connect_args={"check_same_thread": False},
    )
    monkeypatch.setattr(db_module, "engine", test_engine)

    db_module.init_db()  # should create the tables on the temp engine

    generator = db_module.get_session()
    session = next(generator)
    assert isinstance(session, Session)
    assert session.get_bind() is test_engine
    with pytest.raises(StopIteration):  # generator closes its session cleanly
        next(generator)


def test_lifespan_creates_the_schema_on_boot(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(main_module, "init_db", lambda: calls.append("init_db"))

    # Entering the context manager triggers the FastAPI lifespan startup.
    with TestClient(main_module.app):
        pass

    assert calls == ["init_db"]
