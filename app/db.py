"""Database engine and session handling.

Uses a local SQLite file so the whole app runs with zero infrastructure --
no database container is needed, which keeps the CI pipeline simple and fast.
"""

import os
from collections.abc import Iterator

from sqlmodel import Session, SQLModel, create_engine

# A file next to the app. Overridable via env so tests / containers can point
# somewhere else without touching code.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./notes.db")

# check_same_thread=False: FastAPI may touch the connection from different
# threads; safe here because each request gets its own short-lived Session.
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


def init_db() -> None:
    """Create tables that don't exist yet. Called once on startup."""
    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    """FastAPI dependency: yield a session and always close it afterwards."""
    with Session(engine) as session:
        yield session
