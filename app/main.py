"""Notes API -- a deliberately small FastAPI application.

It exists to be the thing that flows through the DevSecOps pipeline
(tests -> SAST -> dependency scan -> image scan -> DAST). Keep it minimal.

Endpoints:
    GET    /                 -- API root, no auth (also gives the DAST spider a
                                starting point that links to /docs)
    GET    /health           -- liveness check, no auth
    POST   /notes            -- create a note
    GET    /notes            -- list notes
    GET    /notes/{note_id}  -- fetch one note
    DELETE /notes/{note_id}  -- delete one note

Every /notes endpoint requires the `X-API-Key` header (see app/auth.py).
Baseline security headers are added to every response by SecurityHeadersMiddleware.
"""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status
from sqlmodel import Session, select

from app.auth import require_api_key
from app.db import get_session, init_db
from app.middleware import SecurityHeadersMiddleware
from app.models import Note, NoteCreate, NoteRead


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Run once at startup: make sure the tables exist."""
    init_db()
    yield


app = FastAPI(title="Notes API", version="0.1.0", lifespan=lifespan)
app.add_middleware(SecurityHeadersMiddleware)


@app.get("/")
def root() -> dict[str, str]:
    """Human-friendly entry point; also what the DAST spider crawls first."""
    return {
        "name": app.title,
        "version": app.version,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/notes",
    response_model=NoteRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
def create_note(payload: NoteCreate, session: Session = Depends(get_session)) -> Note:
    note = Note(**payload.model_dump())
    session.add(note)
    session.commit()
    session.refresh(note)
    return note


@app.get(
    "/notes",
    response_model=list[NoteRead],
    dependencies=[Depends(require_api_key)],
)
def list_notes(session: Session = Depends(get_session)) -> list[Note]:
    return list(session.exec(select(Note).order_by(Note.id)).all())


@app.get(
    "/notes/{note_id}",
    response_model=NoteRead,
    dependencies=[Depends(require_api_key)],
)
def get_note(note_id: int, session: Session = Depends(get_session)) -> Note:
    note = session.get(Note, note_id)
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return note


@app.delete(
    "/notes/{note_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_api_key)],
)
def delete_note(note_id: int, session: Session = Depends(get_session)) -> None:
    note = session.get(Note, note_id)
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    session.delete(note)
    session.commit()
