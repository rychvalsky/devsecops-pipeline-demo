"""Data models.

SQLModel lets one class act as both the database table and the API schema.
`Note` is the stored row; the small sibling classes shape what comes in on a
request body and what goes out in a response.
"""

from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class NoteBase(SQLModel):
    """Fields shared by every representation of a note."""

    title: str = Field(min_length=1, max_length=200)
    body: str = Field(default="", max_length=10_000)


class Note(NoteBase, table=True):
    """The persisted note row."""

    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )


class NoteCreate(NoteBase):
    """Request body for creating a note (client cannot set id / created_at)."""


class NoteRead(NoteBase):
    """Response body for a note."""

    id: int
    created_at: datetime
