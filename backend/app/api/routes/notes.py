from datetime import datetime
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user, require_role
from app.models.note import Note
from app.models.user import AuthUser

router = APIRouter(prefix="/notes", tags=["notes"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class NoteCreate(BaseModel):
    entity_type: str   # "endpoint" | "user"
    entity_id: str
    content: str

    @field_validator("entity_type")
    @classmethod
    def validate_entity_type(cls, v: str) -> str:
        if v not in ("endpoint", "user"):
            raise ValueError("entity_type must be 'endpoint' or 'user'")
        return v

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("content cannot be empty")
        if len(v) > 4000:
            raise ValueError("content must be 4000 characters or fewer")
        return v


class NoteResponse(BaseModel):
    id: uuid.UUID
    entity_type: str
    entity_id: str
    content: str
    author_email: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("", response_model=list[NoteResponse])
async def list_notes(
    entity_type: str = Query(...),
    entity_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_role("viewer")),
):
    result = await db.execute(
        select(Note)
        .where(Note.entity_type == entity_type, Note.entity_id == entity_id)
        .order_by(Note.created_at.desc())
    )
    return [NoteResponse.model_validate(n) for n in result.scalars().all()]


@router.post("", response_model=NoteResponse, status_code=status.HTTP_201_CREATED)
async def create_note(
    body: NoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: AuthUser = Depends(require_role("analyst")),
):
    note = Note(
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        content=body.content,
        author_email=current_user.email,
    )
    db.add(note)
    await db.flush()
    await db.refresh(note)
    return NoteResponse.model_validate(note)


@router.delete("/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_note(
    note_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: AuthUser = Depends(require_role("analyst")),
):
    result = await db.execute(select(Note).where(Note.id == note_id))
    note = result.scalars().first()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")

    # Admins can delete any note; analysts can only delete their own
    if current_user.role != "admin" and note.author_email != current_user.email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only delete your own notes",
        )

    await db.delete(note)
