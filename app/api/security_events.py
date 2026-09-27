from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.security_event import (
    SecurityEventCreate,
    SecurityEventResponse,
)
from app.services.security_event_service import create_security_event

router = APIRouter(
    prefix="/events",
    tags=["Security Events"],
)


@router.post(
    "/",
    response_model=SecurityEventResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_event(
    event_data: SecurityEventCreate,
    db: Session = Depends(get_db),
) -> SecurityEventResponse:
    """Create a normalized security event."""

    return create_security_event(db, event_data)