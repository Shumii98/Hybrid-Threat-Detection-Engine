from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.security_event import SecurityEvent
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
    event: SecurityEventCreate,
    db: Session = Depends(get_db),
) -> SecurityEvent:
    """Normalize, create, and persist a security event."""

    return create_security_event(
        db=db,
        event_data=event,
    )