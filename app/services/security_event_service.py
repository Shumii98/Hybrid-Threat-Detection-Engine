from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.schemas.security_event import SecurityEventCreate
from app.services.event_normalizer import normalize_security_event


def create_security_event(
    db: Session,
    event_data: SecurityEventCreate,
) -> SecurityEvent:
    """Normalize, create, and persist a security event."""

    normalized_event = normalize_security_event(
        event_data,
    )

    event = SecurityEvent(
        **normalized_event.model_dump(),
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event