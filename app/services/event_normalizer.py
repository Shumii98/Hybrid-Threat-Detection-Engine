from app.schemas.security_event import SecurityEventCreate


def normalize_security_event(
    event: SecurityEventCreate,
) -> SecurityEventCreate:
    """Normalize common security-event fields before persistence."""

    source = event.source.strip().lower()
    event_type = event.event_type.strip().lower()
    severity = event.severity.strip().lower()

    source_ip = (
        event.source_ip.strip()
        if event.source_ip
        else None
    )

    destination_ip = (
        event.destination_ip.strip()
        if event.destination_ip
        else None
    )

    username = (
        event.username.strip()
        if event.username
        else None
    )

    raw_message = (
        event.raw_message.strip()
        if event.raw_message
        else None
    )

    return SecurityEventCreate(
        timestamp=event.timestamp,
        source=source,
        event_type=event_type,
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        severity=severity,
        raw_message=raw_message,
    )