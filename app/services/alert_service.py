from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.schemas.detection import DetectionResult


def create_alert(
    db: Session,
    detection: DetectionResult,
) -> Alert | None:
    """Create and persist an alert when a detection is triggered."""

    if not detection.detected:
        return None

    alert = Alert(
        rule=detection.rule,
        severity=detection.severity or "medium",
        risk_score=detection.risk_score,
        source_ip=detection.source_ip,
        message=detection.message or "Security detection triggered.",
        status="open",
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert