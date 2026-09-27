from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.schemas.detection import DetectionResult
from app.services.risk_scorer import calculate_risk_score


def detect_brute_force(
    db: Session,
    source_ip: str,
    threshold: int = 5,
) -> DetectionResult:
    """Detect repeated failed login attempts from one source IP."""

    failed_attempts = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.source == "authentication",
            SecurityEvent.event_type == "login_failed",
            SecurityEvent.source_ip == source_ip,
        )
        .all()
    )

    attempt_count = len(failed_attempts)
    detected = attempt_count >= threshold

    detection = DetectionResult(
        detected=detected,
        rule="BRUTE_FORCE_DETECTION",
        source_ip=source_ip,
        failed_attempts=attempt_count,
        threshold=threshold,
        severity="high" if detected else "medium",
        message=(
            f"Detected {attempt_count} failed login attempts "
            f"from {source_ip}."
            if detected
            else f"No brute-force activity detected from {source_ip}."
        ),
    )

    detection.risk_score = calculate_risk_score(detection)

    return detection


def detect_password_spray(
    db: Session,
    source_ip: str,
    threshold: int = 3,
) -> DetectionResult:
    """Detect failed login attempts against multiple usernames."""

    failed_attempts = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.source == "authentication",
            SecurityEvent.event_type == "login_failed",
            SecurityEvent.source_ip == source_ip,
        )
        .all()
    )

    usernames = {
        event.username
        for event in failed_attempts
        if event.username
    }

    account_count = len(usernames)
    detected = account_count >= threshold

    detection = DetectionResult(
        detected=detected,
        rule="PASSWORD_SPRAY_DETECTION",
        source_ip=source_ip,
        failed_attempts=account_count,
        threshold=threshold,
        severity="high" if detected else "medium",
        message=(
            f"Password spraying detected against {account_count} accounts "
            f"from {source_ip}."
            if detected
            else f"No password spraying detected from {source_ip}."
        ),
    )

    detection.risk_score = calculate_risk_score(detection)

    return detection