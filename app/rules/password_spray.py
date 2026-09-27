from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.schemas.detection import DetectionResult


class PasswordSprayRule:
    """Reusable rule for detecting login failures across multiple accounts."""

    name = "PASSWORD_SPRAY_DETECTION"
    default_threshold = 3
    severity = "high"

    def evaluate(
        self,
        db: Session,
        source_ip: str,
    ) -> DetectionResult:
        """Evaluate password-spray activity for a source IP."""

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
        detected = account_count >= self.default_threshold

        return DetectionResult(
            detected=detected,
            rule=self.name,
            source_ip=source_ip,
            failed_attempts=account_count,
            threshold=self.default_threshold,
            severity=self.severity if detected else "medium",
            message=(
                f"Password spraying detected against {account_count} "
                f"accounts from {source_ip}."
                if detected
                else f"No password spraying detected from {source_ip}."
            ),
        )