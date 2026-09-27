from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.schemas.detection import DetectionResult


class BruteForceRule:
    """Reusable rule for detecting repeated failed login attempts."""

    name = "BRUTE_FORCE_DETECTION"
    default_threshold = 5
    severity = "high"

    def evaluate(
        self,
        db: Session,
        source_ip: str,
    ) -> DetectionResult:
        """Evaluate brute-force activity for a source IP."""

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
        detected = attempt_count >= self.default_threshold

        return DetectionResult(
            detected=detected,
            rule=self.name,
            source_ip=source_ip,
            failed_attempts=attempt_count,
            threshold=self.default_threshold,
            severity=self.severity if detected else "medium",
            message=(
                f"Detected {attempt_count} failed login attempts "
                f"from {source_ip}."
                if detected
                else f"No brute-force activity detected from {source_ip}."
            ),
        )