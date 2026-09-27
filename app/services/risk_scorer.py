from app.schemas.detection import DetectionResult


SEVERITY_SCORES = {
    "low": 10,
    "medium": 30,
    "high": 60,
    "critical": 80,
}


def calculate_risk_score(
    detection: DetectionResult,
) -> int:
    """Calculate an explainable risk score from a detection result."""

    if not detection.detected:
        return 0

    score = SEVERITY_SCORES.get(
        detection.severity.lower(),
        30,
    )

    if detection.failed_attempts > detection.threshold:
        score += min(
            (detection.failed_attempts - detection.threshold) * 5,
            20,
        )

    return min(score, 100)