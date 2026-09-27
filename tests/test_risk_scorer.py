from types import SimpleNamespace

from app.services.risk_scorer import calculate_risk_score


def make_detection(
    detected=True,
    severity="high",
    failed_attempts=5,
    threshold=5,
):
    return SimpleNamespace(
        detected=detected,
        severity=severity,
        failed_attempts=failed_attempts,
        threshold=threshold,
    )


def test_not_detected_returns_zero():
    detection = make_detection(
        detected=False,
        severity="high",
        failed_attempts=10,
        threshold=5,
    )

    assert calculate_risk_score(detection) == 0


def test_low_severity_score():
    detection = make_detection(
        severity="low",
        failed_attempts=5,
        threshold=5,
    )

    assert calculate_risk_score(detection) == 10


def test_medium_severity_score():
    detection = make_detection(
        severity="medium",
        failed_attempts=5,
        threshold=5,
    )

    assert calculate_risk_score(detection) == 30


def test_high_severity_score():
    detection = make_detection(
        severity="high",
        failed_attempts=5,
        threshold=5,
    )

    assert calculate_risk_score(detection) == 60


def test_critical_severity_score():
    detection = make_detection(
        severity="critical",
        failed_attempts=5,
        threshold=5,
    )

    assert calculate_risk_score(detection) == 80


def test_score_increases_for_attempts_above_threshold():
    detection = make_detection(
        severity="high",
        failed_attempts=7,
        threshold=5,
    )

    # 60 base + (2 * 5) = 70
    assert calculate_risk_score(detection) == 70


def test_extra_attempt_score_is_capped():
    detection = make_detection(
        severity="high",
        failed_attempts=20,
        threshold=5,
    )

    # Extra-attempt bonus is capped at 20.
    # 60 + 20 = 80.
    assert calculate_risk_score(detection) == 80


def test_unknown_severity_uses_medium_score():
    detection = make_detection(
        severity="unknown",
        failed_attempts=5,
        threshold=5,
    )

    assert calculate_risk_score(detection) == 30