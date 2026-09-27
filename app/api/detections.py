from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.detection import (
    DetectionAlertResponse,
    DetectionResult,
)
from app.services.alert_service import create_alert
from app.services.detection_engine import (
    detect_brute_force,
    detect_password_spray,
)
from app.services.rule_registry import run_rule


router = APIRouter(
    prefix="/detections",
    tags=["Detections"],
)


@router.get(
    "/brute-force/{source_ip}",
    response_model=DetectionResult,
)
def check_brute_force(
    source_ip: str,
    db: Session = Depends(get_db),
) -> DetectionResult:
    """Run brute-force detection for a source IP."""

    return detect_brute_force(
        db=db,
        source_ip=source_ip,
    )


@router.get(
    "/password-spray/{source_ip}",
    response_model=DetectionResult,
)
def check_password_spray(
    source_ip: str,
    db: Session = Depends(get_db),
) -> DetectionResult:
    """Run password-spray detection for a source IP."""

    return detect_password_spray(
        db=db,
        source_ip=source_ip,
    )


@router.post(
    "/brute-force/{source_ip}/alert",
    response_model=DetectionAlertResponse,
)
def detect_brute_force_and_create_alert(
    source_ip: str,
    db: Session = Depends(get_db),
) -> DetectionAlertResponse:
    """Run brute-force detection and create an alert if detected."""

    detection = detect_brute_force(
        db=db,
        source_ip=source_ip,
    )

    alert = create_alert(
        db=db,
        detection=detection,
    )

    if alert is None:
        return DetectionAlertResponse(
            detected=False,
            rule=detection.rule,
            source_ip=detection.source_ip,
            failed_attempts=detection.failed_attempts,
            threshold=detection.threshold,
            severity=detection.severity,
            risk_score=detection.risk_score,
            message=detection.message,
            alert_id=None,
            alert_status="not_detected",
            created_at=None,
        )

    return DetectionAlertResponse(
        detected=True,
        rule=detection.rule,
        source_ip=detection.source_ip,
        failed_attempts=detection.failed_attempts,
        threshold=detection.threshold,
        severity=detection.severity,
        risk_score=alert.risk_score,
        message=detection.message,
        alert_id=alert.id,
        alert_status=alert.status,
        created_at=alert.created_at,
    )


@router.post(
    "/password-spray/{source_ip}/alert",
    response_model=DetectionAlertResponse,
)
def detect_password_spray_and_create_alert(
    source_ip: str,
    db: Session = Depends(get_db),
) -> DetectionAlertResponse:
    """Run password-spray detection and create an alert if detected."""

    detection = detect_password_spray(
        db=db,
        source_ip=source_ip,
    )

    alert = create_alert(
        db=db,
        detection=detection,
    )

    if alert is None:
        return DetectionAlertResponse(
            detected=False,
            rule=detection.rule,
            source_ip=detection.source_ip,
            failed_attempts=detection.failed_attempts,
            threshold=detection.threshold,
            severity=detection.severity,
            risk_score=detection.risk_score,
            message=detection.message,
            alert_id=None,
            alert_status="not_detected",
            created_at=None,
        )

    return DetectionAlertResponse(
        detected=True,
        rule=detection.rule,
        source_ip=detection.source_ip,
        failed_attempts=detection.failed_attempts,
        threshold=detection.threshold,
        severity=detection.severity,
        risk_score=alert.risk_score,
        message=detection.message,
        alert_id=alert.id,
        alert_status=alert.status,
        created_at=alert.created_at,
    )


@router.get(
    "/run/{rule_name}/{source_ip}",
    response_model=DetectionResult,
)
def run_detection_rule(
    rule_name: str,
    source_ip: str,
    db: Session = Depends(get_db),
) -> DetectionResult:
    """Run any registered detection rule."""

    try:
        return run_rule(
            db=db,
            rule_name=rule_name,
            source_ip=source_ip,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc