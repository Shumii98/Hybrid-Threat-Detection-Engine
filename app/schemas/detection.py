from datetime import datetime

from pydantic import BaseModel


class DetectionResult(BaseModel):
    """Standardized result returned by detection rules."""

    detected: bool
    rule: str
    source_ip: str | None = None
    failed_attempts: int = 0
    threshold: int = 0
    severity: str = "medium"
    risk_score: int = 0
    message: str


class DetectionAlertResponse(BaseModel):
    """Response returned after running detection and alert creation."""

    detected: bool
    rule: str
    source_ip: str | None = None
    failed_attempts: int = 0
    threshold: int = 0
    severity: str
    risk_score: int = 0
    message: str
    alert_id: int | None = None
    alert_status: str
    created_at: datetime | None = None
