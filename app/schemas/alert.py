from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AlertResponse(BaseModel):
    """Schema returned by the alerts API."""

    id: int
    rule: str
    severity: str
    risk_score: int
    source_ip: str | None = None
    message: str
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertStatusUpdate(BaseModel):
    """Schema for updating an alert investigation status."""

    status: str = Field(
        min_length=1,
        max_length=20,
    )
