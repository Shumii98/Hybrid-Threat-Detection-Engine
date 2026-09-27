from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SecurityEventCreate(BaseModel):
    """Schema for creating a normalized security event."""

    timestamp: datetime
    source: str = Field(min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)

    source_ip: str | None = Field(
        default=None,
        max_length=45,
    )

    destination_ip: str | None = Field(
        default=None,
        max_length=45,
    )

    username: str | None = Field(
        default=None,
        max_length=255,
    )

    severity: str = Field(
        default="low",
        min_length=1,
        max_length=20,
    )

    raw_message: str | None = None


class SecurityEventResponse(SecurityEventCreate):
    """Schema returned by the API."""

    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)