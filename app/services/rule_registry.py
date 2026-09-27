from sqlalchemy.orm import Session

from app.schemas.detection import DetectionResult
from app.services.detection_engine import (
    detect_brute_force,
    detect_password_spray,
)


RULE_REGISTRY = {
    "brute_force": detect_brute_force,
    "password_spray": detect_password_spray,
}


def run_rule(
    db: Session,
    rule_name: str,
    source_ip: str,
) -> DetectionResult:
    """Run a registered detection rule."""

    rule = RULE_REGISTRY.get(rule_name)

    if rule is None:
        raise ValueError(
            f"Unknown detection rule: {rule_name}"
        )

    return rule(
        db=db,
        source_ip=source_ip,
    )