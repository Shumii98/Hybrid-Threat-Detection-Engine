from sqlalchemy.orm import Session

from app.rules.registry import get_rule
from app.schemas.detection import DetectionResult


def run_rule(
    db: Session,
    rule_name: str,
    source_ip: str,
) -> DetectionResult:
    """Execute a registered detection rule."""

    rule = get_rule(rule_name)

    if rule is None:
        raise ValueError(
            f"Detection rule '{rule_name}' is not registered."
        )

    return rule.evaluate(
        db=db,
        source_ip=source_ip,
    )