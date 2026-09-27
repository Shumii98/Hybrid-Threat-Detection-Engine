"""add risk score to alerts

Revision ID: ddeb54099948
Revises:
Create Date: 2026-09-27 17:08:48.350941

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "ddeb54099948"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add risk score to existing alerts."""

    op.add_column(
        "alerts",
        sa.Column(
            "risk_score",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    op.create_index(
        op.f("ix_alerts_risk_score"),
        "alerts",
        ["risk_score"],
        unique=False,
    )

    op.alter_column(
        "alerts",
        "risk_score",
        server_default=None,
    )


def downgrade() -> None:
    """Remove risk score from alerts."""

    op.drop_index(
        op.f("ix_alerts_risk_score"),
        table_name="alerts",
    )

    op.drop_column(
        "alerts",
        "risk_score",
    )