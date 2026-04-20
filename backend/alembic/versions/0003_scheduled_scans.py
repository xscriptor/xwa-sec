"""scheduled scans table

Revision ID: 0003_scheduled_scans
Revises: 0002_users_table
Create Date: 2026-04-20 00:00:02

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_scheduled_scans"
down_revision: Union[str, None] = "0002_users_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scheduled_scans",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("scan_type", sa.String(length=32), nullable=False),
        sa.Column("target", sa.String(length=2048), nullable=False),
        sa.Column("config_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("cron_expression", sa.String(length=128), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_by_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("next_run_at", sa.DateTime(), nullable=True),
        sa.Column(
            "last_scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_scheduled_scans_next_run_at", "scheduled_scans", ["next_run_at"])
    op.create_index("ix_scheduled_scans_is_enabled", "scheduled_scans", ["is_enabled"])


def downgrade() -> None:
    op.drop_index("ix_scheduled_scans_is_enabled", table_name="scheduled_scans")
    op.drop_index("ix_scheduled_scans_next_run_at", table_name="scheduled_scans")
    op.drop_table("scheduled_scans")
