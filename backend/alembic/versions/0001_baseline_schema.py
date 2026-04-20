"""baseline: scans, discovered_links, findings

Revision ID: 0001_baseline_schema
Revises:
Create Date: 2026-04-20 00:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0001_baseline_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "scans" not in existing_tables:
        op.create_table(
            "scans",
            sa.Column("id", sa.Integer(), primary_key=True, index=True),
            sa.Column("domain_target", sa.String(), index=True),
            sa.Column("status", sa.String(), nullable=True, server_default="RUNNING"),
            sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("scan_type", sa.String(), nullable=True, server_default="port_scan"),
        )

    if "discovered_links" not in existing_tables:
        op.create_table(
            "discovered_links",
            sa.Column("id", sa.Integer(), primary_key=True, index=True),
            sa.Column(
                "scan_id",
                sa.Integer(),
                sa.ForeignKey("scans.id", ondelete="CASCADE"),
            ),
            sa.Column("url", sa.String()),
            sa.Column("status_code", sa.Integer(), nullable=True),
            sa.Column("content_type", sa.String(), nullable=True),
        )

    if "findings" not in existing_tables:
        op.create_table(
            "findings",
            sa.Column("id", sa.Integer(), primary_key=True, index=True),
            sa.Column(
                "scan_id",
                sa.Integer(),
                sa.ForeignKey("scans.id", ondelete="CASCADE"),
            ),
            sa.Column(
                "link_id",
                sa.Integer(),
                sa.ForeignKey("discovered_links.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column("severity", sa.String()),
            sa.Column("finding_type", sa.String()),
            sa.Column("description", sa.String()),
            sa.Column("poc_payload", sa.String(), nullable=True),
            sa.Column("cvss_score", sa.String(), nullable=True),
        )


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("discovered_links")
    op.drop_table("scans")
