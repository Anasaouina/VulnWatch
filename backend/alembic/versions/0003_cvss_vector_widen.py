"""Widen cvss_scores.vector for CVSS v4 vectors

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-14

CVSS v4.0 vectors are up to ~200 characters (v3.x vectors stay under 120),
so the NVD feed trips the previous varchar(120) limit with
StringDataRightTruncation. Widening to varchar(255) keeps full vectors; the
downgrade restores the old width (existing long vectors would be truncated
by the database, which is acceptable for a rollback of a cosmetic width).
"""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("cvss_scores") as batch:
        batch.alter_column(
            "vector",
            existing_type=sa.String(120),
            type_=sa.String(255),
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("cvss_scores") as batch:
        batch.alter_column(
            "vector",
            existing_type=sa.String(255),
            type_=sa.String(120),
            existing_nullable=True,
        )
