"""EPSS enrichment and KEV context columns

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-07

- epss_scores: current FIRST EPSS score/percentile for canonical CVEs
  (1:1 by vulnerability_id, typed numeric columns and provenance).
- epss_history: one snapshot per CVE per EPSS score date (unique, indexed
  for queries by CVE and date).
- vulnerabilities: additional CISA KEV context columns (due date, required
  action, ransomware campaign use, catalog release date). Existing rows keep
  NULLs until a KEV sync fills them; server defaults avoid rewriting data.
"""

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("kev_due_date", sa.String(10), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("kev_required_action", sa.Text(), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("kev_ransomware_use", sa.String(64), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("kev_catalog_released", sa.String(32), nullable=True),
    )

    op.create_table(
        "epss_scores",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "vulnerability_id",
            sa.Integer(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(32), nullable=False, server_default="first_epss"),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("score_date", sa.Date(), nullable=False),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("model_version", sa.String(32), nullable=True),
        sa.UniqueConstraint("vulnerability_id", name="uq_epss_current_vuln"),
    )
    op.create_index("ix_epss_scores_vulnerability_id", "epss_scores", ["vulnerability_id"], unique=True)

    op.create_table(
        "epss_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "vulnerability_id",
            sa.Integer(),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(32), nullable=False, server_default="first_epss"),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("score_date", sa.Date(), nullable=False),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("model_version", sa.String(32), nullable=True),
        sa.UniqueConstraint("vulnerability_id", "score_date", name="uq_epss_history_vuln_date"),
    )
    op.create_index("ix_epss_history_vulnerability_id", "epss_history", ["vulnerability_id"])
    op.create_index("ix_epss_history_vuln_date", "epss_history", ["vulnerability_id", "score_date"])


def downgrade() -> None:
    op.drop_index("ix_epss_history_vuln_date", table_name="epss_history")
    op.drop_index("ix_epss_history_vulnerability_id", table_name="epss_history")
    op.drop_table("epss_history")
    op.drop_index("ix_epss_scores_vulnerability_id", table_name="epss_scores")
    op.drop_table("epss_scores")
    op.drop_column("vulnerabilities", "kev_catalog_released")
    op.drop_column("vulnerabilities", "kev_ransomware_use")
    op.drop_column("vulnerabilities", "kev_required_action")
    op.drop_column("vulnerabilities", "kev_due_date")
