"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-11-06
"""

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vuln_id", sa.String(64), nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("summary_source", sa.String(80), nullable=True),
        sa.Column("stated_severity", sa.String(32), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("kev_date_added", sa.String(10), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vulnerabilities_vuln_id", "vulnerabilities", ["vuln_id"], unique=True)

    op.create_table(
        "source_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("vuln_id", sa.String(64), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=True),
        sa.Column("first_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("source", "vuln_id", name="uq_source_vuln"),
    )
    op.create_index("ix_source_records_vulnerability_id", "source_records", ["vulnerability_id"])
    op.create_index("ix_source_records_source", "source_records", ["source"])
    op.create_index("ix_source_records_vuln_id", "source_records", ["vuln_id"])

    op.create_table(
        "cvss_scores",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(40), nullable=False),
        sa.Column("version", sa.String(16), nullable=False),
        sa.Column("vector", sa.String(120), nullable=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.UniqueConstraint("vulnerability_id", "source", "version", name="uq_cvss_attr"),
    )
    op.create_index("ix_cvss_scores_vulnerability_id", "cvss_scores", ["vulnerability_id"])

    op.create_table(
        "affected_products",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("vendor", sa.String(200), nullable=False, server_default=""),
        sa.Column("product", sa.String(200), nullable=False, server_default=""),
        sa.Column("versions", sa.JSON(), nullable=True),
        sa.Column("fixes", sa.JSON(), nullable=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.UniqueConstraint("vulnerability_id", "vendor", "product", "source", name="uq_affected"),
    )
    op.create_index("ix_affected_products_vulnerability_id", "affected_products", ["vulnerability_id"])

    op.create_table(
        "watchlist_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("keywords", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_watchlist_items_name", "watchlist_items", ["name"], unique=True)

    op.create_table(
        "watchlist_matches",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("watchlist_item_id", sa.Integer(), sa.ForeignKey("watchlist_items.id", ondelete="CASCADE"), nullable=False),
        sa.Column("match_type", sa.String(16), nullable=False),
        sa.Column("matched_term", sa.String(200), nullable=False),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("vulnerability_id", "watchlist_item_id", "match_type", "matched_term", name="uq_match"),
    )
    op.create_index("ix_match_item", "watchlist_matches", ["watchlist_item_id"])

    op.create_table(
        "sync_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="never_run"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("records_processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("checkpoint", sa.JSON(), nullable=True),
    )
    op.create_index("ix_sync_state_source", "sync_state", ["source"], unique=True)


def downgrade() -> None:
    op.drop_table("sync_state")
    op.drop_table("watchlist_matches")
    op.drop_table("watchlist_items")
    op.drop_table("affected_products")
    op.drop_table("cvss_scores")
    op.drop_table("source_records")
    op.drop_table("vulnerabilities")
