from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

SOURCES = ("cve_now", "cisa_kev")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Canonical, normalized vulnerability identifier (usually a CVE ID; cve.now
    # also publishes GHSA/OSV-style identifiers, which get their own records).
    vuln_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # provenance for summary text: e.g. "cve_now:model-summary", "cisa_kev:short_description"
    summary_source: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # vendor/source-stated severity label where no numeric score is available
    stated_severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    first_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    kev_date_added: Mapped[str | None] = mapped_column(String(10), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    source_records: Mapped[list["SourceRecord"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    cvss_scores: Mapped[list["CvssScore"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    affected_products: Mapped[list["AffectedProduct"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )
    watchlist_matches: Mapped[list["WatchlistMatch"]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan"
    )


class SourceRecord(Base):
    """Preserved record from one source for one vulnerability."""

    __tablename__ = "source_records"
    __table_args__ = (UniqueConstraint("source", "vuln_id", name="uq_source_vuln"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(32), index=True)
    vuln_id: Mapped[str] = mapped_column(String(64), index=True)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # full source payload (normalized dict) for provenance
    data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    first_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="source_records")


class CvssScore(Base):
    """CVSS score kept with version and source attribution."""

    __tablename__ = "cvss_scores"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "source", "version", name="uq_cvss_attr"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(40))
    version: Mapped[str] = mapped_column(String(16))
    vector: Mapped[str | None] = mapped_column(String(120), nullable=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="cvss_scores")


class AffectedProduct(Base):
    """Structured affected-product data (vendor/product/versions) from a source."""

    __tablename__ = "affected_products"
    __table_args__ = (
        UniqueConstraint(
            "vulnerability_id", "vendor", "product", "source", name="uq_affected"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True
    )
    vendor: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    product: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    versions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    fixes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    source: Mapped[str] = mapped_column(String(32))

    vulnerability: Mapped[Vulnerability] = relationship(
        back_populates="affected_products"
    )


class WatchlistItem(Base):
    __tablename__ = "watchlist_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    keywords: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    matches: Mapped[list["WatchlistMatch"]] = relationship(
        back_populates="item", cascade="all, delete-orphan"
    )


class WatchlistMatch(Base):
    __tablename__ = "watchlist_matches"
    __table_args__ = (
        UniqueConstraint(
            "vulnerability_id",
            "watchlist_item_id",
            "match_type",
            "matched_term",
            name="uq_match",
        ),
        Index("ix_match_item", "watchlist_item_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE")
    )
    watchlist_item_id: Mapped[int] = mapped_column(
        ForeignKey("watchlist_items.id", ondelete="CASCADE")
    )
    # 'structured' (affected-product data) or 'keyword' (title/summary text)
    match_type: Mapped[str] = mapped_column(String(16))
    matched_term: Mapped[str] = mapped_column(String(200))
    matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    vulnerability: Mapped[Vulnerability] = relationship(
        back_populates="watchlist_matches"
    )
    item: Mapped[WatchlistItem] = relationship(back_populates="matches")


class SyncState(Base):
    __tablename__ = "sync_state"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(32), unique=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # 'running' | 'success' | 'error'
    status: Mapped[str] = mapped_column(String(16), default="never_run")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    records_processed: Mapped[int] = mapped_column(default=0, nullable=False)
    checkpoint: Mapped[dict | None] = mapped_column(JSON, nullable=True)
