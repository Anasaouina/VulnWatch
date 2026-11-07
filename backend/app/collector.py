"""Collector: fetches both sources, normalizes and upserts records.

Guarantees:
- Idempotent: replaying the same feed creates no duplicate vulnerabilities,
  source records, CVSS rows, matches or affected products.
- Source failure: a failed or malformed fetch is logged, the source's sync
  state records the error, the last successful data stays untouched and the
  checkpoint does not advance.
"""

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from sqlalchemy import text, select
from sqlalchemy.orm import Session, sessionmaker

from . import matching
from .config import Settings, settings as default_settings
from .db import make_engine
from .models import utcnow
from .models import (
    SOURCES,
    AffectedProduct,
    CvssScore,
    SourceRecord,
    SyncState,
    Vulnerability,
    WatchlistItem,
)
from .normalize import normalize_vuln_id, parse_datetime, safe_url, severity_bucket
from .sources import cisa_kev, cve_now

log = logging.getLogger("vulnwatch.collector")

CISA_SUMMARY_SOURCE = "cisa_kev:short_description"
CVE_NOW_SUMMARY_PREFIX = "cve_now:model-summary"


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat() if dt else None


def get_or_create_vuln(session: Session, vuln_id: str, now: datetime) -> tuple[Vulnerability, bool]:
    canonical = normalize_vuln_id(vuln_id)
    vuln = session.execute(
        select(Vulnerability).where(Vulnerability.vuln_id == canonical)
    ).scalar_one_or_none()
    if vuln is None:
        vuln = Vulnerability(vuln_id=canonical, created_at=now)
        session.add(vuln)
        session.flush()
        return vuln, True
    return vuln, False


def upsert_source_record(
    session: Session, vuln: Vulnerability, source: str, source_url: str | None,
    data: dict, now: datetime,
) -> SourceRecord:
    rec = session.execute(
        select(SourceRecord).where(
            SourceRecord.source == source, SourceRecord.vuln_id == vuln.vuln_id
        )
    ).scalar_one_or_none()
    if rec is None:
        rec = SourceRecord(
            vulnerability_id=vuln.id,
            source=source,
            vuln_id=vuln.vuln_id,
            source_url=safe_url(source_url),
            first_synced_at=now,
        )
        session.add(rec)
    rec.data = data
    rec.last_synced_at = now
    return rec


def upsert_cvss(
    session: Session, vuln: Vulnerability, source: str, version: str,
    score: float, vector: str | None,
) -> None:
    row = session.execute(
        select(CvssScore).where(
            CvssScore.vulnerability_id == vuln.id,
            CvssScore.source == source,
            CvssScore.version == version,
        )
    ).scalar_one_or_none()
    if row is None:
        row = CvssScore(
            vulnerability_id=vuln.id, source=source, version=version,
            vector=vector, score=score,
        )
        session.add(row)
    else:
        row.score = score
        if vector:
            row.vector = vector


def upsert_kev_flag(session: Session, vuln: Vulnerability, date_added: str | None) -> None:
    vuln.is_kev = True
    if date_added and (not vuln.kev_date_added or date_added < vuln.kev_date_added):
        vuln.kev_date_added = date_added


def vector_version(vector: str | None) -> str:
    prefix = (vector or "")[:10].upper()
    if prefix.startswith("CVSS:"):
        tail = prefix.split(":", 1)[1].split("/", 1)[0]
        if tail and all(ch in ".0123456789" for ch in tail):
            return tail
    return "unknown"


# --- cve.now ingestion --------------------------------------------------------

@dataclass
class ListSyncResult:
    pages: int = 0
    entries: int = 0
    newest: datetime | None = None
    watermark: datetime | None = None


def ingest_cve_now_entries(session: Session, entries: list[cve_now.CveNowEntry]) -> int:
    """Upsert one page of cve.now list entries. Returns count processed."""
    now = utcnow()
    for e in entries:
        vuln, created = get_or_create_vuln(session, e.vuln_id, now)
        if e.title:
            vuln.title = e.title
        if e.stated_severity:
            vuln.stated_severity = e.stated_severity
        # dates: keep previously known values; source dates win when present
        if e.published_at:
            vuln.published_at = e.published_at
        if e.first_seen_at:
            vuln.first_seen_at = e.first_seen_at
        vuln.last_updated_at = e.modified_at or utcnow()

        raw = dict(e.raw)
        raw.pop("_cve_now", None)
        data = {
            "kind": "cve.now-list-entry",
            "title": e.title,
            "publishedAt": _iso(e.published_at),
            "firstSeenAt": _iso(e.first_seen_at),
            "modifiedAt": _iso(e.modified_at),
            "cvss": e.cvss,
            "statedSeverity": e.stated_severity,
            "kev": e.kev,
            "product": e.product,
            "productKey": e.product_key,
            "fix": e.fix_versions,
        }
        upsert_source_record(
            session, vuln, "cve_now",
            f"{default_settings.cve_now_base_url}/{quote(e.vuln_id)}",
            data, now,
        )
        if e.cvss is not None:
            # List endpoint does not include the scoring origin; label it
            # accordingly instead of inventing an attribution.
            upsert_cvss(session, vuln, "cve_now-list (unattributed)", "unknown", e.cvss, None)
        if e.kev:
            # list-level KEV hint; authoritative dateAdded comes from CISA KEV
            if not vuln.is_kev:
                vuln.is_kev = True
        if e.product:
            upsert_list_affected(session, vuln, e.product, e.fix_versions)
    return len(entries)


def upsert_list_affected(
    session: Session, vuln: Vulnerability, product_name: str, versions=None
) -> None:
    """Keep a product row derived from the list-level `product`/`fix` fields."""
    product = (product_name or "").strip()
    if not product:
        return
    row = session.execute(
        select(AffectedProduct).where(
            AffectedProduct.vulnerability_id == vuln.id,
            AffectedProduct.vendor == "",
            AffectedProduct.product == product.lower()[:200],
            AffectedProduct.source == "cve_now",
        )
    ).scalar_one_or_none()
    versions_clean = _clean_versions(versions) if versions else None
    if row is None:
        session.add(
            AffectedProduct(
                vulnerability_id=vuln.id,
                vendor="",
                product=product.lower()[:200],
                versions=versions_clean,
                source="cve_now",
            )
        )
    elif versions_clean and not row.versions:
        row.versions = versions_clean


def sync_cve_now(
    session: Session, s: Settings, now: datetime | None = None
) -> ListSyncResult:
    """Pull recent pages of the cve.now entries API; upsert; update checkpoint."""
    state = _sync_state(session, "cve_now")
    checkpoint = state.checkpoint or {}
    watermark = parse_datetime(checkpoint.get("watermark"))
    result = ListSyncResult()
    newest_seen = watermark

    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        cursor = None
        for page_no in range(s.cve_now_max_pages_per_run):
            entries, next_cursor = cve_now.CveNowClient(client, s).list_entries(cursor)
            if not entries and page_no == 0:
                raise ValueError("empty cve.now page")
            result.pages += 1
            for e in entries:
                seen_dt = e.first_seen_at or e.modified_at
                if seen_dt and (newest_seen is None or seen_dt > newest_seen):
                    newest_seen = seen_dt

            ingest_cve_now_entries(session, entries)
            result.entries += len(entries)
            session.commit()

            if next_cursor is None:
                break
            # stop when the whole page is older than the watermark
            if watermark is not None and not any(
                (e.first_seen_at or e.modified_at or e.published_at or utcnow()) > watermark
                for e in entries
            ):
                break
            cursor = next_cursor
            time.sleep(s.cve_now_page_pause_seconds)

    if newest_seen:
        state.checkpoint = {"watermark": _iso(newest_seen)}
        result.watermark = newest_seen
    return result


# --- CISA KEV ingestion -------------------------------------------------------

def ingest_kev_catalog(session: Session, entries: list[cisa_kev.KevEntry], catalog_version: str | None) -> int:
    now = utcnow()
    count = 0
    for kev in entries:
        vuln, _created = get_or_create_vuln(session, kev.vuln_id, now)
        if not vuln.title and kev.vulnerability_name:
            vuln.title = kev.vulnerability_name
        if not vuln.summary and kev.short_description:
            vuln.summary = kev.short_description
            vuln.summary_source = CISA_SUMMARY_SOURCE
        upsert_kev_flag(session, vuln, kev.date_added)
        upsert_source_record(
            session, vuln, "cisa_kev",
            cisa_kev.catalog_detail_url(kev.vuln_id),
            {
                "kind": "cisa-kev-entry",
                "dateAdded": kev.date_added,
                "dueDate": kev.due_date,
                "vendorProject": kev.vendor_project,
                "product": kev.product,
                "vulnerabilityName": kev.vulnerability_name,
                "requiredAction": kev.required_action,
                "knownRansomwareCampaignUse": kev.ransomware_use,
                "notes": kev.notes_url,
                "cwes": kev.cwes,
                "catalogVersion": catalog_version,
            },
            now,
        )
        # kev due date preserved on the record; width of detail shown by API
        count += 1
    return count


def sync_cisa_kev(session: Session, s: Settings) -> int:
    """Fetch and upsert the full KEV catalog. Raises on fetch/parse failure."""
    from .http import fetch

    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        resp = fetch(
            client, s.cisa_kev_url, retries=s.http_retries,
            timeout=s.http_timeout_seconds, backoff=s.http_retry_backoff_seconds,
        )
        entries, version = cisa_kev.parse_catalog(resp.json())
        return ingest_kev_catalog(session, entries, version)


# --- detail enrichment --------------------------------------------------------

def enrich_from_detail(
    session: Session, session_factory: sessionmaker, s: Settings, limit: int = 25
) -> int:
    """Fetch cve.now per-entry detail for KEV/watchlist-matched CVEs that lack it.

    Provides structured affected-products data, remediation/fix versions,
    attributed CVSS (source + vector), references and summary provenance.
    """
    from .sources.cve_now import CveNowClient, parse_detail

    targets = session.execute(
        select(Vulnerability)
        .where(
            Vulnerability.vuln_id.like("CVE-%"),
            ~Vulnerability.vuln_id.in_(
                select(SourceRecord.vuln_id).where(
                    SourceRecord.data["kind"].as_string() == "cve.now-detail"
                )
            ),
        )
        .order_by(Vulnerability.is_kev.desc(), Vulnerability.updated_at.desc())
        .limit(limit)
    ).scalars().all()
    if not targets:
        return 0
    count = 0
    now = utcnow()
    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        client2 = CveNowClient(client, s)
        for vuln in targets:
            if count >= limit:
                break
            try:
                detail = client2.fetch_detail(vuln.vuln_id)
            except Exception as exc:
                log.warning("detail fetch failed for %s: %r", vuln.vuln_id, exc)
                continue
            if detail is None:
                continue
            _apply_detail(session, vuln, detail, now)
            count += 1
            session.commit()
            time.sleep(s.cve_now_detail_pause_seconds)
    return count


def _apply_detail(session: Session, vuln: Vulnerability, detail: cve_now.CveNowDetail, now: datetime) -> None:
    e = detail.entry
    if e.title:
        vuln.title = e.title
    if e.published_at:
        vuln.published_at = e.published_at
    if e.modified_at:
        vuln.last_updated_at = e.modified_at
    if detail.summary:
        vuln.summary = detail.summary
        vuln.summary_source = (
            f"{CVE_NOW_SUMMARY_PREFIX}:{detail.summary_model}" if detail.summary_model
            else CVE_NOW_SUMMARY_PREFIX
        )
    elif detail.original_description and not vuln.summary:
        vuln.summary = detail.original_description
        vuln.summary_source = "cve_now:cvelistV5-description"
    if e.cvss is not None:
        # attribute with the source cve.now published alongside the score
        score_source = e.severity_source or "cve_now-list (unattributed)"
        upsert_cvss(session, vuln, score_source, vector_version(e.cvss_vector), e.cvss, e.cvss_vector)
    if detail.kev_date_added:
        upsert_kev_flag(session, vuln, detail.kev_date_added)
    upsert_source_record(
        session, vuln, "cve_now",
        f"{default_settings.cve_now_base_url}/{quote(e.vuln_id)}",
        {
            "kind": "cve.now-detail",
            "title": e.title,
            "summaryProvenance": detail.summary_model,
            "publishedAt": _iso(e.published_at),
            "firstSeenAt": _iso(e.first_seen_at),
            "modifiedAt": _iso(e.modified_at),
            "cvss": e.cvss,
            "cvssVector": e.cvss_vector,
            "statedSeverity": e.stated_severity,
            "kev": e.kev,
            "kevDateAdded": detail.kev_date_added,
            "kevDueDate": detail.kev_due_date,
            "references": detail.references,
            "aliases": detail.aliases,
            "sourceLinks": detail.source_links,
            "affected": detail.affected,
            "originalUrl": f"{default_settings.cve_now_base_url}/{quote(e.vuln_id)}",
        },
        now,
    )
    existing_pairs = {
        (ap.vendor.lower(), ap.product.lower(), ap.source)
        for ap in vuln.affected_products
    }
    for a in detail.affected:
        vendor = (a.get("vendor") or "").strip()
        product = (a.get("product") or "").strip()
        if not product and not vendor:
            continue
        key = (vendor.lower(), product.lower(), "cve_now")
        if key in existing_pairs:
            continue
        affected = AffectedProduct(
            vulnerability_id=vuln.id,
            vendor=vendor[:200],
            product=product.lower()[:200],
            versions=_clean_versions(a.get("ranges") or a.get("versions")),
            fixes=_clean_versions((a.get("fixes") or a.get("fix"))),
            source="cve_now",
        )
        session.add(affected)
    # merge list-level fix rows found earlier
    list_ap = [
        ap
        for ap in vuln.affected_products
        if ap.source == "cve_now" and not ap.vendor
    ]
    for ap in list_ap:
        for a in detail.affected:
            product = (a.get("product") or "").strip().lower()
            if product and product == ap.product.lower():
                ap.vendor = (a.get("vendor") or "").strip()[:200]
                if not ap.versions and a.get("ranges"):
                    ap.versions = _clean_versions(a.get("ranges"))
                if not ap.fixes and a.get("fixes"):
                    ap.fixes = _clean_versions(a.get("fixes"))


def _clean_versions(v) -> list | None:
    if not isinstance(v, list):
        return None
    out = []
    for item in v[:20]:
        if isinstance(item, str) and item:
            out.append(item)
        elif isinstance(item, dict):
            simple = {k: item[k] for k in item if isinstance(item[k], (str, int, float)) and k not in ("versions",)}
            if item.get("ranges"):
                simple[""] = item["ranges"]
            out.append(simple or None)
    out = [o for o in out if o is not None]
    return out or None


# --- sync state ---------------------------------------------------------------

def _sync_state(session: Session, source: str) -> SyncState:
    row = session.execute(select(SyncState).where(SyncState.source == source)).scalar_one_or_none()
    if row is None:
        row = SyncState(source=source)
        session.add(row)
        session.flush()
    return row


def _begin_attempt(session: Session, source: str) -> None:
    st = _sync_state(session, source)
    st.last_attempt_at = utcnow()
    st.status = "running"
    st.error_message = None
    session.commit()


def _mark_success(session: Session, source: str, records: int) -> None:
    st = _sync_state(session, source)
    st.last_success_at = utcnow()
    st.status = "success"
    st.error_message = None
    st.records_processed = records
    session.commit()


def _mark_error(session: Session, source: str, message: str) -> None:
    st = _sync_state(session, source)
    st.status = "error"
    st.error_message = message[:2000]
    # deliberately keeps last_success_at and checkpoint from the previous success
    session.commit()


# --- orchestration ------------------------------------------------------------

class RunLock:
    """Cross-process advisory lock (Postgres) nested inside a threading lock."""

    def __init__(self, session_factory: sessionmaker):
        self._thread_lock = threading.Lock()
        self.session_factory = session_factory

    def acquire(self) -> bool:
        if not self._thread_lock.acquire(blocking=False):
            return False
        try:
            with self.session_factory() as session:
                session.execute(text("SELECT 1"))
                is_pg = session.connection().dialect.name == "postgresql"
                if is_pg:
                    got = session.execute(
                        text("SELECT pg_try_advisory_lock(710201)")
                    ).scalar()
                    if not got:
                        self._thread_lock.release()
                        return False
            return True
        except Exception:
            self._thread_lock.release()
            raise

    def release(self) -> None:
        try:
            with self.session_factory() as session:
                is_pg = session.connection().dialect.name == "postgresql"
                if is_pg:
                    session.execute(text("SELECT pg_advisory_unlock(710201)"))
                    session.commit()
        finally:
            self._thread_lock.release()


def run_sync(session_factory: sessionmaker, s: Settings, sources: list[str] | None = None) -> dict:
    """Run one collector cycle. Returns a per-source result summary."""
    sources = sources or list(SOURCES)
    results: dict[str, dict] = {}
    for source in sources:
        with session_factory() as session:
            try:
                _begin_attempt(session, source)
                if source == "cve_now":
                    r = sync_cve_now(session, s)
                    _mark_success(session, source, r.entries)
                    results[source] = {
                        "status": "success",
                        "pages": r.pages,
                        "records": r.entries,
                    }
                elif source == "cisa_kev":
                    r = sync_cisa_kev(session, s)
                    _mark_success(session, source, r)
                    results[source] = {"status": "success", "records": r}
                else:
                    raise ValueError(f"unknown source {source}")
            except Exception as exc:  # noqa: BLE001
                log.exception("sync for %s failed; keeping last successful data", source)
                with session_factory() as session:
                    _mark_error(session, source, f"{type(exc).__name__}: {exc}")
                results[source] = {"status": "error", "error": f"{type(exc).__name__}"}

    # enrichment + matching run after the fetches; failure is non-fatal
    try:
        with session_factory() as session:
            n = enrich_from_detail(session, session_factory, s)
            if n:
                results["_enriched"] = {"count": n}
    except Exception:  # noqa: BLE001
        log.exception("detail enrichment failed (non-fatal)")

    try:
        with session_factory() as session:
            vids = [
                v.id
                for v in session.execute(
                    select(Vulnerability).order_by(Vulnerability.updated_at.desc()).limit(500)
                ).scalars()
            ]
            matching.recompute_matches(session, vids)
            session.commit()
    except Exception:  # noqa: BLE001
        log.exception("watchlist matching failed (non-fatal)")
    return results
