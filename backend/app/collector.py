"""Collector: fetches all sources, normalizes and upserts records.

Guarantees:
- Idempotent: replaying the same feed creates no duplicate vulnerabilities,
  source records, CVSS rows, matches, affected products or EPSS snapshots.
- Source failure: a failed or malformed fetch is logged, the source's sync
  state records the error, the last successful data stays untouched and the
  checkpoint does not advance.
- Per-source isolation: a failure in one source never blocks the others.
"""

import logging
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from urllib.parse import quote

import httpx
from sqlalchemy import or_, text, select
from sqlalchemy.orm import Session, sessionmaker

from . import matching
from .config import Settings, settings as default_settings
from .db import make_engine
from .models import utcnow
from .models import (
    SOURCES,
    AffectedProduct,
    CvssScore,
    EpssHistory,
    EpssScore,
    SourceRecord,
    SyncState,
    Vulnerability,
    WatchlistItem,
)
from .normalize import normalize_vuln_id, parse_datetime, safe_url, severity_bucket
from .sources import (
    cisa_advisories,
    cisa_kev,
    cve_now,
    debian_tracker,
    epss,
    exploit_db,
    github_advisory,
    metasploit,
    nuclei,
    nvd,
    osv_dev,
    poc_in_github,
    redhat,
    threatfox,
    ubuntu,
    vulners,
)

log = logging.getLogger("vulnwatch.collector")

CISA_SUMMARY_SOURCE = "cisa_kev:short_description"
CVE_NOW_SUMMARY_PREFIX = "cve_now:model-summary"

# chunk size when matching a bulk feed against the canonical vulnerability table
_LOOKUP_CHUNK = 800


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

def ingest_kev_catalog(
    session: Session,
    entries: list[cisa_kev.KevEntry],
    catalog_version: str | None,
    catalog_released: str | None = None,
) -> int:
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
        extend_kev_context(session, vuln, kev.required_action, kev.due_date, kev.ransomware_use)
        if catalog_released:
            vuln.kev_catalog_released = catalog_released
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


def extend_kev_context(
    session: Session,
    vuln: Vulnerability,
    required_action: str | None,
    due_date: str | None,
    ransomware_use: str | None,
) -> None:
    """Keep the extra CISA KEV fields on the canonical row.

    Fill-on-write: a later feed omitting a field never erases a previously
    stored value (CISA does not publish per-field deletions).
    """
    if required_action:
        vuln.kev_required_action = required_action
    if due_date:
        vuln.kev_due_date = due_date
    if ransomware_use:
        vuln.kev_ransomware_use = ransomware_use


def sync_cisa_kev(session: Session, s: Settings) -> int:
    """Fetch and upsert the full KEV catalog. Raises on fetch/parse failure."""
    from .http import fetch

    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        resp = fetch(
            client, s.cisa_kev_url, retries=s.http_retries,
            timeout=s.http_timeout_seconds, backoff=s.http_retry_backoff_seconds,
        )
        entries, version, released = cisa_kev.parse_catalog(resp.json())
        return ingest_kev_catalog(session, entries, version, released)


# --- FIRST EPSS ingestion -----------------------------------------------------

@dataclass
class EpssSyncResult:
    score_date: date | None = None
    matched: int = 0
    history_written: int = 0
    unknown_cves: int = 0
    skipped_rows: int = 0
    up_to_date: bool = False


def _vuln_id_map(session: Session, vuln_ids: set[str]) -> dict[str, int]:
    """Map canonical CVE id -> canonical vulnerability id (existing rows only)."""
    out: dict[str, int] = {}
    wanted = sorted(vuln_ids)
    for start in range(0, len(wanted), _LOOKUP_CHUNK):
        chunk = wanted[start : start + _LOOKUP_CHUNK]
        rows = session.execute(
            select(Vulnerability.id, Vulnerability.vuln_id).where(
                Vulnerability.vuln_id.in_(chunk)
            )
        ).all()
        out.update({vuln_id: vid for vid, vuln_id in rows})
    return out


def ingest_epss_scores(
    session: Session, feed: epss.EpssFeed, source_url: str
) -> EpssSyncResult:
    """Apply one parsed EPSS bulk feed to the canonical vulnerabilities.

    - only CVEs already present canonically are stored (no full mirror of the
      EPSS population, and no new canonical records are created);
    - the current `epss_scores` row is updated in place (score date from the
      file's meta header, which is authoritative for the whole bulk file);
    - one `epss_history` snapshot per CVE per score date (unique), updated in
      place when the same date is re-imported.

    Committing is left to the caller so this composes with the sync state flow.
    """
    now = utcnow()
    result = EpssSyncResult(
        score_date=feed.score_date,
        skipped_rows=feed.skipped_rows,
    )
    by_id = {e.vuln_id: e for e in feed.entries}
    vuln_ids = _vuln_id_map(session, set(by_id))
    result.unknown_cves = len(by_id) - len(vuln_ids)
    if not vuln_ids:
        return result

    matched_ids = list(vuln_ids.values())
    current_rows: dict[int, EpssScore] = {}
    for start in range(0, len(matched_ids), _LOOKUP_CHUNK):
        chunk = matched_ids[start : start + _LOOKUP_CHUNK]
        rows = session.execute(
            select(EpssScore).where(EpssScore.vulnerability_id.in_(chunk))
        ).scalars().all()
        current_rows.update({row.vulnerability_id: row for row in rows})
    hist_rows = session.execute(
        select(EpssHistory).where(
            EpssHistory.vulnerability_id.in_(matched_ids),
            EpssHistory.score_date == feed.score_date,
        )
    ).scalars().all()
    hist_by_vid = {row.vulnerability_id: row for row in hist_rows}

    for entry in feed.entries:
        vid = vuln_ids.get(entry.vuln_id)
        if vid is None:
            continue
        # the bulk feed's meta-line score date is authoritative for the whole
        # file (FIRST stamps every row with it); use it consistently for both
        # the current row and history so they can never disagree
        cur = current_rows.get(vid)
        if cur is not None:
            cur.source = epss.SOURCE
            cur.source_url = safe_url(source_url)
            cur.score = entry.score
            cur.percentile = entry.percentile
            cur.score_date = feed.score_date
            cur.retrieved_at = now
            cur.model_version = feed.model_version
        else:
            session.add(
                EpssScore(
                    vulnerability_id=vid,
                    source=epss.SOURCE,
                    source_url=safe_url(source_url),
                    score=entry.score,
                    percentile=entry.percentile,
                    score_date=entry.score_date,
                    retrieved_at=now,
                    model_version=feed.model_version,
                )
            )
        result.matched += 1
        hist = hist_by_vid.get(vid)
        if hist is not None:
            hist.source = epss.SOURCE
            hist.source_url = safe_url(source_url)
            hist.score = entry.score
            hist.percentile = entry.percentile
            hist.retrieved_at = now
            hist.model_version = feed.model_version
        else:
            session.add(
                EpssHistory(
                    vulnerability_id=vid,
                    source=epss.SOURCE,
                    source_url=safe_url(source_url),
                    score=entry.score,
                    percentile=entry.percentile,
                    score_date=feed.score_date,
                    retrieved_at=now,
                    model_version=feed.model_version,
                )
            )
            result.history_written += 1
    return result


def sync_epss(session: Session, s: Settings) -> EpssSyncResult:
    """Daily bulk EPSS sync with its own checkpoint (score_date).

    The checkpoint advances only after a successful apply; a failed or
    malformed fetch raises so _mark_error keeps the last good EPSS values and
    the checkpoint untouched. When the checkpoint already matches today's
    date, the bulk download is skipped (the feed publishes once per day).

    A full re-import of the same day's file is possible by clearing the
    checkpoint (`UPDATE sync_state SET checkpoint = NULL WHERE source =
    'first_epss'`) and triggering a sync; the upsert is idempotent.
    """
    from .http import fetch

    state = _sync_state(session, epss.SOURCE)
    checkpoint = state.checkpoint or {}
    checkpoint_score_date = checkpoint_date(checkpoint)
    today = datetime.now(timezone.utc).date()
    if checkpoint_score_date == today:
        log.info("EPSS already synced for %s; skipping bulk download", today)
        return EpssSyncResult(up_to_date=True, score_date=checkpoint_score_date)

    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        resp = fetch(
            client, s.epss_bulk_url, retries=s.http_retries,
            timeout=s.http_timeout_seconds, backoff=s.http_retry_backoff_seconds,
            expect_json=False,
        )
        feed = epss.parse_feed(resp.content)
        result = ingest_epss_scores(session, feed, s.epss_bulk_url)
        state.checkpoint = {"score_date": feed.score_date.isoformat()}
        session.commit()
    log.info(
        "EPSS sync %s: %d stored, %d new history snapshots, "
        "%d not-yet-known CVEs skipped, %d rows skipped as malformed",
        result.score_date,
        result.matched, result.history_written, result.unknown_cves, result.skipped_rows,
    )
    return result


def checkpoint_date(checkpoint: dict | None) -> date | None:
    raw = (checkpoint or {}).get("score_date")
    if not raw:
        return None
    try:
        return date.fromisoformat(str(raw))
    except ValueError:
        return None


# --- extended sources ---------------------------------------------------------
#
# Ingestion policies per source (enrichment-only = never creates canonical
# rows; evidence attaches only to CVEs already present):
#
#   canonical-creating: nvd, github_advisory, redhat, ubuntu
#   enrichment-only:    osv_dev, exploit_db, metasploit, nuclei,
#                       poc_in_github, debian_tracker, cisa_advisories
#   key-gated:          threatfox (THREATFOX_AUTH_KEY), vulners (VULNERS_API_KEY)
#
# Every source keeps its own checkpoint (JSON on sync_state) including
# last_run_ts, and is re-synced at most every SOURCE_MIN_INTERVALS entry.

# Minimum wall-clock seconds between two runs of each extended source.
SOURCE_MIN_INTERVALS = {
    "nvd": 3600,
    "github_advisory": 3600,
    "osv_dev": 86400,
    "exploit_db": 86400,
    "metasploit": 86400,
    "nuclei": 86400,
    "poc_in_github": 3600,
    "redhat": 21600,
    "debian_tracker": 86400,
    "ubuntu": 21600,
    "cisa_advisories": 21600,
    "threatfox": 21600,
    "vulners": 86400,
}


def _interval_due(session: Session, source: str) -> bool:
    """True when the source's minimum re-sync interval has elapsed."""
    state = _sync_state(session, source)
    last = parse_datetime((state.checkpoint or {}).get("last_run_ts"))
    interval = SOURCE_MIN_INTERVALS.get(source, 3600)
    if last is None:
        return True
    return (utcnow() - last).total_seconds() >= interval


def _touch_run_ts(state: SyncState, checkpoint: dict | None) -> dict:
    """Merge last_run_ts into a source checkpoint (interval bookkeeping)."""
    out = dict(checkpoint or {})
    out["last_run_ts"] = _iso(utcnow())
    state.checkpoint = out
    return out


def _merge_list_payload(
    session: Session, vuln: Vulnerability, source: str, source_url: str,
    kind: str, items: list[dict], now: datetime, cap: int = 50,
) -> None:
    """Store a merged one-record-per-CVE payload for repeat-entry sources."""
    existing = session.execute(
        select(SourceRecord).where(
            SourceRecord.source == source, SourceRecord.vuln_id == vuln.vuln_id
        )
    ).scalar_one_or_none()
    if existing is None:
        rec = SourceRecord(
            vulnerability_id=vuln.id, source=source, vuln_id=vuln.vuln_id,
            source_url=safe_url(source_url), first_synced_at=now,
        )
        session.add(rec)
    else:
        rec = existing
    prior = (rec.data or {}).get("items") if isinstance(rec.data, dict) else None
    merged = list(prior or []) + items
    seen = set()
    unique: list[dict] = []
    for item in merged:
        key = repr(item.get("url") or item.get("edbId") or item.get("module") or item)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
        if len(unique) >= cap:
            break
    rec.data = {"kind": kind, "items": unique, "count": len(unique)}
    rec.last_synced_at = now


def sync_nvd(session: Session, s: Settings) -> dict:
    """Incremental NVD sync by lastMod window; attributed CVSS + descriptions."""
    from .http import fetch

    state = _sync_state(session, nvd.SOURCE)
    checkpoint = state.checkpoint or {}
    last_run = parse_datetime(checkpoint.get("last_run_ts"))
    now = utcnow()
    end = now - timedelta(minutes=5)
    if last_run is not None:
        start = max(last_run - timedelta(hours=1), end - timedelta(days=119))
    else:
        start = end - timedelta(days=7)
    if start >= end:
        return {"status": "skipped", "reason": "no modification window"}

    headers = {"User-Agent": "VulnWatch/0.1"}
    if s.nvd_api_key:
        headers["apiKey"] = s.nvd_api_key
    records = 0
    with httpx.Client(headers=headers, follow_redirects=True) as client:
        start_index = 0
        for _page in range(s.nvd_max_pages_per_run):
            url = (
                f"{s.nvd_api_url}?lastModStartDate={nvd.nvd_window_format(start)}"
                f"&lastModEndDate={nvd.nvd_window_format(end)}"
                f"&resultsPerPage=2000&startIndex={start_index}"
            )
            resp = fetch(
                client, url, retries=s.http_retries,
                timeout=s.http_timeout_seconds, backoff=s.http_retry_backoff_seconds,
            )
            page = resp.json()
            entries = nvd.parse_nvd_page(page)
            if not entries:
                break
            ingest_nvd_entries(session, entries)
            records += len(entries)
            session.commit()
            if len(entries) < 2000:
                break
            start_index += 2000
            time.sleep(s.nvd_page_pause_seconds)
    _touch_run_ts(state, checkpoint)
    return {"status": "success", "records": records}


def ingest_nvd_entries(session: Session, entries: list[nvd.NvdEntry]) -> int:
    now = utcnow()
    for e in entries:
        vuln, _created = get_or_create_vuln(session, e.vuln_id, now)
        if not vuln.title and e.title:
            vuln.title = e.title
        if not vuln.summary and e.summary:
            vuln.summary = e.summary
            vuln.summary_source = "nvd"
        if e.published:
            pub = parse_datetime(e.published) or _parse_nvd_dt(e.published)
            if pub and not vuln.published_at:
                vuln.published_at = pub
        if e.last_modified:
            mod = _parse_nvd_dt(e.last_modified)
            if mod and _newer_than(mod, vuln.last_updated_at):
                vuln.last_updated_at = mod
        # NVD can list multiple metrics per version (Primary + Secondary);
        # CvssScore is unique per (vuln, source, version), so keep one per
        # version — Primary first, otherwise the first-seen metric.
        seen_pairs: set[tuple[str, str]] = set()
        ordered = sorted(e.metrics, key=lambda m: 0 if m.metric_type == "Primary" else 1)
        for m in ordered:
            pair = (e.vuln_id, m.version)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            upsert_cvss(
                session, vuln, "nvd", m.version, m.score,
                m.vector or None,
            )
        upsert_source_record(
            session, vuln, "nvd",
            f"https://nvd.nist.gov/vuln/detail/{e.vuln_id}",
            {
                "kind": "nvd-cve",
                "published": e.published,
                "lastModified": e.last_modified,
                "references": e.references,
                "metricSources": [
                    {"version": m.version, "source": m.metric_source, "type": m.metric_type}
                    for m in e.metrics
                ],
            },
            now,
        )
    return len(entries)


def _parse_nvd_dt(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _newer_than(mod: datetime, existing: datetime | None) -> bool:
    """TZ-aware vs possibly-naive (SQLite) stored datetime comparison."""
    if existing is None:
        return True
    if existing.tzinfo is None:
        mod = mod.replace(tzinfo=None)
    return mod > existing


def sync_github_advisory(session: Session, s: Settings) -> dict:
    """Incremental GitHub advisories sync by modified=>date."""
    from .http import fetch

    state = _sync_state(session, github_advisory.SOURCE)
    checkpoint = state.checkpoint or {}
    since = checkpoint.get("last_modified") or _iso(utcnow())[:10]
    headers = {
        "User-Agent": "VulnWatch/0.1",
        "Accept": "application/vnd.github+json",
    }
    if s.github_token:
        headers["Authorization"] = f"Bearer {s.github_token}"
    records = 0
    newest = since
    with httpx.Client(headers=headers, follow_redirects=True) as client:
        for page_no in range(1, s.gh_adv_max_pages_per_run + 1):
            url = (
                f"{s.github_advisory_url}?modified=%3E{since}"
                f"&per_page=100&page={page_no}"
            )
            resp = fetch(
                client, url, retries=s.http_retries,
                timeout=s.http_timeout_seconds, backoff=s.http_retry_backoff_seconds,
            )
            advisories = github_advisory.parse_advisories(resp.json())
            if not advisories:
                break
            records += ingest_github_advisories(session, advisories)
            for adv in advisories:
                if adv.updated_at and adv.updated_at > newest:
                    newest = adv.updated_at
            session.commit()
            if len(advisories) < 100:
                break
    checkpoint = _touch_run_ts(state, checkpoint)
    checkpoint["last_modified"] = newest
    state.checkpoint = checkpoint
    return {"status": "success", "records": records}


def ingest_github_advisories(
    session: Session, advisories: list[github_advisory.GithubAdvisory]
) -> int:
    now = utcnow()
    for adv in advisories:
        if not adv.vuln_id:
            continue
        vuln, _created = get_or_create_vuln(session, adv.vuln_id, now)
        if not vuln.title and adv.summary:
            vuln.title = adv.summary[:200]
        if not vuln.summary and (adv.description or adv.summary):
            vuln.summary = adv.description or adv.summary
            vuln.summary_source = "github_advisory"
        if adv.cvss_score is not None:
            upsert_cvss(
                session, vuln, "github_advisory",
                vector_version(adv.cvss_vector), adv.cvss_score, adv.cvss_vector,
            )
        existing_pairs = {
            (ap.vendor.lower(), ap.product.lower(), ap.source)
            for ap in vuln.affected_products
        }
        for v in adv.vulnerabilities:
            ecosystem = (v.get("ecosystem") or "").strip()
            package = (v.get("package") or "").strip()
            if not package:
                continue
            key = (ecosystem.lower(), package.lower(), "github_advisory")
            if key in existing_pairs:
                continue
            existing_pairs.add(key)
            session.add(
                AffectedProduct(
                    vulnerability_id=vuln.id,
                    vendor=ecosystem[:200],
                    product=package.lower()[:200],
                    versions=[v["range"]] if v.get("range") else None,
                    fixes=[v["firstPatched"]] if v.get("firstPatched") else None,
                    source="github_advisory",
                )
            )
        upsert_source_record(
            session, vuln, "github_advisory",
            github_advisory.advisory_data(adv)["url"],
            github_advisory.advisory_data(adv),
            now,
        )
    return len(advisories)


def sync_osv_dev(session: Session, s: Settings) -> dict:
    """Enrich canonical CVEs having a GHSA (from github_advisory) with OSV data."""
    state = _sync_state(session, osv_dev.SOURCE)
    checkpoint = state.checkpoint or {}
    ghsa_rows = session.execute(
        select(SourceRecord)
        .where(
            SourceRecord.source == "github_advisory",
            ~SourceRecord.vuln_id.in_(
                select(SourceRecord.vuln_id).where(SourceRecord.source == osv_dev.SOURCE)
            ),
        )
        .limit(s.osv_max_per_run)
    ).scalars().all()
    records = 0
    if ghsa_rows:
        now = utcnow()
        with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
            for row in ghsa_rows:
                ghsa_id = (row.data or {}).get("ghsaId") if isinstance(row.data, dict) else None
                if not ghsa_id:
                    continue
                try:
                    adv = osv_dev.fetch_osv_record(
                        client, s.osv_api_url, ghsa_id, s.http_timeout_seconds
                    )
                except Exception as exc:  # noqa: BLE001 - one miss must not stop the batch
                    log.warning("OSV fetch failed for %s: %r", ghsa_id, exc)
                    continue
                if adv is None:
                    continue
                vuln = session.execute(
                    select(Vulnerability).where(Vulnerability.vuln_id == row.vuln_id)
                ).scalar_one_or_none()
                if vuln is None:
                    continue
                upsert_source_record(
                    session, vuln, osv_dev.SOURCE,
                    osv_dev.osv_data(adv)["url"], osv_dev.osv_data(adv), now,
                )
                records += 1
            session.commit()
    _touch_run_ts(state, checkpoint)
    return {"status": "success", "records": records}


def sync_exploit_db(session: Session, s: Settings) -> dict:
    """Enrichment-only bulk sync of Exploit-DB PoC availability."""
    from .http import fetch

    state = _sync_state(session, exploit_db.SOURCE)
    checkpoint = state.checkpoint or {}
    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        resp = fetch(
            client, s.exploit_db_url, retries=s.http_retries,
            timeout=max(s.http_timeout_seconds, 60.0),
            backoff=s.http_retry_backoff_seconds, expect_json=False,
        )
        entries = exploit_db.parse_exploits_csv(resp.content.decode("utf-8", "replace"))
    by_cve: dict[str, list[exploit_db.ExploitDbEntry]] = {}
    for e in entries:
        by_cve.setdefault(e.vuln_id, []).append(e)
    known = _vuln_id_map(session, set(by_cve))
    now = utcnow()
    for vuln_id, vid in known.items():
        vuln = session.get(Vulnerability, vid)
        if vuln is None:
            continue
        _merge_list_payload(
            session, vuln, exploit_db.SOURCE,
            exploit_db.DETAIL_URL.format(edb_id=by_cve[vuln_id][0].edb_id),
            "exploit-db-entry",
            [exploit_db.exploit_data(e) for e in by_cve[vuln_id]],
            now,
        )
    session.commit()
    _touch_run_ts(state, checkpoint)
    return {"status": "success", "records": len(known)}


def sync_metasploit(session: Session, s: Settings) -> dict:
    """Enrichment-only bulk sync of Metasploit exploit-module availability."""
    from .http import fetch

    state = _sync_state(session, metasploit.SOURCE)
    checkpoint = state.checkpoint or {}
    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        resp = fetch(
            client, s.metasploit_url, retries=s.http_retries,
            timeout=max(s.http_timeout_seconds, 60.0),
            backoff=s.http_retry_backoff_seconds,
        )
        modules = metasploit.parse_modules(resp.json())
    by_cve: dict[str, list[metasploit.MetasploitModule]] = {}
    for m in modules:
        for cve in m.cves:
            by_cve.setdefault(cve, []).append(m)
    known = _vuln_id_map(session, set(by_cve))
    now = utcnow()
    for vuln_id, vid in known.items():
        vuln = session.get(Vulnerability, vid)
        if vuln is None:
            continue
        _merge_list_payload(
            session, vuln, metasploit.SOURCE,
            metasploit.module_data(by_cve[vuln_id][0])["url"],
            "metasploit-module",
            [metasploit.module_data(m) for m in by_cve[vuln_id]],
            now,
        )
    session.commit()
    _touch_run_ts(state, checkpoint)
    return {"status": "success", "records": len(known)}


def sync_nuclei(session: Session, s: Settings) -> dict:
    """Enrichment-only sync of nuclei detection-template coverage."""
    from .http import fetch

    state = _sync_state(session, nuclei.SOURCE)
    checkpoint = state.checkpoint or {}
    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        resp = fetch(
            client, s.nuclei_tree_url, retries=s.http_retries,
            timeout=max(s.http_timeout_seconds, 60.0),
            backoff=s.http_retry_backoff_seconds,
        )
        by_cve = nuclei.parse_tree(resp.json())
    known = _vuln_id_map(session, set(by_cve))
    now = utcnow()
    for vuln_id, vid in known.items():
        vuln = session.get(Vulnerability, vid)
        if vuln is None:
            continue
        upsert_source_record(
            session, vuln, nuclei.SOURCE,
            nuclei.nuclei_data(by_cve[vuln_id])["url"],
            nuclei.nuclei_data(by_cve[vuln_id]),
            now,
        )
    session.commit()
    _touch_run_ts(state, checkpoint)
    return {"status": "success", "records": len(known)}


def sync_poc_in_github(session: Session, s: Settings) -> dict:
    """On-demand PoC-in-GitHub fetch for newest canonical CVEs lacking a record."""
    state = _sync_state(session, poc_in_github.SOURCE)
    checkpoint = state.checkpoint or {}
    targets = session.execute(
        select(Vulnerability)
        .where(
            Vulnerability.vuln_id.like("CVE-%"),
            ~Vulnerability.vuln_id.in_(
                select(SourceRecord.vuln_id).where(
                    SourceRecord.source == poc_in_github.SOURCE
                )
            ),
        )
        .order_by(Vulnerability.updated_at.desc())
        .limit(s.poc_max_per_run)
    ).scalars().all()
    records = 0
    if targets:
        now = utcnow()
        with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
            for vuln in targets:
                try:
                    repos = poc_in_github.fetch_poc_file(
                        client, s.poc_base_url, vuln.vuln_id, s.http_timeout_seconds
                    )
                except Exception as exc:  # noqa: BLE001 - bounded per-CVE failures
                    log.warning("PoC fetch failed for %s: %r", vuln.vuln_id, exc)
                    continue
                if not repos:
                    continue
                url = poc_in_github.cve_file_url(s.poc_base_url, vuln.vuln_id)
                _merge_list_payload(
                    session, vuln, poc_in_github.SOURCE, url, "poc-in-github",
                    repos, now,
                )
                records += 1
            session.commit()
    _touch_run_ts(state, checkpoint)
    return {"status": "success", "records": records}


def sync_redhat(session: Session, s: Settings) -> dict:
    """Incremental Red Hat security-data sync by `after` date."""
    from .http import fetch

    state = _sync_state(session, redhat.SOURCE)
    checkpoint = state.checkpoint or {}
    after = checkpoint.get("after") or _iso(utcnow())[:10]
    records = 0
    newest_date = after
    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        for page_no in range(1, s.redhat_max_pages_per_run + 1):
            url = f"{s.redhat_securitydata_url}?after={after}&per_page=100&page={page_no}"
            resp = fetch(
                client, url, retries=s.http_retries,
                timeout=s.http_timeout_seconds, backoff=s.http_retry_backoff_seconds,
            )
            rows = redhat.parse_cve_rows(resp.json())
            if not rows:
                break
            records += ingest_redhat_rows(session, rows)
            for row in rows:
                day = (row.public_date or "")[:10]
                if day and day > newest_date:
                    newest_date = day
            session.commit()
            if len(rows) < 100:
                break
    checkpoint = _touch_run_ts(state, checkpoint)
    checkpoint["after"] = newest_date
    state.checkpoint = checkpoint
    return {"status": "success", "records": records}


def ingest_redhat_rows(session: Session, rows: list[redhat.RedhatCve]) -> int:
    now = utcnow()
    for row in rows:
        vuln, _created = get_or_create_vuln(session, row.vuln_id, now)
        if not vuln.title and row.description:
            vuln.title = row.description[:200]
        if row.cvss3_score is not None:
            upsert_cvss(
                session, vuln, "redhat", vector_version(row.cvss3_vector),
                row.cvss3_score, row.cvss3_vector,
            )
        existing_pairs = {
            (ap.vendor.lower(), ap.product.lower(), ap.source)
            for ap in vuln.affected_products
        }
        for rel in row.affected_release:
            package = (rel.get("package") or "").strip()
            if not package:
                continue
            name, _sep, version = package.partition("-0:")
            key = ("red hat", name.lower(), "redhat")
            if key in existing_pairs:
                continue
            existing_pairs.add(key)
            session.add(
                AffectedProduct(
                    vulnerability_id=vuln.id,
                    vendor="Red Hat",
                    product=name.lower()[:200],
                    versions=[package] if package else None,
                    fixes=[version] if version else None,
                    source="redhat",
                )
            )
        upsert_source_record(
            session, vuln, "redhat",
            redhat.redhat_data(row)["url"], redhat.redhat_data(row), now,
        )
    return len(rows)


def sync_debian_tracker(session: Session, s: Settings) -> dict:
    """Enrichment-only daily sync of the Debian security tracker JSON export."""
    from .http import fetch

    state = _sync_state(session, debian_tracker.SOURCE)
    checkpoint = state.checkpoint or {}
    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        resp = fetch(
            client, s.debian_tracker_url, retries=s.http_retries,
            timeout=max(s.http_timeout_seconds, 120.0),
            backoff=s.http_retry_backoff_seconds, expect_json=False,
        )
        tracker = debian_tracker.iter_cve_blocks(resp.json())
    by_cve = dict(tracker)
    # the tracker export has ~270k CVE keys — larger than Postgres' 65535
    # bind-parameter limit — so fetch the (small) canonical table and
    # intersect locally instead of filtering with a huge IN clause
    canonical_rows = [
        (vid, vuln_id)
        for vid, vuln_id in session.execute(
            select(Vulnerability.id, Vulnerability.vuln_id).where(
                Vulnerability.vuln_id.like("CVE-%")
            )
        ).all()
        if vuln_id in by_cve
    ]
    now = utcnow()
    for vid, vuln_id in canonical_rows:
        block = by_cve.get(vuln_id)
        if not isinstance(block, dict):
            continue
        vuln = session.get(Vulnerability, vid)
        if vuln is None:
            continue
        data = debian_tracker.debian_data(vuln_id, block)
        upsert_source_record(
            session, vuln, debian_tracker.SOURCE, data["url"], data, now,
        )
        existing_pairs = {
            (ap.vendor.lower(), ap.product.lower(), ap.source)
            for ap in vuln.affected_products
        }
        for release, packages in (data.get("releases") or {}).items():
            for pkg in packages:
                package = pkg.get("package") or ""
                key = ("debian", package.lower(), "debian_tracker")
                if not package or key in existing_pairs:
                    continue
                existing_pairs.add(key)
                session.add(
                    AffectedProduct(
                        vulnerability_id=vuln.id,
                        vendor="Debian",
                        product=package.lower()[:200],
                        versions=[release],
                        fixes=[pkg["fixed"]] if pkg.get("fixed") else None,
                        source="debian_tracker",
                    )
                )
    session.commit()
    _touch_run_ts(state, checkpoint)
    return {"status": "success", "records": len(canonical_rows)}


def sync_ubuntu(session: Session, s: Settings) -> dict:
    """Incremental Ubuntu CVE tracker sync by modified_since date."""
    from .http import fetch

    state = _sync_state(session, ubuntu.SOURCE)
    checkpoint = state.checkpoint or {}
    since = checkpoint.get("modified_since") or (_iso(utcnow())[:10])
    records = 0
    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        for page_no in range(1, s.ubuntu_max_pages_per_run + 1):
            url = f"{s.ubuntu_api_url}?page_size=100&page={page_no}&modified_since={since}"
            resp = fetch(
                client, url, retries=s.http_retries,
                timeout=s.http_timeout_seconds, backoff=s.http_retry_backoff_seconds,
            )
            entries = ubuntu.parse_cve_list(resp.json())
            if not entries:
                break
            records += ingest_ubuntu_entries(session, entries)
            session.commit()
            if len(entries) < 100:
                break
    checkpoint = _touch_run_ts(state, checkpoint)
    # overlap one day to keep intra-day modifications from being missed
    checkpoint["modified_since"] = (
        datetime.now(timezone.utc) - timedelta(days=1)
    ).strftime("%Y-%m-%d")
    state.checkpoint = checkpoint
    return {"status": "success", "records": records}


def ingest_ubuntu_entries(session: Session, entries: list[ubuntu.UbuntuCve]) -> int:
    now = utcnow()
    for e in entries:
        vuln, _created = get_or_create_vuln(session, e.vuln_id, now)
        if not vuln.title and e.description:
            vuln.title = e.description[:200]
        if not vuln.summary and e.description:
            vuln.summary = e.description
            vuln.summary_source = "ubuntu"
        if e.priority and not vuln.stated_severity:
            vuln.stated_severity = e.priority
        existing_pairs = {
            (ap.vendor.lower(), ap.product.lower(), ap.source)
            for ap in vuln.affected_products
        }
        for row in ubuntu.released_fixes(e):
            key = ("ubuntu", row["product"].lower(), "ubuntu")
            if key in existing_pairs:
                continue
            existing_pairs.add(key)
            session.add(
                AffectedProduct(
                    vulnerability_id=vuln.id,
                    vendor="Ubuntu",
                    product=row["product"].lower()[:200],
                    versions=[row["release"]],
                    fixes=row["fixes"],
                    source="ubuntu",
                )
            )
        upsert_source_record(
            session, vuln, "ubuntu",
            ubuntu.ubuntu_data(e)["url"], ubuntu.ubuntu_data(e), now,
        )
    return len(entries)


def sync_cisa_advisories(session: Session, s: Settings) -> dict:
    """Context feed: link CISA advisories to canonical CVEs via CVE mentions."""
    from .http import fetch

    state = _sync_state(session, cisa_advisories.SOURCE)
    checkpoint = state.checkpoint or {}
    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        resp = fetch(
            client, s.cisa_advisories_url, retries=s.http_retries,
            timeout=s.http_timeout_seconds, backoff=s.http_retry_backoff_seconds,
            expect_json=False,
        )
        items = cisa_advisories.parse_rss(resp.content)
    by_cve: dict[str, list[cisa_advisories.AdvisoryItem]] = {}
    for item in items:
        for cve in item.cves:
            by_cve.setdefault(cve, []).append(item)
    known = _vuln_id_map(session, set(by_cve))
    now = utcnow()
    for vuln_id, vid in known.items():
        vuln = session.get(Vulnerability, vid)
        if vuln is None:
            continue
        _merge_list_payload(
            session, vuln, cisa_advisories.SOURCE,
            by_cve[vuln_id][0].url, "cisa-advisory",
            [cisa_advisories.advisory_data(i) for i in by_cve[vuln_id]],
            now,
        )
    session.commit()
    _touch_run_ts(state, checkpoint)
    return {"status": "success", "records": len(known)}


def sync_threatfox(session: Session, s: Settings) -> dict:
    """IOC context feed; requires a free abuse.ch Auth-Key."""
    state = _sync_state(session, threatfox.SOURCE)
    checkpoint = state.checkpoint or {}
    if not s.threatfox_auth_key:
        return {"status": "unconfigured", "reason": "THREATFOX_AUTH_KEY required"}
    with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
        iocs = threatfox.fetch_iocs(
            client, s.threatfox_api_url, s.threatfox_auth_key,
            timeout=s.http_timeout_seconds,
        )
    by_cve: dict[str, list[threatfox.ThreatfoxIoc]] = {}
    for ioc in iocs:
        for cve in threatfox.ioc_cves(ioc):
            by_cve.setdefault(cve, []).append(ioc)
    known = _vuln_id_map(session, set(by_cve))
    now = utcnow()
    for vuln_id, vid in known.items():
        vuln = session.get(Vulnerability, vid)
        if vuln is None:
            continue
        _merge_list_payload(
            session, vuln, threatfox.SOURCE,
            by_cve[vuln_id][0].reference, "threatfox-ioc",
            [threatfox.ioc_data(i) for i in by_cve[vuln_id]],
            now,
        )
    session.commit()
    _touch_run_ts(state, checkpoint)
    return {"status": "success", "records": len(known)}


def sync_vulners(session: Session, s: Settings) -> dict:
    """On-demand Vulners lookups for urgent/high-priority CVEs; API-key gated."""
    state = _sync_state(session, vulners.SOURCE)
    checkpoint = state.checkpoint or {}
    if not s.vulners_api_key:
        return {"status": "unconfigured", "reason": "VULNERS_API_KEY required"}
    targets = session.execute(
        select(Vulnerability)
        .where(
            ~Vulnerability.vuln_id.in_(
                select(SourceRecord.vuln_id).where(SourceRecord.source == vulners.SOURCE)
            ),
            or_(
                Vulnerability.is_kev.is_(True),
                Vulnerability.stated_severity.in_(["critical", "high"]),
                Vulnerability.id.in_(
                    select(CvssScore.vulnerability_id).where(CvssScore.score >= 7.0)
                ),
            ),
        )
        .order_by(Vulnerability.is_kev.desc(), Vulnerability.updated_at.desc())
        .limit(s.vulners_max_per_run)
    ).scalars().all()
    records = 0
    if targets:
        now = utcnow()
        with httpx.Client(headers={"User-Agent": "VulnWatch/0.1"}, follow_redirects=True) as client:
            for vuln in targets:
                try:
                    rec = vulners.fetch_lookup(
                        client, s.vulners_api_url, vuln.vuln_id,
                        s.vulners_api_key, s.http_timeout_seconds,
                    )
                except Exception as exc:  # noqa: BLE001 - one miss must not stop the batch
                    log.warning("Vulners lookup failed for %s: %r", vuln.vuln_id, exc)
                    continue
                if rec is None:
                    continue
                data = vulners.vulners_data(rec)
                upsert_source_record(
                    session, vuln, vulners.SOURCE, data["url"], data, now,
                )
                if rec.cvss_score is not None:
                    upsert_cvss(
                        session, vuln, "vulners",
                        vector_version(rec.cvss_vector), rec.cvss_score, rec.cvss_vector,
                    )
                records += 1
            session.commit()
    _touch_run_ts(state, checkpoint)
    return {"status": "success", "records": records}


_EXTENDED_SYNC = {
    "nvd": sync_nvd,
    "github_advisory": sync_github_advisory,
    "osv_dev": sync_osv_dev,
    "exploit_db": sync_exploit_db,
    "metasploit": sync_metasploit,
    "nuclei": sync_nuclei,
    "poc_in_github": sync_poc_in_github,
    "redhat": sync_redhat,
    "debian_tracker": sync_debian_tracker,
    "ubuntu": sync_ubuntu,
    "cisa_advisories": sync_cisa_advisories,
    "threatfox": sync_threatfox,
    "vulners": sync_vulners,
}


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
        # minimum re-sync interval (extended sources); a skip is a clean no-op
        if source in SOURCE_MIN_INTERVALS:
            with session_factory() as probe:
                if not _interval_due(probe, source):
                    results[source] = {"status": "skipped", "reason": "interval"}
                    continue
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
                elif source == "first_epss":
                    r = sync_epss(session, s)
                    _mark_success(session, source, r.matched)
                    results[source] = {
                        "status": "success",
                        "records": r.matched,
                        "score_date": r.score_date.isoformat() if r.score_date else None,
                        "history_written": r.history_written,
                        "unknown_cves": r.unknown_cves,
                        "skipped_rows": r.skipped_rows,
                        "up_to_date": r.up_to_date,
                    }
                elif source in _EXTENDED_SYNC:
                    r = _EXTENDED_SYNC[source](session, s)
                    status = r.get("status", "success")
                    if status == "unconfigured":
                        # leave the source in never_run until a key is provided
                        st = _sync_state(session, source)
                        st.status = "never_run"
                        st.error_message = None
                        session.commit()
                        results[source] = r
                    else:
                        _mark_success(session, source, r.get("records", 0))
                        results[source] = r
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

