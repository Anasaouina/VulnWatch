"""Serialization helpers for API responses. Missing data renders as None; the
frontend displays 'Unknown'.

The priority is a VulnWatch assessment computed transparently from the
individually exposed signals (see app/priority.py); reasons accompany every
response so nothing is hidden behind a single number.
"""

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from . import priority as priority_mod
from .config import settings
from .models import (
    AffectedProduct,
    CvssScore,
    EpssHistory,
    EpssScore,
    SourceRecord,
    Vulnerability,
    WatchlistMatch,
)
from .normalize import severity_bucket


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def best_score(vuln: Vulnerability) -> CvssScore | None:
    scores = [s for s in vuln.cvss_scores]
    if not scores:
        return None
    # highest score as the headline; full attribution kept alongside
    return max(scores, key=lambda s: s.score)


def _match_info(session: Session, vuln_ids: list[int]) -> dict[int, list[dict]]:
    if not vuln_ids:
        return {}
    rows = session.execute(
        select(WatchlistMatch)
        .options(selectinload(WatchlistMatch.item))
        .where(WatchlistMatch.vulnerability_id.in_(vuln_ids))
    ).scalars().all()
    out: dict[int, list[dict]] = {}
    for m in rows:
        out.setdefault(m.vulnerability_id, []).append(
            {
                "item_id": m.watchlist_item_id,
                "name": m.item.name,
                "match_type": m.match_type,
                "matched_term": m.matched_term,
            }
        )
    return out


# display order for the per-CVE source tags in the UI
_SOURCE_ORDER = {
    s: i for i, s in enumerate(
        (
            "cve_now", "cisa_kev", "nvd", "github_advisory", "osv_dev",
            "first_epss", "redhat", "debian_tracker", "ubuntu",
            "exploit_db", "metasploit", "nuclei", "poc_in_github",
            "cisa_advisories", "threatfox", "vulners",
        )
    )
}


def _source_tags(vuln: Vulnerability) -> list[str]:
    """Distinct source names having a record for this CVE (ordered, UI-ready).

    first_epss is included when the CVE carries an EPSS score so the tag row
    shows every signal source, even though EPSS stores no SourceRecord.
    """
    tags = {r.source for r in vuln.source_records}
    if getattr(vuln, "epss", None) is not None:
        tags.add("first_epss")
    return sorted(tags, key=lambda s: _SOURCE_ORDER.get(s, 99))


def _signals(vuln: Vulnerability) -> dict[str, Any]:
    """CVSS / EPSS / KEV signals shared between the list and detail views."""
    score = best_score(vuln)
    epss_row: EpssScore | None = getattr(vuln, "epss", None)
    return {
        "score": score,
        "epss": epss_row,
        "priority": priority_mod.compute_priority(
            cvss_score=score.score if score else None,
            stated_severity=vuln.stated_severity,
            epss_score=epss_row.score if epss_row else None,
            is_kev=vuln.is_kev,
            high_threshold=settings.priority_epss_high,
            elevated_threshold=settings.priority_epss_elevated,
        ),
    }


def vuln_list_item(
    session: Session, vuln: Vulnerability, match_by_vid: dict[int, list[dict]]
) -> dict[str, Any]:
    sig = _signals(vuln)
    score = sig["score"]
    epss_row = sig["epss"]
    prio, _reasons = sig["priority"]
    bucket = severity_bucket(score.score if score else None, vuln.stated_severity)
    matches = match_by_vid.get(vuln.id, [])
    strongest = "structured" if any(m["match_type"] == "structured" for m in matches) else (
        "keyword" if matches else None
    )
    return {
        "vuln_id": vuln.vuln_id,
        "title": vuln.title,
        "published_at": _iso(vuln.published_at),
        "first_seen_at": _iso(vuln.first_seen_at),
        "severity_bucket": bucket,
        "cvss_score": score.score if score else None,
        "cvss_source": score.source if score else None,
        "cvss_version": score.version if score else None,
        "stated_severity": vuln.stated_severity,
        "epss_score": epss_row.score if epss_row else None,
        "epss_percentile": epss_row.percentile if epss_row else None,
        "epss_score_date": (
            epss_row.score_date.isoformat() if epss_row and epss_row.score_date else None
        ),
        "kev": vuln.is_kev,
        "kev_date_added": vuln.kev_date_added,
        "kev_ransomware_use": vuln.kev_ransomware_use,
        "priority": prio,
        # VulnWatch assessment disclaimer accompanies the computed label
        "priority_note": priority_mod.priority_reason_preamble(),
        "sources": _source_tags(vuln),
        "watchlist_matches": matches,
        "watchlist_match_type": strongest,
    }


def vuln_detail(session: Session, vuln: Vulnerability) -> dict[str, Any]:
    match_map = _match_info(session, [vuln.id])
    base = vuln_list_item(session, vuln, match_map)
    sig = _signals(vuln)
    epss_row = sig["epss"]
    prio_reasons = sig["priority"][1]
    base["summary"] = vuln.summary
    base["summary_source"] = vuln.summary_source
    base["last_updated_at"] = _iso(vuln.last_updated_at)
    base["created_at"] = _iso(vuln.created_at)
    base["records_collected_at"] = _iso(vuln.created_at)
    base["priority_reasons"] = prio_reasons
    base["kev_required_action"] = vuln.kev_required_action
    base["kev_due_date"] = vuln.kev_due_date
    base["kev_catalog_released"] = vuln.kev_catalog_released
    if epss_row:
        base["epss_retrieved_at"] = _iso(epss_row.retrieved_at)
        base["epss_source"] = epss_row.source
        base["epss_source_url"] = epss_row.source_url
        base["epss_model_version"] = epss_row.model_version
    else:
        base["epss_retrieved_at"] = None
        base["epss_source"] = None
        base["epss_source_url"] = None
        base["epss_model_version"] = None
    history = session.execute(
        select(EpssHistory)
        .where(EpssHistory.vulnerability_id == vuln.id)
        .order_by(EpssHistory.score_date.desc())
        .limit(60)
    ).scalars().all()
    base["epss_history"] = [
        {
            "score_date": h.score_date.isoformat() if h.score_date else None,
            "score": h.score,
            "percentile": h.percentile,
            "retrieved_at": _iso(h.retrieved_at),
            "source": h.source,
            "source_url": h.source_url,
            "model_version": h.model_version,
        }
        for h in history
    ]
    base["cvss_scores"] = [
        {
            "score": s.score,
            "version": s.version,
            "source": s.source,
            "vector": s.vector,
        }
        for s in vuln.cvss_scores
    ]
    base["affected_products"] = [
        {
            "vendor": a.vendor,
            "product": a.product,
            "versions": a.versions,
            "fixes": a.fixes,
            "source": a.source,
        }
        for a in vuln.affected_products
    ]
    base["source_records"] = [
        {
            "source": r.source,
            "vuln_id": r.vuln_id,
            "url": r.source_url,
            "first_synced_at": _iso(r.first_synced_at),
            "last_synced_at": _iso(r.last_synced_at),
            "data": r.data,
        }
        for r in vuln.source_records
    ]
    return base
