"""Serialization helpers for API responses. Missing data renders as None; the
frontend displays 'Unknown'."""

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .models import (
    AffectedProduct,
    CvssScore,
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


def vuln_list_item(
    session: Session, vuln: Vulnerability, match_by_vid: dict[int, list[dict]]
) -> dict[str, Any]:
    score = best_score(vuln)
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
        "kev": vuln.is_kev,
        "kev_date_added": vuln.kev_date_added,
        "watchlist_matches": matches,
        "watchlist_match_type": strongest,
    }


def vuln_detail(session: Session, vuln: Vulnerability) -> dict[str, Any]:
    match_map = _match_info(session, [vuln.id])
    base = vuln_list_item(session, vuln, match_map)
    base["summary"] = vuln.summary
    base["summary_source"] = vuln.summary_source
    base["last_updated_at"] = _iso(vuln.last_updated_at)
    base["created_at"] = _iso(vuln.created_at)
    base["records_collected_at"] = _iso(vuln.created_at)
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
