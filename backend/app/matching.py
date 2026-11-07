"""Watchlist matching.

A watchlist match means the product name/keyword appears in stored data. It is
NOT proof that a deployed system is affected.

- "structured": the term matched vendor/product data the source provided
  (cve.now `product` field or per-entry `affected[]` data).
- "keyword": the term matched title or summary text.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    AffectedProduct,
    Vulnerability,
    WatchlistItem,
    WatchlistMatch,
)

log = logging.getLogger("vulnwatch.matching")

MATCH_STRUCTURED = "structured"
MATCH_KEYWORD = "keyword"


def item_terms(item: WatchlistItem) -> list[str]:
    terms = [item.name]
    for kw in item.keywords or []:
        if isinstance(kw, str) and kw.strip():
            terms.append(kw.strip())
    seen: set[str] = set()
    out = []
    for t in terms:
        low = t.lower().strip()
        if low and low not in seen:
            seen.add(low)
            out.append(low)
    return out


def _structured_strings(vuln: Vulnerability) -> list[str]:
    parts = set()
    for ap in vuln.affected_products:
        if ap.vendor:
            parts.add(ap.vendor.lower())
        if ap.product:
            parts.add(ap.product.lower())
        parts.add(f"{ap.vendor or ''} {ap.product or ''}".strip().lower())
        for v in ap.versions or []:
            if isinstance(v, str):
                parts.add(v.lower())
    return [p for p in parts if p]


def _text_strings(vuln: Vulnerability) -> list[str]:
    parts = []
    if vuln.title:
        parts.append(vuln.title.lower())
    if vuln.summary:
        parts.append(vuln.summary.lower())
    return parts


def recompute_matches(session: Session, vuln_ids: list[int] | None = None) -> int:
    """Recompute watchlist matches for given vulnerabilities (or all).

    Deletes stale matches and inserts missing ones. Returns number of rows added.
    """
    items = session.execute(select(WatchlistItem)).scalars().all()
    session.flush()
    if vuln_ids is None:
        vuln_ids = list(session.execute(select(Vulnerability.id)).scalars())
    if not items:
        # still clear any stale matches when the watchlist is emptied
        added = 0
        for vid in vuln_ids:
            for m in session.execute(
                select(WatchlistMatch).where(WatchlistMatch.vulnerability_id == vid)
            ).scalars():
                session.delete(m)
        session.flush()
        return added

    added = 0
    for vid in vuln_ids:
        vuln = session.get(Vulnerability, vid)
        if vuln is None:
            continue
        by_item: dict[int, set[tuple[str, str]]] = {}
        struct_strings = _structured_strings(vuln)
        text = " ".join(_text_strings(vuln))
        for item in items:
            wanted: set[tuple[str, str]] = set()
            for term in item_terms(item):
                if any(term in s for s in struct_strings):
                    wanted.add((MATCH_STRUCTURED, term))
                elif term in text:
                    wanted.add((MATCH_KEYWORD, term))
            by_item[item.id] = wanted

        existing = session.execute(
            select(WatchlistMatch).where(WatchlistMatch.vulnerability_id == vid)
        ).scalars().all()
        existing_keys = {(m.watchlist_item_id, m.match_type, m.matched_term) for m in existing}
        keep_keys = {
            (item_id, match_type, term)
            for item_id, wanted in by_item.items()
            for match_type, term in wanted
        }
        for m in existing:
            key = (m.watchlist_item_id, m.match_type, m.matched_term)
            if key not in keep_keys:
                session.delete(m)
                existing_keys.discard(key)
        for key in keep_keys:
            item_id, match_type, term = key
            if key not in existing_keys:
                session.add(
                    WatchlistMatch(
                        vulnerability_id=vid,
                        watchlist_item_id=item_id,
                        match_type=match_type,
                        matched_term=term,
                        matched_at=datetime.now(timezone.utc),
                    )
                )
                added += 1
    session.flush()
    return added
