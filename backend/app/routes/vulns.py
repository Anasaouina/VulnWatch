from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from ..db import get_session
from ..models import CvssScore, Vulnerability, WatchlistMatch
from ..normalize import severity_bucket
from ..seed import seed_watchlist
from ..serialize import vuln_detail, vuln_list_item

router = APIRouter(prefix="/api/vulns", tags=["vulns"])


def _records_collected_bound():
    return func.coalesce(Vulnerability.published_at, Vulnerability.first_seen_at)


SEVERITY_SQL = {
    "critical": ("score >= :lo", {"lo": 9.0}),
    "high": ("score >= 7.0", ()),
    "medium": ("score >= 4.0", ()),
    "low": ("score > 0.0", ()),
}


@router.get("")
def list_vulns(
    session: Session = Depends(get_session),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    q: str | None = Query(None, max_length=200, description="CVE id or keyword"),
    severity: str | None = Query(
        None, pattern="^(critical|high|medium|low|unknown)$"
    ),
    date_from: str | None = Query(None, description="ISO date or datetime"),
    date_to: str | None = Query(None, description="ISO date or datetime"),
    watchlist_only: bool = Query(False),
    kev_only: bool = Query(False),
):
    from datetime import date

    from ..normalize import parse_datetime

    seed_watchlist(session)

    stmt = select(Vulnerability).options(
        selectinload(Vulnerability.cvss_scores),
        selectinload(Vulnerability.source_records),
    )
    count_stmt = select(func.count(func.distinct(Vulnerability.id))).select_from(Vulnerability)

    if q:
        needle = f"%{q.strip()}%"
        cond = or_(
            Vulnerability.vuln_id.ilike(needle),
            Vulnerability.title.ilike(needle),
            Vulnerability.summary.ilike(needle),
        )
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    if severity:
        if severity == "unknown":
            no_score = ~Vulnerability.id.in_(
                select(CvssScore.vulnerability_id)
            )
            cond = no_score & ~Vulnerability.stated_severity.in_(
                ["critical", "high", "medium", "moderate", "low"]
            )
        else:
            has_bucket = Vulnerability.id.in_(
                select(CvssScore.vulnerability_id).where(
                    CvssScore.score >= {
                        "critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.001,
                    }[severity]
                )
            )
            aliases = [severity] + (["moderate"] if severity == "medium" else [])
            stated = Vulnerability.stated_severity.in_(aliases)
            cond = has_bucket | (stated & ~Vulnerability.id.in_(
                select(CvssScore.vulnerability_id)
            ))
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    for param, op in ((date_from, ">="), (date_to, "<=")):
        if not param:
            continue
        try:
            from datetime import datetime as _dt, time as _time, timezone as _tz

            d = date.fromisoformat(param)
            bound = _dt.combine(d, _time.min if op == ">=" else _time.max, tzinfo=_tz.utc)
        except ValueError:
            dt = parse_datetime(param)
            if dt is None:
                raise HTTPException(422, {"message": "Invalid date. Use YYYY-MM-DD or ISO datetime."})
            bound = dt
        cond = (_records_collected_bound() >= bound) if op == ">=" else (_records_collected_bound() <= bound)
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    if watchlist_only:
        matched = Vulnerability.id.in_(select(WatchlistMatch.vulnerability_id))
        stmt = stmt.where(matched)
        count_stmt = count_stmt.where(matched)
    if kev_only:
        stmt = stmt.where(Vulnerability.is_kev.is_(True))
        count_stmt = count_stmt.where(Vulnerability.is_kev.is_(True))

    total = session.execute(count_stmt).scalar() or 0

    # deterministic: newest first by best available date, tie-break by id ASC
    order_key = func.coalesce(Vulnerability.published_at, Vulnerability.first_seen_at)
    stmt = stmt.order_by(order_key.desc().nulls_last(), Vulnerability.vuln_id.asc())

    items_rows = session.execute(
        stmt.offset((page - 1) * page_size).limit(page_size)
    ).scalars().all()

    matches = {}
    if items_rows:
        from ..serialize import _match_info

        matches = _match_info(session, [v.id for v in items_rows])

    pages = (total + page_size - 1) // page_size
    return {
        "items": [vuln_list_item(session, v, matches) for v in items_rows],
        "page": page,
        "page_size": page_size,
        "total": total,
        "pages": pages,
    }


@router.get("/{vuln_id}")
def get_vuln(vuln_id: str, session: Session = Depends(get_session)):
    vuln = session.execute(
        select(Vulnerability)
        .where(Vulnerability.vuln_id == vuln_id.upper().strip())
        .options(
            selectinload(Vulnerability.cvss_scores),
            selectinload(Vulnerability.source_records),
            selectinload(Vulnerability.affected_products),
            selectinload(Vulnerability.watchlist_matches).selectinload(WatchlistMatch.item),
        )
    ).scalar_one_or_none()
    if vuln is None:
        raise HTTPException(404, {"message": "Vulnerability not found."})
    return vuln_detail(session, vuln)
