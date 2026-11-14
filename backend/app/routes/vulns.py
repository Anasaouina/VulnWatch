from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session, selectinload

from ..config import settings
from ..db import get_session
from ..models import CvssScore, EpssScore, SourceRecord, SOURCE_RECORD_SOURCES, Vulnerability, WatchlistMatch
from ..normalize import severity_bucket
from ..priority import PRIORITY_RANK
from ..seed import seed_watchlist
from ..serialize import vuln_detail, vuln_list_item

router = APIRouter(prefix="/api/vulns", tags=["vulns"])


def _records_collected_bound():
    return func.coalesce(Vulnerability.published_at, Vulnerability.first_seen_at)


def _priority_case(cvss_subq, epss_subq):
    """SQL mirror of app/priority.py rules for filtering and sorting.

    Only the numeric-CVSS path is approximate here: records whose severity
    comes from a stated label rather than numeric CVSS rank as "low"/unknown
    in SQL but are labeled precisely by the serializer. Documented limits of
    the SQL approximation; the serialized priority remains the exact one.
    """
    high = settings.priority_epss_high
    elevated = settings.priority_epss_elevated
    return case(
        (Vulnerability.is_kev.is_(True), PRIORITY_RANK["urgent"]),
        (
            (epss_subq.isnot(None)) & (epss_subq >= high) & (func.coalesce(cvss_subq, 0.0) >= 7.0),
            PRIORITY_RANK["high"],
        ),
        (
            (epss_subq.isnot(None)) & (
                ((epss_subq >= elevated) & (func.coalesce(cvss_subq, 0.0) >= 7.0))
                | (epss_subq >= high)
            ),
            PRIORITY_RANK["medium"],
        ),
        (epss_subq.isnot(None) | cvss_subq.isnot(None), PRIORITY_RANK["low"]),
        else_=PRIORITY_RANK["unknown"],
    )


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
    ransomware_only: bool = Query(
        False, description="Only CVEs marked Known in CISA ransomware campaign use"
    ),
    source: str | None = Query(
        None,
        description="Only CVEs carrying a record from this source "
        f"(one of: {', '.join(SOURCE_RECORD_SOURCES)})",
    ),
    priority: str | None = Query(
        None, pattern="^(urgent|high|medium|low)$",
        description="VulnWatch priority (assessment, not an official rating)",
    ),
    min_epss: float | None = Query(None, ge=0.0, le=1.0),
    min_epss_percentile: float | None = Query(None, ge=0.0, le=1.0),
    sort: str | None = Query(
        None, pattern="^(newest|priority_desc|epss_desc|cvss_desc)$"
    ),
):
    from datetime import date

    from ..normalize import parse_datetime

    seed_watchlist(session)

    stmt = select(Vulnerability).options(
        selectinload(Vulnerability.cvss_scores),
        selectinload(Vulnerability.source_records),
        selectinload(Vulnerability.epss),
    )
    count_stmt = select(func.count(func.distinct(Vulnerability.id))).select_from(Vulnerability)

    # scalar subqueries for EPSS and best numeric CVSS, used for filters/sort
    epss_subq = (
        select(EpssScore.score)
        .where(EpssScore.vulnerability_id == Vulnerability.id)
        .scalar_subquery()
    )
    cvss_subq = (
        select(func.max(CvssScore.score))
        .where(CvssScore.vulnerability_id == Vulnerability.id)
        .scalar_subquery()
    )
    priority_expr = _priority_case(cvss_subq, epss_subq)

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
        matched = Vulnerability.is_kev.is_(True)
        stmt = stmt.where(matched)
        count_stmt = count_stmt.where(matched)
    if ransomware_only:
        cond = func.lower(func.coalesce(Vulnerability.kev_ransomware_use, "")) == "known"
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)
    if source:
        source_name = source.strip().lower()
        if source_name not in SOURCE_RECORD_SOURCES:
            raise HTTPException(
                422,
                {
                    "message": f"Unknown source {source!r}. "
                    f"Valid sources: {', '.join(SOURCE_RECORD_SOURCES)}"
                },
            )
        cond = Vulnerability.id.in_(
            select(SourceRecord.vulnerability_id).where(SourceRecord.source == source_name)
        )
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    if min_epss is not None:
        cond = epss_subq >= min_epss
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)
    if min_epss_percentile is not None:
        pctl_subq = (
            select(EpssScore.percentile)
            .where(EpssScore.vulnerability_id == Vulnerability.id)
            .scalar_subquery()
        )
        cond = pctl_subq >= min_epss_percentile
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)
    if priority:
        if priority == "urgent":
            cond = Vulnerability.is_kev.is_(True)
        else:
            cond = priority_expr == PRIORITY_RANK[priority]
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    total = session.execute(count_stmt).scalar() or 0

    # deterministic ordering; default newest first by best available date
    order_key = func.coalesce(Vulnerability.published_at, Vulnerability.first_seen_at)
    if sort == "priority_desc":
        stmt = stmt.order_by(priority_expr.desc(), Vulnerability.vuln_id.asc())
    elif sort == "epss_desc":
        stmt = stmt.order_by(epss_subq.desc().nullslast(), Vulnerability.vuln_id.asc())
    elif sort == "cvss_desc":
        stmt = stmt.order_by(cvss_subq.desc().nullslast(), Vulnerability.vuln_id.asc())
    else:
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
