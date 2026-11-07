from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import matching
from ..db import get_session
from ..models import WatchlistItem
from ..seed import seed_watchlist

router = APIRouter(prefix="/api/watchlist", tags=["watchlist"])


class WatchlistIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    keywords: list[str] = Field(default_factory=list, max_length=40)


def _serialize(session: Session, item: WatchlistItem, match_count: int | None = None) -> dict:
    if match_count is None:
        match_count = (
            session.execute(
                select(func.count())
                .select_from(matching.WatchlistMatch)
                .where(matching.WatchlistMatch.watchlist_item_id == item.id)
            ).scalar()
            or 0
        )
    return {
        "id": item.id,
        "name": item.name,
        "keywords": item.keywords or [],
        "match_count": match_count,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


def _recompute(session: Session) -> None:
    matching.recompute_matches(session)
    session.commit()


@router.get("")
def list_watchlist(session: Session = Depends(get_session)):
    seed_watchlist(session)
    items = session.execute(
        select(WatchlistItem).order_by(WatchlistItem.name.asc())
    ).scalars().all()
    counts = dict(
        session.execute(
            select(matching.WatchlistMatch.watchlist_item_id, func.count())
            .select_from(matching.WatchlistMatch)
            .group_by(matching.WatchlistMatch.watchlist_item_id)
        ).all()
    )
    return {"items": [_serialize(session, i, counts.get(i.id, 0)) for i in items]}


@router.post("", status_code=201)
def create_watchlist(body: WatchlistIn, session: Session = Depends(get_session)):
    name = body.name.strip()
    if not name:
        raise HTTPException(422, {"message": "Product name is required."})
    duplicate = session.execute(
        select(WatchlistItem).where(func.lower(WatchlistItem.name) == name.lower())
    ).scalar_one_or_none()
    if duplicate is not None:
        raise HTTPException(409, {"message": f"'{name}' is already on the watchlist."})
    keywords = [
        k.strip() for k in body.keywords if isinstance(k, str) and k.strip()
    ]
    item = WatchlistItem(name=name, keywords=keywords)
    session.add(item)
    session.commit()
    _recompute(session)
    return _serialize(session, item)


@router.patch("/{item_id}")
def update_watchlist(item_id: int, body: WatchlistIn, session: Session = Depends(get_session)):
    item = session.get(WatchlistItem, item_id)
    if item is None:
        raise HTTPException(404, {"message": "Watchlist item not found."})
    name = body.name.strip()
    if not name:
        raise HTTPException(422, {"message": "Product name is required."})
    dupe = session.execute(
        select(WatchlistItem).where(
            func.lower(WatchlistItem.name) == name.lower(),
            WatchlistItem.id != item_id,
        )
    ).scalar_one_or_none()
    if dupe is not None:
        raise HTTPException(409, {"message": f"'{name}' is already on the watchlist."})
    item.name = name
    item.keywords = [k.strip() for k in body.keywords if isinstance(k, str) and k.strip()]
    session.commit()
    _recompute(session)
    return _serialize(session, item)


@router.delete("/{item_id}", status_code=204)
def delete_watchlist(item_id: int, session: Session = Depends(get_session)):
    item = session.get(WatchlistItem, item_id)
    if item is None:
        raise HTTPException(404, {"message": "Watchlist item not found."})
    session.delete(item)
    session.commit()
    _recompute(session)
    return None
