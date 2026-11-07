import threading

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..collector import RunLock, run_sync
from ..config import settings
from ..db import get_session
from ..models import SyncState

router = APIRouter(prefix="/api/sync", tags=["sync"])

_sync_lock_ref: dict[str, RunLock] = {}


def describe_sync(session: Session) -> dict:
    rows = session.execute(select(SyncState)).scalars().all()
    by_source = {r.source: r for r in rows}
    interval = settings.sync_interval_seconds
    sources = []
    for src in ("cve_now", "cisa_kev"):
        r = by_source.get(src)
        sources.append(
            {
                "source": src,
                "status": r.status if r else "never_run",
                "last_attempt_at": r.last_attempt_at.isoformat() if r and r.last_attempt_at else None,
                "last_success_at": r.last_success_at.isoformat() if r and r.last_success_at else None,
                "error_message": r.error_message if r else None,
                "records_processed": r.records_processed if r else 0,
                "stale": bool(
                    r
                    and r.last_success_at is None
                    or (
                        r
                        and r.status == "error"
                        and (r.last_success_at is None or r.last_attempt_at > r.last_success_at)
                    )
                ),
            }
        )
    return {
        "sources": sources,
        "interval_seconds": interval,
        "running": _sync_lock_ref.get("lock") is not None and not _sync_lock_ref.get("lock")._thread_lock.locked(),
    }


@router.get("/status")
def sync_status(session: Session = Depends(get_session)):
    return describe_sync(session)


@router.post("/run")
def trigger_sync(request: "Request"):
    if not settings.allow_manual_sync:
        raise HTTPException(403, {"message": "Manual sync is disabled."})
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        raise HTTPException(503, {"message": "Sync is not available yet."})
    accepted, message = run_sync_background(session_factory)
    return {"accepted": accepted, "message": message}


def run_sync_background(session_factory) -> tuple[bool, str]:
    """Start a collector cycle in a thread. Returns (accepted, message)."""
    lock = _sync_lock_ref.get("lock")
    if lock is None:
        lock = RunLock(session_factory)
        _sync_lock_ref["lock"] = lock
    if not lock.acquire():
        return False, "A sync is already running."

    def _worker():
        try:
            run_sync(session_factory, settings)
        finally:
            lock.release()

    threading.Thread(target=_worker, name="manual-sync", daemon=True).start()
    return True, "Sync started."
