"""Collector service entrypoint.

Runs a sync once on startup, then every SYNC_INTERVAL_SECONDS (default hourly).
Overlapping runs are prevented by an in-process lock plus a Postgres advisory
lock shared with the API's manual-sync trigger.

Usage:
    python -m app.collector_main           # startup sync + loop
    python -m app.collector_main --once    # single sync, then exit
"""

import argparse
import logging
import sys
import time

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from . import collector
from .config import settings
from .db import make_engine
from .models import SyncState, utcnow
from .seed import seed_watchlist

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("vulnwatch.collector")


def needs_startup_sync(session: Session) -> bool:
    states = session.execute(select(SyncState)).scalars().all()
    last_success = max(
        (s.last_success_at for s in states if s.last_success_at), default=None
    )
    if last_success is None:
        return True
    age = (utcnow() - last_success).total_seconds()
    return age >= settings.sync_interval_seconds


def run_cycle(factory: sessionmaker, lock: collector.RunLock) -> None:
    if not lock.acquire():
        log.warning("another sync is running; skipping cycle")
        return
    try:
        results = collector.run_sync(factory, settings)
        for source, r in results.items():
            log.info("sync result %s: %s", source, r)
    finally:
        lock.release()


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnWatch collector")
    parser.add_argument("--once", action="store_true", help="Run one sync and exit")
    args = parser.parse_args()

    engine = make_engine()
    factory = sessionmaker(engine, autoflush=False, expire_on_commit=False)
    lock = collector.RunLock(factory)

    with factory() as session:  # type: Session
        session.execute(select(SyncState.id))
        session.commit()
        seed_watchlist(session)
        startup = needs_startup_sync(session)

    if args.once:
        run_cycle(factory, lock)
        return 0

    if startup:
        log.info("startup sync required; running now")
        run_cycle(factory, lock)
    else:
        log.info("recent sync exists; waiting for the next scheduled cycle")

    log.info("collector loop started, interval=%ss", settings.sync_interval_seconds)
    try:
        while True:
            time.sleep(settings.sync_interval_seconds)
            run_cycle(factory, lock)
    except KeyboardInterrupt:
        log.info("collector stopped")
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
