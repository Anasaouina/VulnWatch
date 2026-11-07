"""Default watchlist seed. Idempotent."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import WatchlistItem

DEFAULT_WATCHLIST = [
    ("OpenSSH", ["openssh", "sshd"]),
    ("Wazuh", ["wazuh"]),
    ("pfSense", ["pfsense", "pfSense"]),
    ("Docker", ["docker", "moby"]),
]


def seed_watchlist(session: Session) -> int:
    existing = {
        n.lower()
        for n, in session.execute(select(WatchlistItem.name)).all()
    }
    added = 0
    for name, keywords in DEFAULT_WATCHLIST:
        if name.lower() in existing:
            continue
        session.add(WatchlistItem(name=name, keywords=keywords))
        added += 1
    if added:
        session.commit()
    return added
