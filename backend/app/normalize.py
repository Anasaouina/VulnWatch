"""URL and identifier normalization helpers.

All URLs coming from external sources are untrusted: only http/https URLs with
an http(s) host are allowed through, everything else is discarded.
"""

import re
from datetime import datetime, timezone
from urllib.parse import urlparse

__all__ = [
    "normalize_vuln_id",
    "safe_url",
    "parse_datetime",
    "severity_bucket",
]

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def normalize_vuln_id(raw: str) -> str:
    """Uppercase and strip surrounding whitespace / window dressing."""
    v = (raw or "").strip()
    m = CVE_ID_RE.search(v.upper())
    if m:
        return m.group(0)
    return v.upper().replace(" ", "-")


def safe_url(url: str | None) -> str | None:
    """Return the URL only if it is a plain http/https URL, else None."""
    if not url or not isinstance(url, str):
        return None
    url = url.strip()
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return url


def parse_datetime(raw) -> datetime | None:
    """Parse an ISO-8601 timestamp from a feed into an aware UTC datetime."""
    if not raw:
        return None
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    s = str(raw).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def severity_bucket(score: float | None, stated: str | None = None) -> str:
    """Derive a display bucket. Prefer numeric CVSS; fall back to stated label."""
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
        return "unknown"
    s = (stated or "").strip().lower()
    if s in ("critical", "high", "medium", "moderate", "low"):
        return {"moderate": "medium"}.get(s, s)
    return "unknown"
