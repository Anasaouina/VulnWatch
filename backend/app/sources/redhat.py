"""Red Hat Security Data adapter — vendor CVSS + first-fixed releases.

Source: the public Red Hat Security Data API
(https://access.redhat.com/hydra/rest/securitydata/cve.json — documented at
https://www.redhat.com/en/blog/new-security-data-api, verified live
2026-11-07, no authentication, incremental by `after` date):

    [{"CVE": "CVE-...", "severity": "moderate",
      "public_date": "2026-11-06T04:40:04Z",
      "bugzilla": "...", "bugzilla_description": "...",
      "statement": "...",
      "cvss3": {"cvss3_score": "5.9", "cvss3_scoring_vector": "CVSS:3.1/..."},
      "affected_release": [{"package": "qt6-qtwebsockets-0:6.8.3-...",
                            "fix_state": "Affected",
                            "cpe": "cpe:/a:redhat:enterprise_linux:9"}, ...]}]

Ingest creates canonical records (Red Hat is authoritative for its own
product exposure), stores attributed CVSS v3 rows (source "redhat") and
AffectedProduct rows with the fixed package versions.
"""

import logging
from dataclasses import dataclass, field

from ..normalize import normalize_vuln_id

log = logging.getLogger("vulnwatch.redhat")

SOURCE = "redhat"
DEFAULT_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
DETAIL_URL = "https://access.redhat.com/security/cve/{cve}"


@dataclass
class RedhatCve:
    vuln_id: str
    severity: str | None
    public_date: str | None
    description: str | None
    statement: str | None
    cvss3_score: float | None
    cvss3_vector: str | None
    affected_release: list[dict] = field(default_factory=list)


def _clean_score(raw) -> float | None:
    try:
        return float(raw) if raw not in (None, "") else None
    except (TypeError, ValueError):
        return None


def parse_cve_rows(payload) -> list[RedhatCve]:
    """Parse one security-data page (a JSON list of CVE objects)."""
    if not isinstance(payload, list):
        raise ValueError("unexpected Red Hat security data shape")
    out: list[RedhatCve] = []
    for raw in payload:
        if not isinstance(raw, dict):
            continue
        cve = raw.get("CVE")
        if not isinstance(cve, str) or not cve.strip():
            continue
        cvss3 = raw.get("cvss3") if isinstance(raw.get("cvss3"), dict) else {}
        releases = []
        for rel in raw.get("affected_release") or []:
            if isinstance(rel, dict):
                releases.append(
                    {
                        "package": rel.get("package"),
                        "fixState": rel.get("fix_state"),
                        "cpe": rel.get("cpe"),
                    }
                )
        out.append(
            RedhatCve(
                vuln_id=normalize_vuln_id(cve),
                severity=raw.get("severity"),
                public_date=raw.get("public_date"),
                description=raw.get("bugzilla_description"),
                statement=raw.get("statement"),
                cvss3_score=_clean_score(cvss3.get("cvss3_score")),
                cvss3_vector=cvss3.get("cvss3_scoring_vector"),
                affected_release=releases[:20],
            )
        )
    return out


def redhat_data(entry: RedhatCve) -> dict:
    return {
        "kind": "redhat-security-data",
        "severity": entry.severity,
        "publicDate": entry.public_date,
        "statement": entry.statement,
        "affectedRelease": entry.affected_release,
        "url": DETAIL_URL.format(cve=entry.vuln_id),
    }
