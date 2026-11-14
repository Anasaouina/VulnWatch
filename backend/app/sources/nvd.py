"""NVD (US National Vulnerability Database) adapter — attributed CVSS data.

Source: NVD REST API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0,
verified live 2026-11-07). VulnWatch syncs incrementally by modification
window (the API's documented `lastModStartDate`/`lastModEndDate` parameters,
max 120 days per window):

    {"resultsPerPage": 2000, "startIndex": 0, "totalResults": ...,
     "vulnerabilities": [{"cve": {
        "id": "CVE-...", "published": ..., "lastModified": ...,
        "descriptions": [{"lang": "en", "value": "..."}],
        "metrics": {
            "cvssMetricV31": [{"source": "...", "type": "Primary",
                               "cvssData": {"baseScore": 7.5,
                                            "vectorString": "CVSS:3.1/..."}}],
            "cvssMetricV40": [...], "cvssMetricV2": [...]
        }, ...}}]}

Rate limits: without an API key 5 requests per 30 s (with key 50/30 s). The
sync paces itself (NVD_PAGE_PAUSE_SECONDS) and caps pages per run.

Ingest: creates canonical records (NVD is the authoritative CVE catalog) and
stores attributed CVSS rows (source "nvd") — this closes the unattributed-CVSS
gap in the cve.now list feed. English description also fills title/summary on
write-once semantics (an existing value is never overwritten).
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..normalize import normalize_vuln_id

log = logging.getLogger("vulnwatch.nvd")

SOURCE = "nvd"
DEFAULT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE = 2000
_METRIC_SOURCES = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV2")
_METRIC_VERSIONS = {
    "cvssMetricV40": "4.0",
    "cvssMetricV31": "3.1",
    "cvssMetricV2": "2.0",
}


@dataclass
class NvdCvssMetric:
    version: str
    score: float
    vector: str | None
    metric_source: str | None
    metric_type: str | None


@dataclass
class NvdEntry:
    vuln_id: str
    published: str | None
    last_modified: str | None
    title: str | None
    summary: str | None
    metrics: list[NvdCvssMetric] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def _parse_dt(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        # NVD formats: "2026-11-01T12:00:00.000" (assumed UTC)
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(
            tzinfo=timezone.utc
        ) if "+" not in raw else datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def nvd_window_format(dt: datetime) -> str:
    """Format a datetime for the NVD lastMod* parameters (UTC, milliseconds)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def parse_nvd_page(payload) -> list[NvdEntry]:
    """Parse one API page. Raises on top-level shape drift; skips bad entries."""
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("unexpected NVD API page shape")
    out: list[NvdEntry] = []
    for wrapper in payload["vulnerabilities"]:
        if not isinstance(wrapper, dict):
            continue
        cve = wrapper.get("cve")
        if not isinstance(cve, dict):
            continue
        vuln_id = cve.get("id")
        if not isinstance(vuln_id, str) or not vuln_id.strip():
            continue
        vuln_id = normalize_vuln_id(vuln_id)
        title = summary = None
        for desc in cve.get("descriptions") or []:
            if isinstance(desc, dict) and desc.get("lang") == "en" and desc.get("value"):
                summary = desc["value"]
                title = summary.split(".")[0][:200]
                break
        metrics: list[NvdCvssMetric] = []
        metric_block = cve.get("metrics") or {}
        for key in _METRIC_SOURCES:
            for m in metric_block.get(key) or []:
                data = (m.get("cvssData") or {}) if isinstance(m, dict) else {}
                score = data.get("baseScore")
                if not isinstance(score, (int, float)):
                    continue
                metrics.append(
                    NvdCvssMetric(
                        version=_METRIC_VERSIONS[key],
                        score=float(score),
                        vector=data.get("vectorString"),
                        metric_source=m.get("source"),
                        metric_type=m.get("type"),
                    )
                )
        references = []
        for ref in (cve.get("references") or []):
            if isinstance(ref, dict) and isinstance(ref.get("url"), str):
                references.append(ref["url"])
        out.append(
            NvdEntry(
                vuln_id=vuln_id,
                published=str(cve.get("published")) if cve.get("published") else None,
                last_modified=str(cve.get("lastModified")) if cve.get("lastModified") else None,
                title=title,
                summary=summary,
                metrics=metrics,
                references=references[:20],
                raw=cve,
            )
        )
    return out


def initial_window(now: datetime) -> tuple[datetime, datetime]:
    """First-sync window: the last 7 days, bounded to the API's 120-day cap."""
    end = now - timedelta(minutes=1)
    start = now - timedelta(days=7)
    return start, end
