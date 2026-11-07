"""cve.now source adapter.

Verified against the live service on 2026-11-06 (documented at https://cve.now/llms.txt):

- GET {base}/api/v1/entries            -> {"entries": [...], "nextCursor": "<opaque>", ...}
  Newest first, nextCursor present when more pages exist; pass cursor=<nextCursor>.
- GET {base}/api/v1/entries/<id>       -> full entry with summary, severity {cvss, vector,
  source}, affected [{vendor, product, ranges}], fix versions, references, sources,
  aliases, exploitation.kev {dateAdded, dueDate}, ssvc.
- cve.now summaries are model-generated; records state "Uses NVD data" and label the
  summary with the generating model.

Live behavior notes: pages hold ~30 entries; the service rate-limits aggressively
(repeated rapid requests returned HTTP 403), so callers must pace requests.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime

from ..config import Settings
from ..http import FetchError
from ..normalize import parse_datetime, safe_url

log = logging.getLogger("vulnwatch.cve_now")


@dataclass
class CveNowEntry:
    vuln_id: str
    title: str | None = None
    published_at: datetime | None = None
    first_seen_at: datetime | None = None
    modified_at: datetime | None = None
    cvss: float | None = None
    cvss_vector: str | None = None
    severity_source: str | None = None
    stated_severity: str | None = None
    kev: bool = False
    product: str | None = None
    product_key: str | None = None
    fix_versions: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class CveNowDetail:
    entry: CveNowEntry
    summary: str | None = None
    summary_model: str | None = None
    original_description: str | None = None
    references: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    source_links: dict[str, str] = field(default_factory=dict)
    affected: list[dict] = field(default_factory=list)
    kev_date_added: str | None = None
    kev_due_date: str | None = None


def _product_to_str(raw) -> tuple[str | None, str | None]:
    """product may be a plain string, or {full, short, key, version}."""
    if raw is None:
        return None, None
    if isinstance(raw, str):
        return raw, None
    if isinstance(raw, dict):
        return raw.get("full") or raw.get("short"), raw.get("key")
    return None, None


def parse_entry(raw: dict) -> CveNowEntry | None:
    """Parse one list entry. Returns None if it lacks a usable identifier."""
    if not isinstance(raw, dict):
        return None
    vid = raw.get("id") or raw.get("feedId")
    if not vid or not isinstance(vid, str):
        log.warning("cve.now entry without id skipped: %r", raw)
        return None
    product, product_key = _product_to_str(raw.get("product"))
    sev = raw.get("severity") if isinstance(raw.get("severity"), dict) else {}
    fix = raw.get("fix") if isinstance(raw.get("fix"), list) else []
    fix_versions = [
        str(i.get("version")) if isinstance(i, dict) and i.get("version") is not None
        else str(i)
        for i in fix
        if (i.get("version") if isinstance(i, dict) else i) is not None
    ]
    return CveNowEntry(
        vuln_id=vid.strip(),
        title=raw.get("title") if isinstance(raw.get("title"), str) else None,
        published_at=parse_datetime(raw.get("publishedAt")),
        first_seen_at=parse_datetime(raw.get("firstSeenAt")),
        modified_at=parse_datetime(raw.get("modifiedAt") or raw.get("updatedAt")),
        cvss=sev.get("cvss") if isinstance(sev.get("cvss"), (int, float)) else raw.get("cvss"),
        cvss_vector=sev.get("vector") if isinstance(sev.get("vector"), str) else None,
        severity_source=sev.get("source") if isinstance(sev.get("source"), str) else None,
        stated_severity=(
            raw.get("statedSeverity") if isinstance(raw.get("statedSeverity"), str) else None
        ),
        kev=bool(raw.get("kev")),
        product=product,
        product_key=product_key,
        fix_versions=fix_versions,
        raw=raw,
    )


def parse_list_page(payload) -> tuple[list[CveNowEntry], str | None]:
    """Validate the list payload contract; raise on schema drift."""
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        raise ValueError("unexpected cve.now list response shape")
    entries = []
    for raw in payload["entries"]:
        parsed = parse_entry(raw)
        if parsed is not None:
            entries.append(parsed)
    cursor = payload.get("nextCursor")
    return entries, (cursor if isinstance(cursor, str) and cursor else None)


def parse_detail(payload) -> CveNowDetail | None:
    if not isinstance(payload, dict):
        raise ValueError("unexpected cve.now detail response shape")
    base = parse_entry(payload)
    if base is None:
        return None
    summary_obj = payload.get("summary")
    summary = summary_model = None
    if isinstance(summary_obj, dict):
        summary = (
            summary_obj["text"] if isinstance(summary_obj.get("text"), str) else summary_obj.get("text")
        )
        summary_model = summary_obj.get("model") if isinstance(summary_obj.get("model"), str) else None
    elif isinstance(summary_obj, str):
        summary = summary_obj
    refs = []
    for r in payload.get("references") or []:
        if isinstance(r, dict) and safe_url(r.get("url")):
            refs.append(r["url"])
    source_links: dict[str, str] = {}
    for s in payload.get("sources") or []:
        if isinstance(s, dict) and isinstance(s.get("name"), str) and safe_url(s.get("url")):
            source_links[s["name"]] = s["url"]
    kev_obj = (payload.get("exploitation") or {}).get("kev") if isinstance(payload.get("exploitation"), dict) else None
    kev_date_added = kev_due = None
    if isinstance(kev_obj, dict):
        kev_date_added = kev_obj.get("dateAdded") if isinstance(kev_obj.get("dateAdded"), str) else None
        kev_due = kev_obj.get("dueDate") if isinstance(kev_obj.get("dueDate"), str) else None
    affected = [
        a
        for a in payload.get("affected") or []
        if isinstance(a, dict) and (a.get("product") or a.get("vendor"))
    ]
    original = payload.get("originalDescription")
    detail = CveNowDetail(
        entry=base,
        summary=summary,
        summary_model=summary_model,
        original_description=original if isinstance(original, str) else None,
        references=refs[:20],
        aliases=[a for a in (payload.get("aliases") or []) if isinstance(a, str)],
        source_links=source_links,
        affected=affected[:10],
        kev_date_added=kev_date_added,
        kev_due_date=kev_due,
    )
    return detail


class CveNowClient:
    def __init__(self, client, settings: Settings):
        self.client = client
        self.settings = settings
        self.page_pause = settings.cve_now_page_pause_seconds
        self.detail_pause = settings.cve_now_detail_pause_seconds
        self.max_pages = settings.cve_now_max_pages_per_run

    def list_entries(self, cursor: str | None = None):
        url = f"{self.settings.cve_now_base_url}/api/v1/entries"
        if cursor:
            url = f"{url}?cursor={cursor}"
        resp = self.client.get(url, timeout=self.settings.http_timeout_seconds)
        resp.raise_for_status()
        return parse_list_page(resp.json())

    def fetch_detail(self, vuln_id: str):
        url = f"{self.settings.cve_now_base_url}/api/v1/entries/{vuln_id}"
        resp = self.client.get(url, timeout=self.settings.http_timeout_seconds)
        resp.raise_for_status()
        return parse_detail(resp.json())


__all__ = [
    "CveNowClient",
    "CveNowEntry",
    "CveNowDetail",
    "parse_list_page",
    "parse_detail",
    "FetchError",
]
