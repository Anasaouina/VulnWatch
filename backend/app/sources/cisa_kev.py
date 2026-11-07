"""CISA Known Exploited Vulnerabilities (KEV) catalog adapter.

Schema verified against the live feed on 2026-11-06 (documented at
https://www.cisa.gov/known-exploited-vulnerabilities-catalog JSON feed):

- Top level: title, catalogVersion, dateReleased, count, vulnerabilities[].
- Per entry: cveID, vendorProject, product, vulnerabilityName, dateAdded,
  shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse,
  forensicTriage, notes, cwes.

A malformed catalog response must fail loudly so the caller preserves the last
successful data. Individually malformed entries are skipped with a warning.
"""

import logging
from dataclasses import dataclass, field

from ..normalize import normalize_vuln_id, safe_url

log = logging.getLogger("vulnwatch.cisa_kev")


@dataclass
class KevEntry:
    vuln_id: str
    vendor_project: str | None
    product: str | None
    vulnerability_name: str | None
    date_added: str
    due_date: str | None
    short_description: str | None
    required_action: str | None
    ransomware_use: str | None
    notes_url: str | None
    cwes: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def parse_catalog(payload) -> tuple[list[KevEntry], str | None]:
    """Parse feed; return (entries, catalog_version). Raises on schema drift."""
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("unexpected CISA KEV response shape")
    entries: list[KevEntry] = []
    for raw in payload["vulnerabilities"]:
        if not isinstance(raw, dict):
            continue
        cve = raw.get("cveID")
        if not isinstance(cve, str) or not cve.strip():
            log.warning("CISA KEV entry missing cveID skipped: %r", {k: raw.get(k) for k in raw})
            continue
        if not isinstance(raw.get("dateAdded"), str) or not raw["dateAdded"].strip():
            log.warning("CISA KEV entry %s missing dateAdded, skipped", cve)
            continue
        entries.append(
            KevEntry(
                vuln_id=normalize_vuln_id(cve),
                vendor_project=raw.get("vendorProject") or None,
                product=raw.get("product") or None,
                vulnerability_name=raw.get("vulnerabilityName") or None,
                date_added=raw["dateAdded"].strip(),
                due_date=raw.get("dueDate") or None,
                short_description=raw.get("shortDescription") or None,
                required_action=raw.get("requiredAction") or None,
                ransomware_use=raw.get("knownRansomwareCampaignUse") or None,
                notes_url=safe_url((raw.get("notes") or "").split(";")[0].strip()),
                cwes=[c for c in (raw.get("cwes") or []) if isinstance(c, str)],
                raw=raw,
            )
        )
    returned = payload.get("count")
    if isinstance(returned, int) and returned != len(payload["vulnerabilities"]):
        # count mismatch is suspicious but not fatal; the full array is used.
        log.warning("CISA KEV count=%s but array len=%d", returned, len(payload["vulnerabilities"]))
    version = payload.get("catalogVersion") if isinstance(payload.get("catalogVersion"), str) else None
    return entries, version


def catalog_detail_url(vuln_id: str) -> str:
    return f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={vuln_id}"
