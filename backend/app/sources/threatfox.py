"""ThreatFox (abuse.ch) adapter — malware IOC context per CVE.

Source: ThreatFox Community API (https://threatfox-api.abuse.ch/api/v1/,
documented at https://threatfox.abuse.ch/api/, verified against the live
documentation on 2026-11-07). The API requires a free Auth-Key obtained at
https://auth.abuse.ch/ (header `Auth-Key`); without one the source reports
"unconfigured" and is skipped:

    POST https://threatfox-api.abuse.ch/api/v1/
    header: Auth-Key: <key>
    body:   {"query": "get_iocs", "days": 7}

    -> {"query_status": "ok", "data": [
        {"ioc": "…", "threat_type": "botnet_cc", "ioc_type": "domain",
         "malware": "win.dridex", "malware_alias": null,
         "confidence_level": 50, "first_seen": "...", "reference": ...,
         "tags": [...]}, ...]}

CVE linkage: IOCs rarely name a CVE; the strict CVE regex scans the IOC's
malware alias, reference and threat metadata and only canonical CVEs get a
SourceRecord. Bounded import (days=7 window, IOC entries capped per CVE).
"""

import logging
import re
from dataclasses import dataclass, field

import httpx

from ..normalize import normalize_vuln_id

log = logging.getLogger("vulnwatch.threatfox")

SOURCE = "threatfox"
DEFAULT_URL = "https://threatfox-api.abuse.ch/api/v1/"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_MAX_IOCS_PER_CVE = 50


@dataclass
class ThreatfoxIoc:
    ioc: str | None
    threat_type: str | None
    ioc_type: str | None
    malware: str | None
    malware_alias: str | None
    confidence_level: int | None
    first_seen: str | None
    reference: str | None
    tags: list[str] = field(default_factory=list)


def parse_ioc_response(payload) -> list[ThreatfoxIoc]:
    """Parse a get_iocs response. Raises on query-level failure."""
    if not isinstance(payload, dict):
        raise ValueError("unexpected ThreatFox response shape")
    status = payload.get("query_status")
    if status != "ok":
        raise ValueError(f"ThreatFox query_status={status!r}")
    data = payload.get("data")
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError("unexpected ThreatFox data shape")
    out: list[ThreatfoxIoc] = []
    for raw in data:
        if not isinstance(raw, dict):
            continue
        out.append(
            ThreatfoxIoc(
                ioc=raw.get("ioc"),
                threat_type=raw.get("threat_type"),
                ioc_type=raw.get("ioc_type"),
                malware=raw.get("malware"),
                malware_alias=raw.get("malware_alias"),
                confidence_level=(
                    raw.get("confidence_level")
                    if isinstance(raw.get("confidence_level"), int)
                    else None
                ),
                first_seen=raw.get("first_seen"),
                reference=raw.get("reference") if isinstance(raw.get("reference"), str) else None,
                tags=[t for t in (raw.get("tags") or []) if isinstance(t, str)],
            )
        )
    return out


def ioc_cves(ioc: ThreatfoxIoc) -> list[str]:
    """CVEs named anywhere in the IOC record (alias/reference/rare IOC text)."""
    blob = " ".join(
        x for x in (ioc.malware_alias, ioc.reference, ioc.ioc, ioc.malware) if x
    )
    out: list[str] = []
    for token in _CVE_RE.findall(blob):
        norm = normalize_vuln_id(token)
        if norm not in out:
            out.append(norm)
    return out


def ioc_data(ioc: ThreatfoxIoc) -> dict:
    return {
        "kind": "threatfox-ioc",
        "ioc": ioc.ioc,
        "threatType": ioc.threat_type,
        "iocType": ioc.ioc_type,
        "malware": ioc.malware,
        "malwareAlias": ioc.malware_alias,
        "confidenceLevel": ioc.confidence_level,
        "firstSeen": ioc.first_seen,
        "reference": ioc.reference,
        "tags": ioc.tags,
        "url": ioc.reference,
    }


def fetch_iocs(
    client: httpx.Client, base_url: str, auth_key: str | None, days: int = 7, timeout: float = 30.0
) -> list[ThreatfoxIoc]:
    headers = {"Auth-Key": auth_key} if auth_key else None
    resp = client.post(
        base_url.rstrip("/") + "/",
        json={"query": "get_iocs", "days": days},
        headers=headers,
        timeout=timeout,
    )
    resp.raise_for_status()
    return parse_ioc_response(resp.json())
