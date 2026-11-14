"""Vulners adapter — aggregated exploit/advisory references (API-key gated).

Source: Vulners API (https://vulners.com/api/v3/search/id/). The unauthenticated
endpoint is Cloudflare-challenged for datacenter IPs (verified live
2026-11-07), so an API key (free at https://vulners.com/user/register) is
required; without VULNERS_API_KEY the source reports "unconfigured" and is
skipped:

    GET https://vulners.com/api/v3/search/id/?id=CVE-...&apikey=KEY
    -> {"result": "OK", "data": {
        "id": "CVE-...", "title": "...", "cvss": {"score": 7.5,
        "vector": "CVSS:3.1/..."}, "published": "...", "references": [...],
        "cvelist": [...], "bulletinFamily": "vuln"}}

On-demand enrichment: per cycle, urgent/high-priority canonical CVEs without
a vulners record are looked up (VULNERS_MAX_PER_RUN bound), so the
Cloudflare-limited API is only used for the most relevant CVEs.
"""

import logging
from dataclasses import dataclass, field

import httpx

log = logging.getLogger("vulnwatch.vulners")

SOURCE = "vulners"
DEFAULT_URL = "https://vulners.com/api/v3/search/id/"
DETAIL_URL = "https://vulners.com/{id}"


@dataclass
class VulnersRecord:
    ref_id: str
    title: str | None
    cvss_score: float | None
    cvss_vector: str | None
    published: str | None
    references: list[str] = field(default_factory=list)


def parse_lookup(payload) -> VulnersRecord | None:
    """Parse one search/id response; None when the id is unknown to Vulners."""
    if not isinstance(payload, dict):
        raise ValueError("unexpected Vulners response shape")
    if payload.get("result") != "OK":
        raise ValueError(f"Vulners result={payload.get('result')!r}")
    data = payload.get("data")
    if not isinstance(data, dict) or not data.get("id"):
        return None
    cvss = data.get("cvss") if isinstance(data.get("cvss"), dict) else {}
    score = cvss.get("score")
    return VulnersRecord(
        ref_id=str(data.get("id")),
        title=data.get("title"),
        cvss_score=float(score) if isinstance(score, (int, float)) else None,
        cvss_vector=cvss.get("vector"),
        published=data.get("published"),
        references=[
            r for r in (data.get("references") or []) if isinstance(r, str)
        ][:20],
    )


def vulners_data(rec: VulnersRecord) -> dict:
    return {
        "kind": "vulners-record",
        "title": rec.title,
        "published": rec.published,
        "references": rec.references,
        "url": DETAIL_URL.format(id=rec.ref_id),
    }


def fetch_lookup(
    client: httpx.Client, base_url: str, vuln_id: str, api_key: str, timeout: float
) -> VulnersRecord | None:
    resp = client.get(
        base_url.rstrip("/") + "/",
        params={"id": vuln_id, "apikey": api_key},
        timeout=timeout,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return parse_lookup(resp.json())
