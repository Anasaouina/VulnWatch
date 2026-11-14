"""OSV.dev adapter — cross-ecosystem advisory linkage.

Source: OSV.dev API (https://api.osv.dev). The v1/query* endpoints only
accept package-based queries, but the documentation-recommended path for a
known GHSA id is a direct GET (verified live 2026-11-07):

    GET https://api.osv.dev/v1/vulns/{GHSA_ID}
    -> {"id": "GHSA-...", "modified": ..., "aliases": ["CVE-..."],
        "severity": [...], "affected": [...], ...}

The CVE->GHSA mapping comes from the github_advisory source records; for
canonical CVEs having a GHSA but no OSV record yet, this adapter fetches the
OSV entry and stores aliases + affected-package summary. Enrichment-only:
nothing canonical is created. Bounded per cycle (OSV_MAX_PER_RUN).
"""

import logging
from dataclasses import dataclass, field

import httpx

log = logging.getLogger("vulnwatch.osv_dev")

SOURCE = "osv_dev"
DEFAULT_URL = "https://api.osv.dev/v1/vulns"


@dataclass
class OsvAdvisory:
    osv_id: str
    aliases: list[str] = field(default_factory=list)
    modified: str | None = None
    severity: list[dict] = field(default_factory=list)
    affected_ecosystems: list[str] = field(default_factory=list)
    first_patched: list[str] = field(default_factory=list)


def parse_osv_record(payload) -> OsvAdvisory:
    """Parse one OSV record. Raises on shape drift."""
    if not isinstance(payload, dict) or not isinstance(payload.get("id"), str):
        raise ValueError("unexpected OSV record shape")
    ecosystems: list[str] = []
    first_patched: list[str] = []
    for a in payload.get("affected") or []:
        if not isinstance(a, dict):
            continue
        pkg = a.get("package") if isinstance(a.get("package"), dict) else {}
        eco = pkg.get("ecosystem")
        if isinstance(eco, str) and eco not in ecosystems:
            ecosystems.append(eco)
        for r in a.get("ranges") or []:
            if isinstance(r, dict):
                for ev in r.get("events") or []:
                    if isinstance(ev, dict) and isinstance(ev.get("fixed"), str):
                        first_patched.append(ev["fixed"])
    return OsvAdvisory(
        osv_id=payload["id"],
        aliases=[
            a for a in (payload.get("aliases") or [])
            if isinstance(a, str)
        ],
        modified=payload.get("modified"),
        severity=[
            s for s in (payload.get("severity") or []) if isinstance(s, dict)
        ],
        affected_ecosystems=ecosystems[:20],
        first_patched=sorted(set(first_patched))[:10],
    )


def osv_data(adv: OsvAdvisory) -> dict:
    return {
        "kind": "osv-advisory",
        "osvId": adv.osv_id,
        "aliases": adv.aliases,
        "modified": adv.modified,
        "affectedEcosystems": adv.affected_ecosystems,
        "firstPatched": adv.first_patched,
        "url": f"https://osv.dev/vulnerability/{adv.osv_id}",
    }


def fetch_osv_record(
    client: httpx.Client, base_url: str, ghsa_id: str, timeout: float
) -> OsvAdvisory | None:
    resp = client.get(f"{base_url.rstrip('/')}/{ghsa_id}", timeout=timeout)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return parse_osv_record(resp.json())
