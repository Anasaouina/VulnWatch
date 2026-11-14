"""GitHub Security Advisory Database adapter.

Source: the public GitHub Advisories REST API
(https://api.github.com/advisories, verified live 2026-11-07 — no token
needed for moderate use; a GITHUB_TOKEN raises the rate limit):

    [{"ghsa_id": "GHSA-...", "cve_id": "CVE-..." | null,
      "summary": "...", "description": "...",
      "severity": "high", "published_at": ..., "updated_at": ...,
      "cvss": {"score": 7.5, "vector_string": "CVSS:3.1/..."} | null,
      "vulnerabilities": [{"package": {"name": ..., "ecosystem": ...},
                           "vulnerable_version_range": ">1.0",
                           "first_patched_version": "1.2"}], ...}]

Incremental by `modified=>{date}`. Advisories carrying a CVE id create or
enrich canonical records (the GitHub database is authoritative); advisories
without a CVE id (GHSA-only) are skipped because VulnWatch's canonical space
is CVE-centric.

The GHSA ids stored here also drive the separate `osv_dev` enrichment pass.
"""

import logging
from dataclasses import dataclass, field

from ..normalize import normalize_vuln_id

log = logging.getLogger("vulnwatch.github_advisory")

SOURCE = "github_advisory"
DEFAULT_URL = "https://api.github.com/advisories"


@dataclass
class GithubAdvisory:
    ghsa_id: str
    vuln_id: str | None
    summary: str | None
    description: str | None
    severity: str | None
    cvss_score: float | None
    cvss_vector: str | None
    published_at: str | None
    updated_at: str | None
    vulnerabilities: list[dict] = field(default_factory=list)


def parse_advisories(payload) -> list[GithubAdvisory]:
    """Parse one advisories page. Raises on shape drift; skips unusable rows."""
    if not isinstance(payload, list):
        raise ValueError("unexpected GitHub advisories page shape")
    out: list[GithubAdvisory] = []
    for raw in payload:
        if not isinstance(raw, dict):
            continue
        ghsa = raw.get("ghsa_id")
        if not isinstance(ghsa, str) or not ghsa.strip():
            continue
        cve = raw.get("cve_id")
        vuln_id = normalize_vuln_id(cve) if isinstance(cve, str) and cve.strip() else None
        if vuln_id is None:
            # GHSA-only advisories cannot anchor to a canonical CVE record
            continue
        cvss = raw.get("cvss") if isinstance(raw.get("cvss"), dict) else {}
        vulns = []
        for v in raw.get("vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            pkg = v.get("package") if isinstance(v.get("package"), dict) else {}
            vulns.append(
                {
                    "ecosystem": pkg.get("ecosystem"),
                    "package": pkg.get("name"),
                    "range": v.get("vulnerable_version_range"),
                    "firstPatched": v.get("first_patched_version"),
                }
            )
        out.append(
            GithubAdvisory(
                ghsa_id=ghsa,
                vuln_id=vuln_id,
                summary=raw.get("summary"),
                description=raw.get("description"),
                severity=raw.get("severity"),
                cvss_score=cvss.get("score"),
                cvss_vector=cvss.get("vector_string"),
                published_at=raw.get("published_at"),
                updated_at=raw.get("updated_at"),
                vulnerabilities=vulns,
            )
        )
    return out


def advisory_data(adv: GithubAdvisory) -> dict:
    return {
        "kind": "github-advisory",
        "ghsaId": adv.ghsa_id,
        "severity": adv.severity,
        "vulnerabilities": adv.vulnerabilities[:20],
        "url": f"https://github.com/advisories/{adv.ghsa_id}",
    }
