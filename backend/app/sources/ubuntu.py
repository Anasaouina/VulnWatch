"""Ubuntu CVE tracker adapter — Canonical package fix status.

Source: the Ubuntu CVE Tracker API v0
(https://cve.ubuntu.com/api/v0/cves/ — Canonical's documented security data
API; supports `page_size`, `page` and `modified_since` parameters). NOTE
(2026-11-07): the host does not resolve from this deployment's network, so
the sync degrades gracefully to a per-source error without affecting the
other feeds; override UBUNTU_API_URL to point at a reachable mirror/proxy.

Response: a JSON list of CVE objects, e.g.

    [{"id": "CVE-...", "description": "...", "priority": "medium",
      "notices_ids": ["USN-..."],
      "packages": {"openssl": {"jammy": {"status": "released",
                                          "version": "3.0.2-..."}}}}]

Ingest creates canonical records + AffectedProduct rows with released fixes
(source "ubuntu"), and a SourceRecord for provenance.
"""

import logging
from dataclasses import dataclass, field

from ..normalize import normalize_vuln_id

log = logging.getLogger("vulnwatch.ubuntu")

SOURCE = "ubuntu"
DEFAULT_URL = "https://cve.ubuntu.com/api/v0/cves/"
DETAIL_URL = "https://ubuntu.com/security/cve/{cve}"

_MAX_PACKAGES = 20


@dataclass
class UbuntuCve:
    vuln_id: str
    description: str | None
    priority: str | None
    notices: list[str] = field(default_factory=list)
    packages: dict = field(default_factory=dict)


def parse_cve_list(payload) -> list[UbuntuCve]:
    if not isinstance(payload, list):
        raise ValueError("unexpected Ubuntu CVE API page shape")
    out: list[UbuntuCve] = []
    for raw in payload:
        if not isinstance(raw, dict):
            continue
        cve = raw.get("id")
        if not isinstance(cve, str) or not cve.strip():
            continue
        packages = raw.get("packages") if isinstance(raw.get("packages"), dict) else {}
        slim: dict = {}
        for name, releases in list(packages.items())[:_MAX_PACKAGES]:
            if isinstance(releases, dict):
                slim[str(name)[:200]] = {
                    str(rel)[:64]: val for rel, val in releases.items()
                    if isinstance(val, dict)
                }
        out.append(
            UbuntuCve(
                vuln_id=normalize_vuln_id(cve),
                description=raw.get("description"),
                priority=raw.get("priority"),
                notices=[n for n in (raw.get("notices_ids") or []) if isinstance(n, str)],
                packages=slim,
            )
        )
    return out


def released_fixes(entry: UbuntuCve) -> list[dict]:
    """AffectedProduct-shaped rows for packages with a released fix."""
    out: list[dict] = []
    for package, releases in entry.packages.items():
        for release, info in releases.items():
            if info.get("status") == "released" and info.get("version"):
                out.append(
                    {
                        "vendor": "Ubuntu",
                        "product": package,
                        "release": release,
                        "fixes": [str(info["version"])],
                    }
                )
    return out[:_MAX_PACKAGES]


def ubuntu_data(entry: UbuntuCve) -> dict:
    return {
        "kind": "ubuntu-cve",
        "priority": entry.priority,
        "notices": entry.notices[:20],
        "packages": entry.packages,
        "url": DETAIL_URL.format(cve=entry.vuln_id),
    }
