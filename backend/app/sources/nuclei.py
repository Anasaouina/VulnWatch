"""Nuclei templates adapter (ProjectDiscovery) — detection-template coverage.

Source: projectdiscovery/nuclei-templates Git tree listing via the public
GitHub API (verified live 2026-11-07, ~4,600 CVE-mapped templates):

    GET https://api.github.com/repos/projectdiscovery/nuclei-templates/
        git/trees/main?recursive=1
    -> {"tree": [{"path": "code/cves/2014/CVE-2014-0160.yaml", ...}],
        "truncated": false}

CVE linkage: template file paths carrying a CVE id. Enrichment-only: one
SourceRecord per canonical CVE listing the template paths. The anonymous
GitHub API rate limit (60 requests/hour/IP) is fine for a daily tree pull.
"""

import logging
import re

from ..normalize import normalize_vuln_id

log = logging.getLogger("vulnwatch.nuclei")

SOURCE = "nuclei"
DEFAULT_URL = (
    "https://api.github.com/repos/projectdiscovery/nuclei-templates/"
    "git/trees/main?recursive=1"
)
TEMPLATE_URL = "https://github.com/projectdiscovery/nuclei-templates/blob/main/{path}"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def parse_tree(payload) -> dict[str, list[str]]:
    """Map normalized CVE id -> template paths. Raises on shape drift."""
    if not isinstance(payload, dict) or not isinstance(payload.get("tree"), list):
        raise ValueError("unexpected nuclei template tree shape")
    if payload.get("truncated"):
        log.warning("nuclei tree listing truncated; coverage may be partial")
    out: dict[str, list[str]] = {}
    for item in payload["tree"]:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if not isinstance(path, str) or "/cves/" not in path:
            continue
        for token in _CVE_RE.findall(path):
            cve = normalize_vuln_id(token)
            paths = out.setdefault(cve, [])
            if path not in paths:
                paths.append(path)
    return out


def nuclei_data(paths: list[str]) -> dict:
    return {
        "kind": "nuclei-template",
        "templateCount": len(paths),
        "templates": paths[:50],
        "url": TEMPLATE_URL.format(path=paths[0]),
    }
