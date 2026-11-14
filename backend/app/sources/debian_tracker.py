"""Debian Security Tracker adapter — distro fixed-in versions.

Source: the Debian security tracker's JSON export
(https://security-tracker.debian.org/tracker/data/json, verified live
2026-11-14, ~90 MB, no authentication). Top level is keyed by source package
name and CVE blocks hang directly below it:

    {"389-ds-base": {
        "CVE-2012-0833": {
            "description": "...", "debianbugs": ["1234"],
            "releases": {
                "bookworm": {"status": "resolved", "repositories": {
                    "bookworm": "1.2.3-4"}},
                "trixie": {"status": "open"}, ...
            }}, ...}, ...}

Enrichment-only: only CVEs already canonical are stored (the tracker covers
the whole CVE universe). For matched CVEs this stores per-release status and
fixed-in versions as a SourceRecord plus AffectedProduct rows (source
"debian_tracker"). Daily interval — the file is large.
"""

import logging

log = logging.getLogger("vulnwatch.debian_tracker")

SOURCE = "debian_tracker"
DEFAULT_URL = "https://security-tracker.debian.org/tracker/data/json"
DETAIL_URL = "https://security-tracker.debian.org/tracker/{cve}"

_MAX_PRODUCTS_PER_CVE = 20


def iter_cve_blocks(payload) -> list[tuple[str, dict]]:
    """Flatten the tracker export to (CVE, block) pairs.

    Verified live 2026-11-14: top level is keyed by source package and CVE
    blocks hang directly below it — {"389-ds-base": {"CVE-2012-0833": {...}}}.
    The parser also tolerates the older two-level nesting
    {"package": {"package": {"CVE-...": {...}}}} in case the layout shifts.
    Raises on shape drift; duplicate CVEs across packages yield once.
    """
    if not isinstance(payload, dict) or not payload:
        raise ValueError("unexpected Debian tracker JSON shape")
    out: dict[str, dict] = {}

    def _collect(mapping: dict) -> None:
        for cve, block in mapping.items():
            if (
                isinstance(cve, str)
                and cve.upper().startswith("CVE-")
                and isinstance(block, dict)
                and cve not in out
            ):
                out[cve] = block

    for key, value in payload.items():
        if not isinstance(value, dict):
            continue
        first = next(iter(value), None)
        if isinstance(first, str) and first.upper().startswith("CVE-"):
            _collect(value)  # {package: {CVE: block}} (current layout)
        else:
            for inner in value.values():
                if isinstance(inner, dict):
                    _collect(inner)  # legacy {package: {package: {CVE: block}}}
    if not out:
        raise ValueError("unexpected Debian tracker JSON keys")
    return list(out.items())


def _release_summary(cve_block: dict) -> dict:
    releases = cve_block.get("releases") if isinstance(cve_block, dict) else None
    out: dict[str, list[dict]] = {}
    if not isinstance(releases, dict):
        return out
    for release, info in releases.items():
        if not isinstance(info, dict):
            continue
        repos = info.get("repositories") if isinstance(info.get("repositories"), dict) else {}
        for package, fixed in repos.items():
            out.setdefault(release, []).append(
                {
                    "package": str(package)[:200],
                    "status": info.get("status"),
                    "fixed": str(fixed) if fixed else None,
                }
            )
        out[release] = out[release][:_MAX_PRODUCTS_PER_CVE]
    return out


def debian_data(vuln_id: str, cve_block: dict) -> dict:
    return {
        "kind": "debian-tracker",
        "bug": cve_block.get("debianbugs"),
        "releases": _release_summary(cve_block),
        "url": DETAIL_URL.format(cve=vuln_id),
    }
