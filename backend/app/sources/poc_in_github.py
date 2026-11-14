"""PoC-in-GitHub adapter — public PoC repository evidence per CVE.

Source: nomi-sec/PoC-in-GitHub (https://github.com/nomi-sec/PoC-in-GitHub,
verified live 2026-11-07): one JSON file per CVE, e.g.

    https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/
        master/2025/CVE-2025-0054.json

The file content is a list of PoC repository entries, e.g.

    [{"owner": {"login": "…"}, "html_url": "https://github.com/…",
      "created_at": "2025-01-05T...", "description": "…"}, ...]

Enrichment-only, on-demand: for canonical CVEs (newest first) that lack a
record, fetch up to `max_per_run` per-CVE files per collector cycle. This
never mirrors the whole dataset (which is tens of thousands of files) and
respects the raw.githubusercontent.com service.
"""

import logging

import httpx

from ..normalize import normalize_vuln_id

log = logging.getLogger("vulnwatch.poc_in_github")

SOURCE = "poc_in_github"
DEFAULT_BASE_URL = (
    "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
)


def cve_file_url(base_url: str, vuln_id: str) -> str | None:
    """The repo layout is one file per year directory: {base}/{year}/{CVE}.json."""
    import re

    match = re.match(r"CVE-(\d{4})-", vuln_id)
    if not match:
        return None
    return f"{base_url.rstrip('/')}/{match.group(1)}/{vuln_id}.json"


def parse_poc_file(payload) -> list[dict]:
    """Parse one per-CVE file into a compact list of PoC repo references."""
    if payload is None:
        return []
    if not isinstance(payload, list):
        raise ValueError("unexpected PoC-in-GitHub file shape")
    out: list[dict] = []
    for item in payload[:20]:
        if not isinstance(item, dict):
            continue
        url = item.get("html_url")
        if not isinstance(url, str) or not url.strip():
            continue
        owner = item.get("owner")
        out.append(
            {
                "url": url.strip(),
                "owner": owner.get("login") if isinstance(owner, dict) else None,
                "createdAt": item.get("created_at"),
                "description": (
                    item.get("description") or ""
                ).strip()[:300] or None,
            }
        )
    return out


def fetch_poc_file(
    client: httpx.Client, base_url: str, vuln_id: str, timeout: float
) -> list[dict] | None:
    """Fetch+parse one per-CVE file; None when the CVE has no PoC file (404)."""
    url = cve_file_url(base_url, vuln_id)
    if url is None:
        return None
    resp = client.get(url, timeout=timeout)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return parse_poc_file(resp.json())
