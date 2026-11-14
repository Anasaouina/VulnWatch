"""Metasploit Framework adapter — exploit module availability per CVE.

Source: rapid7/metasploit-framework `db/modules_metadata_base.json`
(https://github.com/rapid7/metasploit-framework, verified live 2026-11-07):
a large JSON object keyed by module fullname, e.g.

    "exploit/windows/smb/ms17_010_eternalblue": {
        "name": "...", "fullname": "...", "rank": "great",
        "references": ["CVE-2017-0143", "URL-...", "MSB-MS17-010"], ...
    }

CVE linkage: entries in `references` matching CVE-YYYY-NNNN. Enrichment-only:
no canonical records are created; each CVE gets one SourceRecord payload
listing every module that references it.
"""

import logging
import re
from dataclasses import dataclass

from ..normalize import normalize_vuln_id

log = logging.getLogger("vulnwatch.metasploit")

SOURCE = "metasploit"
DEFAULT_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/"
    "master/db/modules_metadata_base.json"
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@dataclass
class MetasploitModule:
    fullname: str
    name: str | None
    rank: str | None
    disclosed_at: str | None
    cves: list[str]


def parse_modules(payload) -> list[MetasploitModule]:
    """Parse the module metadata object; raises on shape drift."""
    if not isinstance(payload, dict) or not payload:
        raise ValueError("unexpected Metasploit metadata shape")
    out: list[MetasploitModule] = []
    for fullname, mod in payload.items():
        if not isinstance(mod, dict) or not isinstance(mod.get("references"), list):
            continue
        cves: list[str] = []
        for ref in mod["references"]:
            if not isinstance(ref, str):
                continue
            for token in _CVE_RE.findall(ref):
                norm = normalize_vuln_id(token)
                if norm not in cves:
                    cves.append(norm)
        if not cves:
            continue
        out.append(
            MetasploitModule(
                fullname=fullname,
                name=(mod.get("name") or None),
                rank=(mod.get("rank") or None),
                disclosed_at=(mod.get("disclosureDate") or mod.get("disclosed_at") or None),
                cves=cves,
            )
        )
    return out


def module_data(module: MetasploitModule) -> dict:
    return {
        "kind": "metasploit-module",
        "module": module.fullname,
        "name": module.name,
        "rank": module.rank,
        "disclosureDate": module.disclosed_at,
        "url": f"https://github.com/rapid7/metasploit-framework/blob/master/modules/{module.fullname}.md",
    }
