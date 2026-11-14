"""CISA Cybersecurity Advisories adapter — CISA AA advisory context.

Source: the CISA "Cybersecurity Advisories" RSS feed
(https://www.cisa.gov/cybersecurity-advisories/all.xml, includes Alerts,
Advisories and Malware Analysis Reports). NOTE (2026-11-07): cisa.gov is
blocked from this deployment's network (Akamai 403 for non-browser clients),
so the sync degrades gracefully to a per-source error without affecting the
other feeds; override CISA_ADVISORIES_URL to point at a reachable mirror.

RSS 2.0 shape:

    <rss><channel>
      <item><title>...</title><link>...</link>
            <pubDate>...</pubDate><description>...</description></item>
    </channel></rss>

CVE linkage: CISA advisories often reference CVE ids in the title/description
text; a strict regex extracts them and only canonical CVEs get a SourceRecord
(the advisories are kept as vulnerability context, not as standalone rows).
"""

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from ..normalize import normalize_vuln_id

log = logging.getLogger("vulnwatch.cisa_advisories")

SOURCE = "cisa_advisories"
DEFAULT_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_MAX_CVES_PER_ITEM = 20


@dataclass
class AdvisoryItem:
    title: str | None
    url: str | None
    published: str | None
    description: str | None
    cves: list[str] = field(default_factory=list)


def parse_rss(payload: bytes | str) -> list[AdvisoryItem]:
    """Parse the RSS feed; raises on unparsable XML."""
    root = ET.fromstring(payload)
    items: list[AdvisoryItem] = []
    for item_el in root.iter("item"):
        title = item_el.findtext("title")
        link = item_el.findtext("link")
        published = item_el.findtext("pubDate")
        description = item_el.findtext("description")
        text_blob = " ".join(x for x in (title, description) if x)
        cves: list[str] = []
        for token in _CVE_RE.findall(text_blob):
            norm = normalize_vuln_id(token)
            if norm not in cves:
                cves.append(norm)
        items.append(
            AdvisoryItem(
                title=title,
                url=link.strip() if link and link.strip() else None,
                published=published.strip() if published else None,
                description=(description or "")[:500] or None,
                cves=cves[:_MAX_CVES_PER_ITEM],
            )
        )
    return items


def advisory_data(item: AdvisoryItem) -> dict:
    return {
        "kind": "cisa-advisory",
        "title": item.title,
        "published": item.published,
        "excerpt": item.description,
        "url": item.url,
    }
