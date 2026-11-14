"""FIRST EPSS (Exploit Prediction Scoring System) adapter.

Data semantics (documented by FIRST at https://www.first.org/epss/data and
https://www.first.org/epss/data_stats; verified live against the bulk file and
the API on 2026-11-07):

- epss: probability [0, 1] of exploitation in the wild in the next 30 days
  (following score publication).
- percentile: proportion of all scored vulnerabilities with the same or a
  lower EPSS score.

Two access paths, used exactly as FIRST documents them:

- BULK (routine sync): the daily CSV gzip file referenced by a single stable
  URL, https://epss.empiricalsecurity.com/epss_scores-current.csv.gz (the URL
  redirects, so the client must follow redirects). File format:

      #model_version:v2023.03.01,score_date:2023-03-07T00:00:00+00:00
      cve,epss,percentile
      CVE-1999-0001,0.0046,0.7385
      ...

- API (on-demand single-CVE lookup only — never bulk sync):
  https://api.first.org/data/v1/epss?cve=CVE-... returning
  {"data": [{"cve": ..., "epss": "...", "percentile": "...", "date": ...}]}.

Error policy mirrors the other adapters: a structurally broken file (missing
meta line, wrong header, non-numeric masses) raises so the fetch is marked
failed and the last good EPSS data is preserved; individually malformed rows
are skipped with a warning so one bad line cannot corrupt valid data.
"""

import gzip
import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone

from ..normalize import normalize_vuln_id

log = logging.getLogger("vulnwatch.epss")

BULK_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
API_URL = "https://api.first.org/data/v1/epss"
SOURCE = "first_epss"
PROVENANCE_URL = "https://www.first.org/epss/data"

_META_LINE_RE = re.compile(
    r"^#\s*model_version:(?P<model>\S+)\s*,\s*score_date:(?P<dt>\S+)\s*$"
)
_CVE_TOKEN_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass
class EpssEntry:
    vuln_id: str
    score: float
    percentile: float
    score_date: date


@dataclass
class EpssFeed:
    score_date: date
    model_version: str | None
    entries: list[EpssEntry] = field(default_factory=list)
    skipped_rows: int = 0


class ParseError(ValueError):
    """Structurally invalid EPSS feed (fail loudly, keep last good data)."""


def _parse_row(cve_raw: str, score_raw: str, percentile_raw: str, score_date: date) -> EpssEntry:
    cve = normalize_vuln_id(cve_raw)
    if not _CVE_TOKEN_RE.match(cve):
        raise ValueError(f"not a CVE id: {cve_raw!r}")
    score = float(score_raw)
    percentile = float(percentile_raw)
    if not (0.0 <= score <= 1.0):
        raise ValueError(f"EPSS score out of [0,1] range: {score_raw!r}")
    if not (0.0 <= percentile <= 1.0):
        raise ValueError(f"EPSS percentile out of [0,1] range: {percentile_raw!r}")
    return EpssEntry(
        vuln_id=cve,
        score=round(score, 6),
        percentile=round(percentile, 6),
        score_date=score_date,
    )


def _score_date_from_meta(meta_datetime: str) -> date:
    dt = datetime.fromisoformat(meta_datetime.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).date()


def parse_feed(raw: bytes | str) -> EpssFeed:
    """Parse the EPSS bulk CSV (plain text or gzip).

    Raises ValueError on structural problems; skips malformed individual rows.
    """
    if isinstance(raw, bytes):
        try:
            raw = gzip.decompress(raw)
        except OSError:
            # not gzip: fall through and parse the bytes as text
            pass
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    lines = raw.splitlines()
    if not lines or not lines[0].lstrip().startswith("#"):
        raise ValueError("EPSS feed missing #model_version/score_date meta line")
    meta = _META_LINE_RE.match(lines[0].lstrip())
    if meta is None:
        raise ValueError(f"unrecognized EPSS meta line: {lines[0][:80]!r}")
    try:
        score_date = _score_date_from_meta(meta.group("dt"))
    except ValueError as exc:
        raise ValueError(f"invalid EPSS score_date in meta line: {exc}") from None
    if not lines[1].strip().lower().startswith("cve,"):
        raise ValueError(f"unexpected EPSS header row: {lines[1][:80]!r}")

    feed = EpssFeed(score_date=score_date, model_version=meta.group("model"))
    for lineno, line in enumerate(lines[2:], start=3):
        line = line.strip()
        if not line:
            continue
        parts = line.split(",")
        if len(parts) < 3:
            log.warning("EPSS row %d has too few columns, skipped: %r", lineno, line[:60])
            feed.skipped_rows += 1
            continue
        try:
            feed.entries.append(_parse_row(parts[0], parts[1], parts[2], score_date))
        except (TypeError, ValueError) as exc:
            log.warning("EPSS row %d malformed, skipped (%s): %r", lineno, exc, line[:60])
            feed.skipped_rows += 1
    log.info(
        "EPSS feed %s (model %s): %d rows, %d skipped",
        score_date,
        feed.model_version,
        len(feed.entries),
        feed.skipped_rows,
    )
    return feed


def parse_api_response(payload) -> tuple[list[EpssEntry], date | None]:
    """Parse the on-demand single-CVE (or small batch) API response.

    Shape verified live 2026-11-07:
    {"status": "OK", "data": [{"cve": ..., "epss": "...", "percentile": "...",
                               "date": "YYYY-MM-DD"}]}
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValueError("unexpected EPSS API response shape")
    entries: list[EpssEntry] = []
    feed_date: date | None = None
    for raw in payload["data"]:
        if not isinstance(raw, dict):
            continue
        try:
            entry_date = date.fromisoformat(str(raw.get("date", "")))
        except ValueError:
            log.warning("EPSS API entry with bad date skipped: %r", raw.get("cve"))
            continue
        try:
            entries.append(
                _parse_row(
                    str(raw.get("cve", "")), str(raw.get("epss", "")),
                    str(raw.get("percentile", "")), entry_date,
                )
            )
        except (TypeError, ValueError) as exc:
            log.warning("EPSS API entry malformed, skipped (%s): %r", exc, raw.get("cve"))
            continue
        if feed_date is None or entry_date > feed_date:
            feed_date = entry_date
    return entries, feed_date


def lookup(client, cve: str, base_url: str = API_URL) -> EpssEntry | None:
    """On-demand single-CVE lookup through the official EPSS API.

    Use only for single CVEs (e.g. interactive queries); bulk sync must use
    the daily CSV instead. Returns None when the CVE is not scored or not a
    CVE ID. `client` is an httpx.Client.
    """
    canonical = normalize_vuln_id(cve)
    if not _CVE_TOKEN_RE.match(canonical):
        return None
    resp = client.get(base_url, params={"cve": canonical})
    resp.raise_for_status()
    entries, _ = parse_api_response(resp.json())
    for e in entries:
        if e.vuln_id == canonical:
            return e
    return None
