"""EPSS adapter, ingestion, history and sync-state tests."""

import gzip
from datetime import date, datetime, timezone

import pytest
from sqlalchemy import func, select

from app import collector
from app.collector import ingest_epss_scores, sync_epss
from app.config import Settings
from app.models import (
    EpssHistory,
    EpssScore,
    SyncState,
    Vulnerability,
)
from app.sources.cve_now import CveNowEntry


def _feed_text(rows: dict[str, tuple[str, str]], score_date: str) -> str:
    lines = [f"#model_version:v2023.03.01,score_date:{score_date}", "cve,epss,percentile"]
    for cve, (score, pct) in rows.items():
        lines.append(f"{cve},{score},{pct}")
    return "\n".join(lines) + "\n"


def _feed_bytes(rows: dict[str, tuple[str, str]], score_date=None) -> bytes:
    if score_date is None:
        score_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00+00:00")
    return gzip.compress(_feed_text(rows, score_date).encode("utf-8"))


def _seed_vulns(factory, ids=("CVE-2026-1000", "CVE-2026-2000")):
    with factory() as s:
        collector.ingest_cve_now_entries(
            s,
            [CveNowEntry(vuln_id=v, title="x", cvss=8.1, raw={"id": v}) for v in ids],
        )
        s.commit()


def _epss_entry(cve, score, pct, score_date=None):
    from app.sources.epss import EpssEntry

    return EpssEntry(
        vuln_id=cve, score=float(score), percentile=float(pct),
        score_date=score_date or date(2026, 11, 7),
    )


# --- parsing -------------------------------------------------------------------

def test_parse_feed_happy_path_and_row_skipping():
    from app.sources.epss import parse_feed

    text = (
        "#model_version:v2023.03.01,score_date:2026-11-07T00:00:00+00:00\n"
        "cve,epss,percentile\n"
        "CVE-2026-1000,0.42,0.88\n"
        "cve-2026-2000,0.01,0.02\n"          # lowercase: normalized
        "garbage-entry,0.5,0.5\n"            # not a CVE id -> skipped
        "CVE-2026-3000,1.7,0.5\n"            # score out of range -> skipped
        "CVE-2026-4000,0.3,2.2\n"            # percentile out of range -> skipped
        "CVE-2026-5000,bad,0.5\n"            # non-numeric -> skipped
        "\n"
    )
    feed = parse_feed(text)
    assert feed.score_date == date(2026, 11, 7)
    assert feed.model_version == "v2023.03.01"
    assert [e.vuln_id for e in feed.entries] == ["CVE-2026-1000", "CVE-2026-2000"]
    assert feed.entries[0].score == pytest.approx(0.42)
    assert feed.entries[0].percentile == pytest.approx(0.88)
    assert feed.skipped_rows == 4


def test_parse_feed_accepts_gzip():
    from app.sources.epss import parse_feed

    feed = parse_feed(_feed_bytes({"CVE-2026-1000": ("0.1", "0.2")}))
    # the helper stamps today's UTC date into the meta line; the meta line is
    # authoritative and must round-trip through the parse
    assert feed.score_date == datetime.now(timezone.utc).date()
    assert len(feed.entries) == 1
    assert feed.entries[0].score_date == feed.score_date


def test_parse_feed_structural_failures():
    from app.sources.epss import parse_feed

    with pytest.raises(ValueError):
        parse_feed("cve,epss,percentile\nCVE-2026-1000,0.1,0.2\n")  # no meta line
    with pytest.raises(ValueError):
        parse_feed(
            "#model_version:vX,score_date:2026-11-07T00:00:00+00:00\n"
            "cve_id,epss,percentile\n"
        )  # wrong header
    with pytest.raises(ValueError):
        parse_feed(
            "#model_version:vX,score_date:not-a-date\n"
            "cve,epss,percentile\n"
        )  # bad meta date


def test_parse_api_response_and_lookup_filtering():
    from app.sources.epss import parse_api_response

    payload = {
        "status": "OK",
        "data": [
            {"cve": "CVE-2026-1000", "epss": "0.77", "percentile": "0.93", "date": "2026-11-07"},
            {"cve": "CVE-2026-1000", "epss": "broken", "percentile": "0.10", "date": "2026-11-07"},
        ],
    }
    entries, feed_date = parse_api_response(payload)
    assert feed_date == date(2026, 11, 7)
    assert [e.score for e in entries] == [pytest.approx(0.77)]


# --- ingestion ------------------------------------------------------------------

def test_ingest_epss_is_idempotent_and_canonical_only(factory):
    _seed_vulns(factory)
    feed = collector.epss.EpssFeed(
        score_date=date(2026, 11, 7),
        model_version="v2023.03.01",
        entries=[
            _epss_entry("CVE-2026-1000", 0.42, 0.88),
            _epss_entry("CVE-2026-2000", 0.03, 0.05),
            _epss_entry("CVE-2026-9999", 0.99, 0.99),  # not in canonical table
        ],
    )
    with factory() as s:
        result = ingest_epss_scores(s, feed, "https://epss.example/data")
        s.commit()
        assert result.matched == 2
        assert result.unknown_cves == 1
        assert result.history_written == 2
        # only canonical CVEs are stored; no new records for unknown CVEs
        assert s.execute(select(func.count(Vulnerability.id))).scalar() == 2
        assert s.execute(select(func.count(EpssScore.id))).scalar() == 2
        assert s.execute(select(func.count(EpssHistory.id))).scalar() == 2

        # replay: same values, updated in place, history stays one row/date
        result2 = ingest_epss_scores(s, feed, "https://epss.example/data")
        s.commit()
        assert result2.matched == 2
        assert result2.unknown_cves == 1
        assert result2.history_written == 0
        assert s.execute(select(func.count(EpssScore.id))).scalar() == 2
        assert s.execute(select(func.count(EpssHistory.id))).scalar() == 2

        # same CVE, one day later: new history snapshot, current row updated
        newer = collector.epss.EpssFeed(
            score_date=date(2026, 11, 8),
            model_version="v2023.03.01",
            entries=[_epss_entry("CVE-2026-1000", 0.55, 0.91, date(2026, 11, 8))],
        )
        result3 = ingest_epss_scores(s, newer, "https://epss.example/data")
        s.commit()
        assert result3.history_written == 1

        cur = s.execute(
            select(EpssScore).join(Vulnerability).where(Vulnerability.vuln_id == "CVE-2026-1000")
        ).scalar_one()
        assert cur.score == pytest.approx(0.55)
        assert cur.score_date == date(2026, 11, 8)
        assert cur.source == "first_epss"
        assert cur.source_url == "https://epss.example/data"
        assert cur.retrieved_at is not None
        hist = s.execute(
            select(EpssHistory).where(EpssHistory.vulnerability_id == cur.vulnerability_id)
            .order_by(EpssHistory.score_date)
        ).scalars().all()
        assert [h.score_date for h in hist] == [date(2026, 11, 7), date(2026, 11, 8)]


# --- sync state -----------------------------------------------------------------

def test_sync_epss_sets_checkpoint_and_is_daily(factory, monkeypatch):
    from app.http import FetchError

    _seed_vulns(factory)
    calls = {"n": 0}

    class Resp:
        status_code = 200
        content = _feed_bytes({"CVE-2026-1000": ("0.42", "0.88"), "CVE-2026-2000": ("0.03", "0.05")})

        def raise_for_status(self):
            return None

    def fake_fetch(client, url, **kwargs):
        calls["n"] += 1
        assert "epss" in url or "empiricalsecurity" in url
        return Resp()

    import app.http as http_mod
    monkeypatch.setattr(http_mod, "fetch", fake_fetch)

    s_settings = Settings(database_url="sqlite://")
    s_settings.epss_bulk_url = "https://epss.example/data"

    with factory() as s:
        r = sync_epss(s, s_settings)
        s.commit()
        assert r.matched == 2
        st = s.execute(select(SyncState).where(SyncState.source == "first_epss")).scalar_one()
        # the helper stamps today's UTC date; the checkpoint must match it
        assert st.checkpoint["score_date"] == datetime.now(timezone.utc).date().isoformat()

    # same-day re-run skips the download entirely (fetch would raise if called)
    def boom_fetch(*a, **k):
        raise FetchError("must not be fetched again")

    monkeypatch.setattr(http_mod, "fetch", boom_fetch)
    with factory() as s:
        r2 = sync_epss(s, s_settings)
        assert r2.up_to_date is True
        assert r2.matched == 0
    assert calls["n"] == 1


def test_failed_epss_fetch_preserves_values_and_checkpoint(factory, monkeypatch):
    _seed_vulns(factory)
    s_settings = Settings(database_url="sqlite://")
    from app.http import FetchError
    import app.http as http_mod

    # pre-state: a successful run yesterday left values and a checkpoint
    yesterday = datetime.now(timezone.utc).date()
    from datetime import timedelta

    yesterday -= timedelta(days=1)
    with factory() as s:
        vuln = s.execute(
            select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2026-1000")
        ).scalar_one()
        s.add(
            EpssScore(
                vulnerability_id=vuln.id, score=0.42, percentile=0.88,
                score_date=yesterday, retrieved_at=datetime.now(timezone.utc),
                source="first_epss", model_version="v2023.03.01",
            )
        )
        s.add(
            SyncState(
                source="first_epss", status="success",
                last_success_at=datetime(2026, 11, 6, 10, 0, tzinfo=timezone.utc),
                checkpoint={"score_date": yesterday.isoformat()},
            )
        )
        s.commit()

    # next day: fetch fails -> error state, values + checkpoint untouched
    def bad_fetch(*a, **k):
        raise FetchError("upstream 503 (VulnWatch does not log payloads)")

    monkeypatch.setattr(http_mod, "fetch", bad_fetch)

    results = collector.run_sync(factory, s_settings, sources=["first_epss"])
    assert results["first_epss"]["status"] == "error"
    with factory() as s:
        st = s.execute(select(SyncState).where(SyncState.source == "first_epss")).scalar_one()
        assert st.status == "error"
        assert st.checkpoint["score_date"] == yesterday.isoformat()
        assert st.last_success_at is not None
        # last good values still present
        assert (
            s.execute(select(func.count(EpssScore.id))).scalar() == 1
        )
        cur = s.execute(select(EpssScore)).scalar_one()
        assert cur.score == pytest.approx(0.42)
        assert s.execute(select(func.count(EpssHistory.id))).scalar() == 0


def test_epss_failure_does_not_block_other_sources(factory, monkeypatch):
    from datetime import timedelta

    _seed_vulns(factory)

    def boom(*a, **k):
        raise RuntimeError("epss down")

    import app.http as http_mod
    monkeypatch.setattr(http_mod, "fetch", boom)

    ok = datetime.now(timezone.utc) - timedelta(hours=1)
    class FakeCveNow:
        def list_entries(self, cursor=None):
            return (
                [
                    CveNowEntry(
                        vuln_id="CVE-2026-1000", title="refreshed", cvss=7.1,
                        published_at=ok, first_seen_at=ok, modified_at=ok,
                        raw={"id": "CVE-2026-1000"},
                    )
                ],
                None,
            )

    monkeypatch.setattr(collector.cve_now, "CveNowClient", lambda *a, **k: FakeCveNow())
    monkeypatch.setattr(collector, "enrich_from_detail", lambda *a, **k: 0)

    s_settings = Settings(database_url="sqlite://")
    results = collector.run_sync(factory, s_settings, sources=["cve_now", "first_epss"])
    # cve.now succeeded while EPSS failed independently
    assert results["cve_now"]["status"] == "success"
    assert results["first_epss"]["status"] == "error"
    with factory() as s:
        assert s.execute(
            select(func.count(EpssScore.id))
        ).scalar() == 0  # nothing corrupted
