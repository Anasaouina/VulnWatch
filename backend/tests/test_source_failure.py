"""Tests for sync-state behavior: preserve last good data on source failure."""

import pytest
from sqlalchemy import select, func

from app import collector
from app.collector import run_sync
from app.config import Settings
from app.collector import ingest_cve_now_entries
from app.models import SyncState, Vulnerability, SourceRecord
from app.sources.cve_now import CveNowEntry

from datetime import datetime, timezone


def func_count(model):
    return func.count(model.id)


def _good_s(factory):
    with factory() as s:
        ingest_cve_now_entries(
            s,
            [CveNowEntry(vuln_id="CVE-2026-1000", title="Good data", cvss=5.0, raw={"id": "CVE-2026-1000"})],
        )
        s.commit()


def _set_last_success(factory):
    with factory() as s:
        st = s.execute(select(SyncState).where(SyncState.source == "cve_now")).scalar_one_or_none()
        if st is None:
            st = SyncState(source="cve_now")
            s.add(st)
        now = datetime(2026, 11, 6, 10, 0, tzinfo=timezone.utc)
        st.checkpoint = {"watermark": now.isoformat()}
        st.last_success_at = now
        st.status = "success"
        s.commit()


def test_failed_source_run_preserves_data_and_checkpoint(factory, monkeypatch):
    """A failing cve.now page fetch must keep records and not advance state."""
    _good_s(factory)
    _set_last_success(factory)

    class Boom:
        def list_entries(self, cursor=None):
            raise RuntimeError("upstream 503")

    monkeypatch.setattr(collector.cve_now, "CveNowClient", lambda *a, **k: Boom())
    monkeypatch.setattr(collector, "enrich_from_detail", lambda *a, **k: 0)

    s_settings = Settings(database_url="sqlite://")
    s_settings.cve_now_page_pause_seconds = 0
    results = run_sync(factory, s_settings, sources=["cve_now"])

    assert results["cve_now"]["status"] == "error"
    with factory() as s:
        v = s.execute(
            select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2026-1000")
        ).scalar_one()
        assert v.title == "Good data"
        assert s.execute(func_count(SourceRecord)).scalar() == 1
        st = s.execute(select(SyncState).where(SyncState.source == "cve_now")).scalar_one()
        assert st.status == "error"
        assert "RuntimeError" in (st.error_message or "")
        # checkpoint and last success not advanced
        assert st.checkpoint["watermark"] == "2026-11-06T10:00:00+00:00"
        expected = datetime(2026, 11, 6, 10, 0, tzinfo=timezone.utc).replace(tzinfo=None)
        assert st.last_success_at == expected


def test_malformed_payload_persists_error(factory, monkeypatch):
    from app.sources.cisa_kev import parse_catalog

    with pytest.raises(ValueError):
        parse_catalog({"nope": True})
    with pytest.raises(ValueError):
        parse_catalog("not a dict")
    with pytest.raises(ValueError):
        parse_catalog({"vulnerabilities": "nope"})


def test_kev_after_error_keeps_old_records(factory, monkeypatch):
    _good_s(factory)
    with factory() as s:
        s.add(
            SyncState(
                source="cisa_kev",
                status="success",
                last_success_at=datetime(2026, 11, 5, 9, 0, tzinfo=timezone.utc),
            )
        )
        s.commit()

    def boom(*a, **k):
        raise RuntimeError("feed timeout")

    monkeypatch.setattr(collector, "sync_cisa_kev", boom)
    monkeypatch.setattr(collector, "enrich_from_detail", lambda *a, **k: 0)

    s_settings = Settings(database_url="sqlite://")
    results = run_sync(factory, s_settings, sources=["cisa_kev"])
    assert results["cisa_kev"]["status"] == "error"
    with factory() as s:
        st = s.execute(select(SyncState).where(SyncState.source == "cisa_kev")).scalar_one()
        assert st.status == "error"
        expected = datetime(2026, 11, 5, 9, 0, tzinfo=timezone.utc).replace(tzinfo=None)
        assert st.last_success_at == expected
        # data from other sources stays untouched
        assert s.execute(func_count(Vulnerability)).scalar() == 1
