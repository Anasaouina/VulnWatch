"""Idempotent import tests: replaying the same feeds must not duplicate data."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, func

from app.collector import (
    ingest_cve_now_entries,
    ingest_kev_catalog,
)
from app.models import (
    AffectedProduct,
    CvssScore,
    SourceRecord,
    Vulnerability,
)
from app.sources.cisa_kev import KevEntry
from app.sources.cve_now import CveNowEntry


def _entries():
    now = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
    return [
        CveNowEntry(
            vuln_id="CVE-2026-1111",
            title="Docker engine flaw",
            published_at=now,
            first_seen_at=now,
            modified_at=now,
            cvss=7.5,
            stated_severity=None,
            kev=False,
            product="Docker Engine",
            fix_versions=["27.1"],
            raw={"id": "CVE-2026-1111", "title": "Docker engine flaw"},
        ),
        CveNowEntry(
            vuln_id="CVE-2026-2222",
            title="OpenSSH auth bypass",
            published_at=now - timedelta(hours=3),
            first_seen_at=now - timedelta(hours=3),
            modified_at=now - timedelta(hours=3),
            cvss=9.8,
            kev=True,
            product="OpenSSH",
            fix_versions=[],
            raw={"id": "CVE-2026-2222", "kev": True},
        ),
        # normalized id: lowercase + junk should map to the same canonical ID
        CveNowEntry(
            vuln_id="cve-2026-1111 ",
            title="Docker engine flaw (dupe form)",
            raw={"id": "cve-2026-1111"},
        ),
    ]


def _kev():
    return [
        KevEntry(
            vuln_id="CVE-2026-3333",
            vendor_project="pfSense",
            product="pfSense",
            vulnerability_name="pfSense command injection",
            date_added="2026-11-01",
            due_date="2026-11-15",
            short_description="Remote code execution in pfSense web UI.",
            required_action="Update pfSense.",
            ransomware_use="Known",
            notes_url="https://example.com/advisory",
            cwes=["CWE-77"],
            raw={},
        )
    ]


def test_replaying_cve_now_entries_creates_no_duplicates(factory):
    with factory() as s:
        for _ in range(3):
            ingest_cve_now_entries(s, _entries())
            s.commit()
        assert s.execute(select(func.count(Vulnerability.id))).scalar() == 2
        assert s.execute(select(func.count(SourceRecord.id))).scalar() == 2
        assert s.execute(select(func.count(CvssScore.id))).scalar() == 2
        assert s.execute(select(func.count(AffectedProduct.id))).scalar() == 2
        # the duplicate-shaped record normalizes to the same canonical ID;
        # later entries overwrite title fields (idempotent upsert semantics)
        vuln = s.execute(
            select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2026-1111")
        ).scalar_one()
        assert vuln.title == "Docker engine flaw (dupe form)"


def test_replaying_kev_catalog_creates_no_duplicates(factory):
    with factory() as s:
        for _ in range(2):
            ingest_kev_catalog(s, _kev(), "2026-11-06-r1")
            s.commit()
        assert s.execute(select(func.count(Vulnerability.id))).scalar() == 1
        assert s.execute(select(func.count(SourceRecord.id))).scalar() == 1
        assert s.execute(select(func.count(Vulnerability.id)).where(
            Vulnerability.is_kev.is_(True)
        )).scalar() == 1


def test_kev_only_record_merges_with_cve_now_record(factory):
    with factory() as s:
        ingest_kev_catalog(s, _kev(), "v1")
        s.commit()
        tow = [
            CveNowEntry(
                vuln_id="CVE-2026-3333",
                title="pfSense command injection",
                cvss=9.8,
                kev=True,
                raw={"id": "CVE-2026-3333"},
            )
        ]
        ingest_cve_now_entries(s, tow)
        s.commit()
        vulns = s.execute(select(Vulnerability)).scalars().all()
        assert len(vulns) == 1
        sources = s.execute(select(SourceRecord.source)).scalars().all()
        assert sorted(sources) == ["cisa_kev", "cve_now"]
        # KEV first-seen data is preserved
        v = vulns[0]
        assert v.is_kev is True
        assert v.kev_date_added == "2026-11-01"


def test_watchlist_matching_is_idempotent(factory):
    from app import matching
    from app.models import WatchlistItem, WatchlistMatch

    with factory() as s:
        s.add(WatchlistItem(name="Docker", keywords=["docker"]))
        s.commit()
        ingest_cve_now_entries(s, _entries())
        s.commit()
        for _ in range(2):
            matching.recompute_matches(s)
            s.commit()
        matches = s.execute(select(WatchlistMatch)).scalars().all()
        assert len(matches) == 1
        assert matches[0].match_type == "structured"
        assert matches[0].matched_term == "docker"
