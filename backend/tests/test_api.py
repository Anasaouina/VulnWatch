"""API endpoint tests."""

import pytest
from datetime import date, datetime, timedelta, timezone

from app.collector import ingest_cve_now_entries, ingest_kev_catalog, ingest_epss_scores
from app.models import WatchlistItem
from app.sources.cisa_kev import KevEntry
from app.sources.cve_now import CveNowEntry


def _epss_feed(entries, score_date):
    from app import collector as collector_mod

    return collector_mod.epss.EpssFeed(
        score_date=score_date, model_version="v2023.03.01", entries=entries
    )


@pytest.fixture()
def seeded(factory):
    from app import matching

    now = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
    with factory() as session:
        ingest_cve_now_entries(
            session,
            [
                CveNowEntry(
                    vuln_id="CVE-2026-1111",
                    title="Docker engine race condition",
                    published_at=now,
                    first_seen_at=now,
                    modified_at=now,
                    cvss=8.1,
                    kev=True,
                    product="Docker Engine",
                    raw={"id": "CVE-2026-1111"},
                ),
                CveNowEntry(
                    vuln_id="CVE-2026-2222",
                    title="Unrelated library issue",
                    published_at=now - timedelta(hours=30),
                    first_seen_at=now - timedelta(hours=30),
                    modified_at=now - timedelta(hours=30),
                    cvss=5.0,
                    kev=False,
                    raw={"id": "CVE-2026-2222"},
                ),
                CveNowEntry(
                    vuln_id="CVE-2026-3333",
                    title="GHSA advisory without score",
                    cvss=None,
                    stated_severity="critical",
                    raw={"id": "CVE-2026-3333"},
                ),
            ],
        )
        ingest_kev_catalog(
            session,
            [
                KevEntry(
                    vuln_id="CVE-2026-1111",
                    vendor_project="Docker",
                    product="Engine",
                    vulnerability_name="Docker Engine race",
                    date_added="2026-11-05",
                    due_date="2026-11-19",
                    short_description="Remote code execution in Docker Engine.",
                    required_action="Update.",
                    ransomware_use="Unknown",
                    notes_url=None,
                    cwes=[],
                    raw={},
                )
            ],
            "v1",
        )
        # EPSS enrichment for the two scored CVEs (2026-1111 handled by KEV rule)
        from app.sources.epss import EpssEntry

        ingest_epss_scores(
            session,
            _epss_feed(
                [
                    EpssEntry("CVE-2026-1111", 0.7, 0.95, date(2026, 11, 7)),
                    EpssEntry("CVE-2026-2222", 0.004, 0.12, date(2026, 11, 7)),
                    EpssEntry("CVE-2026-4444", 0.9, 0.99, date(2026, 11, 7)),  # not canonical: dropped
                ],
                date(2026, 11, 7),
            ),
            "https://epss.example/data",
        )
        matching.recompute_matches(session)
        session.commit()
    return True


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["database"] == "ok"


def test_list_sort_and_pagination(client, seeded):
    r = client.get("/api/vulns?page=1&page_size=2")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert body["pages"] == 2
    items = body["items"]
    # newest first, deterministic
    assert items[0]["vuln_id"] == "CVE-2026-1111"
    page2 = client.get("/api/vulns?page=2&page_size=2").json()
    assert page2["items"][0]["vuln_id"] != items[0]["vuln_id"]


def test_list_severity_filter(client, seeded):
    body = client.get("/api/vulns?severity=critical").json()
    assert {i["vuln_id"] for i in body["items"]} == {"CVE-2026-3333"}
    body = client.get("/api/vulns?severity=high").json()
    assert {i["vuln_id"] for i in body["items"]} == {"CVE-2026-1111"}
    body = client.get("/api/vulns?severity=unknown").json()
    assert body["items"] == []


def test_list_kev_and_search_filters(client, seeded):
    body = client.get("/api/vulns?kev_only=true").json()
    assert {i["vuln_id"] for i in body["items"]} == {"CVE-2026-1111"}
    assert body["items"][0]["kev_date_added"] == "2026-11-05"
    body = client.get("/api/vulns?q=docker").json()
    assert {i["vuln_id"] for i in body["items"]} == {"CVE-2026-1111"}
    body = client.get("/api/vulns?q=CVE-2026-2222").json()
    assert {i["vuln_id"] for i in body["items"]} == {"CVE-2026-2222"}


def test_list_invalid_params(client, seeded):
    assert client.get("/api/vulns?page=0").status_code == 422
    assert client.get("/api/vulns?page_size=1000").status_code == 422
    assert client.get("/api/vulns?severity=banana").status_code == 422
    assert client.get("/api/vulns?date_from=not-a-date").status_code == 422


def test_vuln_detail_provenance(client, seeded):
    r = client.get("/api/vulns/CVE-2026-1111")
    assert r.status_code == 200
    body = r.json()
    assert body["vuln_id"] == "CVE-2026-1111"
    assert body["kev"] is True
    assert body["summary_source"] == "cisa_kev:short_description"
    sources = {s["source"] for s in body["source_records"]}
    assert sources == {"cve_now", "cisa_kev"}
    assert all(s["url"] is None or s["url"].startswith("http") for s in body["source_records"])

    r = client.get("/api/vulns/cve-2026-1111")
    assert r.status_code == 200

    r = client.get("/api/vulns/CVE-9999-0000")
    assert r.status_code == 404


def test_watchlist_crud_and_matches(client, seeded):
    items = client.get("/api/watchlist").json()["items"]
    names = {i["name"] for i in items}
    assert {"OpenSSH", "Wazuh", "pfSense", "Docker"} <= names

    r = client.post("/api/watchlist", json={"name": "Racecar", "keywords": []})
    assert r.status_code == 201
    r = client.post("/api/watchlist", json={"name": "racecar", "keywords": []})
    assert r.status_code == 409

    rid = None
    listing = client.get("/api/watchlist").json()["items"]
    item = next(i for i in listing if i["name"] == "Racecar")
    r = client.patch(f"/api/watchlist/{item['id']}", json={"name": "Racecar 2", "keywords": ["racecar"]})
    assert r.status_code == 200
    assert r.json()["name"] == "Racecar 2"

    r = client.delete(f"/api/watchlist/{item['id']}")
    assert r.status_code == 204
    listing = client.get("/api/watchlist").json()["items"]
    assert not any(i["name"] == "Racecar 2" for i in listing)

    assert client.get(f"/api/watchlist/{item['id']}").status_code in (404, 405)


def test_missing_data_renders_unknowns(client, seeded):
    body = client.get("/api/vulns/CVE-2026-3333").json()
    assert body["cvss_score"] is None
    assert body["stated_severity"] == "critical"
    assert body["severity_bucket"] == "critical"
    assert body["published_at"] is None
    assert body["watchlist_matches"] == []


# --- EPSS / KEV context / priority ---------------------------------------------

def test_list_includes_epss_and_priority(client, seeded):
    body = client.get("/api/vulns").json()
    assert body["total"] == 3  # unknown-CVE EPSS entry created nothing
    by_id = {i["vuln_id"]: i for i in body["items"]}
    kev_item = by_id["CVE-2026-1111"]
    assert kev_item["epss_score"] == pytest.approx(0.7)
    assert kev_item["epss_percentile"] == pytest.approx(0.95)
    assert kev_item["epss_score_date"] == "2026-11-07"
    assert kev_item["priority"] == "urgent"
    assert "VulnWatch assessment" in kev_item["priority_note"]
    assert kev_item["kev_date_added"] == "2026-11-05"
    mid = by_id["CVE-2026-2222"]
    assert mid["priority"] == "low"  # tiny EPSS with medium CVSS
    # backward compatibility: previously exposed fields still present
    for legacy in ("vuln_id", "title", "severity_bucket", "cvss_score",
                   "kev", "watchlist_matches"):
        assert legacy in mid


def test_detail_includes_kev_context_epss_and_history(client, seeded):
    body = client.get("/api/vulns/CVE-2026-1111").json()
    assert body["kev_required_action"] == "Update."
    assert body["kev_due_date"] == "2026-11-19"
    assert body["kev_ransomware_use"] == "Unknown"
    assert body["priority"] == "urgent"
    assert any("CISA" in r for r in body["priority_reasons"])
    assert body["epss_source"] == "first_epss"
    assert body["epss_source_url"] == "https://epss.example/data"
    assert body["epss_retrieved_at"] is not None
    assert body["epss_model_version"] == "v2023.03.01"
    assert len(body["epss_history"]) == 1
    snap = body["epss_history"][0]
    assert snap["score_date"] == "2026-11-07"
    assert snap["score"] == pytest.approx(0.7)
    assert snap["source"] == "first_epss"

    unscored = client.get("/api/vulns/CVE-2026-3333").json()
    assert unscored["epss_score"] is None
    assert unscored["epss_history"] == []
    assert unscored["epss_retrieved_at"] is None


def test_epss_filters_and_sorting(client, seeded):
    body = client.get("/api/vulns?min_epss=0.5").json()
    assert {i["vuln_id"] for i in body["items"]} == {"CVE-2026-1111"}
    body = client.get("/api/vulns?min_epss_percentile=0.5").json()
    assert {i["vuln_id"] for i in body["items"]} == {"CVE-2026-1111"}
    body = client.get("/api/vulns?priority=urgent").json()
    assert {i["vuln_id"] for i in body["items"]} == {"CVE-2026-1111"}
    body = client.get("/api/vulns?priority=low").json()
    assert body["total"] >= 1
    assert client.get("/api/vulns?min_epss=2").status_code == 422
    assert client.get("/api/vulns?sort=bogus").status_code == 422

    order = client.get("/api/vulns?sort=epss_desc").json()["items"]
    ids = [i["vuln_id"] for i in order]
    assert ids[0] == "CVE-2026-1111"
    order = client.get("/api/vulns?sort=priority_desc").json()["items"]
    prio = [i["priority"] for i in order]
    rank = {"urgent": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    assert prio == sorted(prio, key=lambda p: rank[p], reverse=True)


def test_ransomware_filter(client):
    from app.collector import ingest_kev_catalog
    from app.sources.cisa_kev import KevEntry

    # app.state.session_factory is wired to the same test engine via conftest
    with client.app.state.session_factory() as s:
        ingest_cve_now_entries(
            s,
            [
                CveNowEntry(
                    vuln_id="CVE-2026-8888", title="Ransomware target", cvss=9.0,
                    raw={"id": "CVE-2026-8888"},
                ),
                CveNowEntry(
                    vuln_id="CVE-2026-7777", title="Ransomware quiet", cvss=9.0,
                    raw={"id": "CVE-2026-7777"},
                ),
            ],
        )
        ingest_kev_catalog(
            s,
            [
                KevEntry(
                    vuln_id="CVE-2026-8888", vendor_project="X", product="Y",
                    vulnerability_name="X", date_added="2026-11-01", due_date=None,
                    short_description=None, required_action=None,
                    ransomware_use="Known", notes_url=None, cwes=[], raw={},
                ),
                KevEntry(
                    vuln_id="CVE-2026-7777", vendor_project="X", product="Y",
                    vulnerability_name="X", date_added="2026-11-01", due_date=None,
                    short_description=None, required_action=None,
                    ransomware_use="Unknown", notes_url=None, cwes=[], raw={},
                ),
            ],
            "v1",
        )
        s.commit()

    body = client.get("/api/vulns?ransomware_only=true").json()
    assert {i["vuln_id"] for i in body["items"]} == {"CVE-2026-8888"}
    listed = client.get("/api/vulns?kev_only=true").json()
    assert listed["total"] == 2


def test_kev_context_fields_not_erased_by_later_feed(factory):
    from app.collector import ingest_kev_catalog
    from sqlalchemy import select
    from app.models import Vulnerability

    entry = dict(
        vuln_id="CVE-2026-5555", vendor_project="A", product="B",
        vulnerability_name="n", date_added="2026-11-01",
        short_description=None, required_action="Do the thing.",
        ransomware_use="Known", notes_url=None, cwes=[], raw={},
    )
    with factory() as s:
        ingest_kev_catalog(s, [KevEntry(due_date="2026-12-01", **entry)], "v1")
        s.commit()
        # later feed omitted due_date/required_action/ransomware fields
        ingest_kev_catalog(s, [KevEntry(due_date=None, **entry)], "v2")
        s.commit()
        v = s.execute(
            select(Vulnerability).where(Vulnerability.vuln_id == "CVE-2026-5555")
        ).scalar_one()
        assert v.kev_due_date == "2026-12-01"
        assert v.kev_required_action == "Do the thing."
        assert v.kev_ransomware_use == "Known"
