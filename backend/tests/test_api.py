"""API endpoint tests."""

import pytest
from datetime import datetime, timedelta, timezone

from app.collector import ingest_cve_now_entries, ingest_kev_catalog
from app.models import WatchlistItem
from app.sources.cisa_kev import KevEntry
from app.sources.cve_now import CveNowEntry


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
