"""Tests for the extended sources (NVD, GitHub Advisory, OSV, Exploit-DB,
Metasploit, Nuclei, PoC-in-GitHub, Red Hat, Debian, Ubuntu, CISA advisories,
ThreatFox, Vulners) — parsers, ingest policies, idempotency, key gating and
the API source filter."""

from app import collector
from app.collector import (
    _interval_due,
    ingest_cve_now_entries,
    ingest_nvd_entries,
    ingest_github_advisories,
    ingest_redhat_rows,
    ingest_ubuntu_entries,
    run_sync,
)
from app.config import Settings
from app.models import (
    AffectedProduct,
    CvssScore,
    SourceRecord,
    SyncState,
    Vulnerability,
)
from app.sources.cve_now import CveNowEntry


def _seed_vulns(factory, ids=("CVE-2026-1000", "CVE-2026-2000")):
    with factory() as s:
        ingest_cve_now_entries(
            s,
            [CveNowEntry(vuln_id=v, title="x", cvss=8.1, raw={"id": v}) for v in ids],
        )
        s.commit()


# --- NVD -----------------------------------------------------------------------

def test_nvd_parse_page():
    from app.sources.nvd import parse_nvd_page

    payload = {
        "resultsPerPage": 2,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "cve-2026-1000",
                    "published": "2026-11-01T12:00:00.000",
                    "lastModified": "2026-11-05T09:30:00.000",
                    "descriptions": [
                        {"lang": "fr", "value": "ignored"},
                        {"lang": "en", "value": "A flaw in widget handling. More detail."},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "baseScore": 7.5,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N",
                                },
                            }
                        ]
                    },
                    "references": [{"url": "https://example.com/a"}],
                }
            },
            {"cve": {"id": "", "descriptions": []}},  # unusable -> skipped
        ],
    }
    entries = parse_nvd_page(payload)
    assert len(entries) == 1
    e = entries[0]
    assert e.vuln_id == "CVE-2026-1000"
    assert e.summary.startswith("A flaw in widget")
    assert e.metrics[0].version == "3.1"
    assert e.metrics[0].score == 7.5
    assert e.metrics[0].vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"


def test_nvd_parse_rejects_bad_shape():
    import pytest
    from app.sources.nvd import parse_nvd_page

    with pytest.raises(ValueError):
        parse_nvd_page({"unexpected": True})


def test_nvd_ingest_creates_canonical_cvss_and_is_idempotent(factory):
    from app.sources.nvd import NvdCvssMetric, NvdEntry

    entry = NvdEntry(
        vuln_id="CVE-2026-1000",
        published="2026-11-01T12:00:00.000",
        last_modified="2026-11-05T09:30:00.000",
        title="A flaw",
        summary="A flaw in widget handling.",
        metrics=[NvdCvssMetric(version="3.1", score=7.5, vector="CVSS:3.1/AV:N", metric_source="nvd@nist.gov", metric_type="Primary")],
    )
    with factory() as s:
        assert ingest_nvd_entries(s, [entry]) == 1
        s.commit()
        assert ingest_nvd_entries(s, [entry]) == 1  # replay
        s.commit()

        vuln = s.query(Vulnerability).filter_by(vuln_id="CVE-2026-1000").one()
        assert vuln.summary == "A flaw in widget handling."
        assert vuln.summary_source == "nvd"
        rows = s.query(CvssScore).filter_by(vulnerability_id=vuln.id).all()
        assert len(rows) == 1  # unique (vuln, source, version), updated in place
        assert rows[0].score == 7.5
        assert rows[0].source == "nvd"
        assert rows[0].version == "3.1"
        rec = s.query(SourceRecord).filter_by(source="nvd", vuln_id="CVE-2026-1000").one()
        assert rec.data["kind"] == "nvd-cve"


# --- GitHub Advisory + OSV ------------------------------------------------------

def _gh_advisory(cve="CVE-2026-1000", ghsa="GHSA-test-test-test"):
    from app.sources.github_advisory import GithubAdvisory

    return GithubAdvisory(
        ghsa_id=ghsa,
        vuln_id=cve,
        summary="Widget overflow",
        description="Detailed description.",
        severity="high",
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        published_at="2026-11-02T00:00:00Z",
        updated_at="2026-11-06T00:00:00Z",
        vulnerabilities=[
            {
                "ecosystem": "PIP",
                "package": "widgets",
                "range": "<1.2",
                "firstPatched": "1.2",
            }
        ],
    )


def test_github_advisory_skips_ghsa_only():
    from app.sources.github_advisory import parse_advisories

    payload = [
        {"ghsa_id": "GHSA-x-y-z", "cve_id": None, "summary": "s"},
        {"ghsa_id": "GHSA-a-b-c", "cve_id": "CVE-2026-1000"},
    ]
    advs = parse_advisories(payload)
    assert [a.ghsa_id for a in advs] == ["GHSA-a-b-c"]


def test_github_advisory_ingest_creates_cvss_products(factory):
    with factory() as s:
        ingest_github_advisories(s, [_gh_advisory()])
        s.commit()
        ingest_github_advisories(s, [_gh_advisory()])  # idempotent replay
        s.commit()

        vuln = s.query(Vulnerability).filter_by(vuln_id="CVE-2026-1000").one()
        assert vuln.summary_source == "github_advisory"
        cvss = s.query(CvssScore).filter_by(source="github_advisory").all()
        assert len(cvss) == 1 and cvss[0].score == 7.5
        aps = s.query(AffectedProduct).filter_by(source="github_advisory").all()
        assert len(aps) == 1
        assert aps[0].fixes == ["1.2"]
        assert aps[0].versions == ["<1.2"]


def test_osv_parse_record():
    from app.sources.osv_dev import parse_osv_record

    rec = parse_osv_record(
        {
            "id": "GHSA-test-test-test",
            "modified": "2026-11-06T00:00:00Z",
            "aliases": ["CVE-2026-1000"],
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "widgets"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.2"}]}],
                }
            ],
        }
    )
    assert rec.osv_id == "GHSA-test-test-test"
    assert rec.aliases == ["CVE-2026-1000"]
    assert rec.affected_ecosystems == ["PyPI"]
    assert rec.first_patched == ["1.2"]


# --- Exploit-DB / Metasploit / Nuclei -------------------------------------------

def test_exploit_db_parse_csv():
    from app.sources.exploit_db import parse_exploits_csv

    csv_text = (
        "id,file,description,date_published,author,type,platform,port,date_added,"
        "date_updated,verified,codes,tags,aliases,screenshots\n"
        '19046,exploits/aix/dos/19046.txt,"Buffer Overflow",1999-10-15,"A",dos,aix,,'
        '1999-10-15,2014-01-02,1,CVE-1999-1015;OSVDB-5970,,,\n'
        '1,exploits/x/y.py,"Title mentioning CVE-2026-1000 in text",2026-01-01,"B",webapps,linux,,'
        '2026-01-01,2026-01-01,1,,, ,\n'
        '2,exploits/z/z.txt,"No CVE here",2020-01-01,"C",dos,windows,,2020-01-01,2020-01-01,0,,, ,\n'
    )
    entries = parse_exploits_csv(csv_text)
    cves = {e.vuln_id for e in entries}
    assert cves == {"CVE-1999-1015", "CVE-2026-1000"}
    assert all(e.edb_id > 0 for e in entries)


def test_metasploit_parse_modules():
    from app.sources.metasploit import parse_modules

    payload = {
        "exploit/a/b": {
            "name": "Module A",
            "references": ["CVE-2026-1000", "URL-1"],
            "rank": "great",
        },
        "auxiliary/c/d": {"name": "Module C", "references": []},
        "exploit/e/f": {"name": "Module F", "references": ["cve-2026-2000"]},
    }
    modules = parse_modules(payload)
    assert len(modules) == 2
    assert modules[0].cves == ["CVE-2026-1000"]


def test_nuclei_parse_tree():
    from app.sources.nuclei import parse_tree

    payload = {
        "truncated": False,
        "tree": [
            {"path": "code/cves/2014/CVE-2014-0160.yaml"},
            {"path": "code/cves/2014/cve-2026-1000.yaml"},
            {"path": "http/misc/readme.md"},
        ],
    }
    out = parse_tree(payload)
    assert set(out) == {"CVE-2014-0160", "CVE-2026-1000"}
    assert out["CVE-2014-0160"] == ["code/cves/2014/CVE-2014-0160.yaml"]


# --- Red Hat / Debian / Ubuntu ---------------------------------------------------

def test_redhat_parse_and_ingest(factory):
    from app.sources.redhat import parse_cve_rows

    payload = [
        {
            "CVE": "CVE-2026-1000",
            "severity": "moderate",
            "public_date": "2026-11-06T04:40:04Z",
            "bugzilla_description": "info disclosure in widget",
            "cvss3": {
                "cvss3_score": "5.9",
                "cvss3_scoring_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            },
            "affected_release": [
                {"package": "qt6-qtwebsockets-0:6.8.3-3.el9", "fix_state": "Affected",
                 "cpe": "cpe:/a:redhat:enterprise_linux:9"}
            ],
        }
    ]
    rows = parse_cve_rows(payload)
    assert rows[0].cvss3_score == 5.9

    with factory() as s:
        ingest_redhat_rows(s, rows)
        s.commit()
        ingest_redhat_rows(s, rows)
        s.commit()
        vuln = s.query(Vulnerability).filter_by(vuln_id="CVE-2026-1000").one()
        cvss = s.query(CvssScore).filter_by(source="redhat").one()
        assert cvss.score == 5.9 and cvss.version == "3.1"
        ap = s.query(AffectedProduct).filter_by(source="redhat").one()
        assert ap.product == "qt6-qtwebsockets"
        assert ap.fixes == ["6.8.3-3.el9"]


def test_debian_data_summary():
    from app.sources.debian_tracker import debian_data, iter_cve_blocks

    # the export nests CVEs under source package: {pkg: {pkg: {cve: block}}}
    payload = {
        "widgets": {
            "widgets": {
                "CVE-2026-1000": {
                    "description": "d",
                    "debianbugs": ["1001"],
                    "releases": {
                        "bookworm": {
                            "status": "resolved",
                            "repositories": {"bookworm": "1.2.3-4"},
                        }
                    },
                }
            }
        }
    }
    pairs = iter_cve_blocks(payload)
    assert [cve for cve, _ in pairs] == ["CVE-2026-1000"]
    data = debian_data("CVE-2026-1000", pairs[0][1])
    assert data["kind"] == "debian-tracker"
    assert data["releases"]["bookworm"][0]["fixed"] == "1.2.3-4"


def test_ubuntu_parse_and_fixes():
    from app.sources.ubuntu import parse_cve_list, released_fixes

    entries = parse_cve_list(
        [
            {
                "id": "CVE-2026-1000",
                "description": "Widget issue",
                "priority": "medium",
                "notices_ids": ["USN-1"],
                "packages": {
                    "openssl": {"jammy": {"status": "released", "version": "3.0.2-1"}},
                    "curl": {"jammy": {"status": "needs-triage"}},
                },
            }
        ]
    )
    assert len(entries) == 1
    e = entries[0]
    assert e.priority == "medium"
    fixes = released_fixes(e)
    assert fixes == [{"vendor": "Ubuntu", "product": "openssl", "release": "jammy", "fixes": ["3.0.2-1"]}]


# --- CISA advisories / ThreatFox / Vulners ---------------------------------------

def test_cisa_advisories_parse_rss():
    from app.sources.cisa_advisories import parse_rss

    xml = """<?xml version="1.0"?>
    <rss><channel>
      <item><title>Alert about CVE-2026-1000</title>
        <link>https://www.cisa.gov/news-events/alerts/2026/11/06/x</link>
        <pubDate>Fri, 06 Nov 2026 12:00:00 EST</pubDate>
        <description>Mitigations for CVE-2026-1000 and CVE-2026-2000.</description>
      </item>
      <item><title>No CVE advisory</title><link>https://x/</link></item>
    </channel></rss>"""
    items = parse_rss(xml)
    assert len(items) == 2
    assert items[0].cves == ["CVE-2026-1000", "CVE-2026-2000"]
    assert items[0].url.startswith("https://www.cisa.gov/")


def test_threatfox_parse_and_cve_extraction():
    from app.sources.threatfox import ioc_cves, parse_ioc_response

    payload = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "evil.example.com",
                "threat_type": "botnet_cc",
                "ioc_type": "domain",
                "malware": "win.dridex",
                "malware_alias": "targets CVE-2026-1000",
                "confidence_level": 75,
                "first_seen": "2026-11-01 12:00:00 UTC",
                "reference": "https://twitter.com/x",
                "tags": ["exe"],
            }
        ],
    }
    iocs = parse_ioc_response(payload)
    assert len(iocs) == 1
    assert ioc_cves(iocs[0]) == ["CVE-2026-1000"]


def test_threatfox_rejects_bad_status():
    import pytest
    from app.sources.threatfox import parse_ioc_response

    with pytest.raises(ValueError):
        parse_ioc_response({"query_status": "no_iocs"})


def test_vulners_parse_lookup():
    from app.sources.vulners import parse_lookup

    rec = parse_lookup(
        {
            "result": "OK",
            "data": {
                "id": "CVE-2026-1000",
                "title": "Widget overflow",
                "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"},
                "published": "2026-11-01T00:00:00Z",
                "references": ["https://a"],
            },
        }
    )
    assert rec.cvss_score == 7.5
    assert rec.ref_id == "CVE-2026-1000"


# --- sync-state behaviors ---------------------------------------------------------

def test_interval_due_first_run_and_replay(factory, monkeypatch):
    from datetime import datetime, timezone

    with factory() as s:
        assert _interval_due(s, "nvd") is True  # creates the state row
        st = s.query(SyncState).filter_by(source="nvd").one()
        st.checkpoint = {"last_run_ts": datetime.now(timezone.utc).isoformat()}
        s.commit()
        assert _interval_due(s, "nvd") is False


def test_key_gated_sources_skip_unconfigured(factory):
    _seed_vulns(factory)
    s = Settings(threatfox_auth_key="", vulners_api_key="")

    with factory() as sess:
        r = collector.sync_threatfox(sess, s)
        sess.commit()
        assert r["status"] == "unconfigured"
        st = sess.query(SyncState).filter_by(source="threatfox").one()
        assert st.status == "never_run"

    with factory() as sess:
        r = collector.sync_vulners(sess, s)
        sess.commit()
        assert r["status"] == "unconfigured"

    with factory() as sess:
        assert sess.query(SourceRecord).count() == 2  # only the cve_now records


def test_run_sync_skips_interval_and_unconfigured(factory):
    from datetime import datetime, timezone

    _seed_vulns(factory)
    with factory() as s:
        for source in ("nvd", "threatfox", "vulners"):
            st = SyncState(source=source)
            st.checkpoint = {"last_run_ts": datetime.now(timezone.utc).isoformat()}
            s.add(st)
        s.commit()

    settings = Settings(threatfox_auth_key="", vulners_api_key="")
    results = run_sync(factory, settings, sources=["nvd", "threatfox", "vulners"])
    assert results["nvd"] == {"status": "skipped", "reason": "interval"}
    assert results["threatfox"]["status"] == "skipped"
    assert results["vulners"]["status"] == "skipped"


# --- API surface ------------------------------------------------------------------

def test_list_has_sources_tags_and_source_filter(client, factory):
    _seed_vulns(factory)
    with factory() as s:
        vuln = s.query(Vulnerability).filter_by(vuln_id="CVE-2026-1000").one()
        s.add(
            SourceRecord(
                vulnerability_id=vuln.id, source="exploit_db",
                vuln_id="CVE-2026-1000", source_url="https://www.exploit-db.com/x",
                data={"kind": "exploit-db-entry", "items": []},
            )
        )
        s.commit()

    body = client.get("/api/vulns").json()
    assert body["total"] == 2
    by_id = {i["vuln_id"]: i for i in body["items"]}
    assert "exploit_db" in by_id["CVE-2026-1000"]["sources"]
    assert "cve_now" in by_id["CVE-2026-1000"]["sources"]
    assert by_id["CVE-2026-2000"]["sources"] == ["cve_now"]

    # the source filter
    r = client.get("/api/vulns", params={"source": "exploit_db"})
    assert r.status_code == 200
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["vuln_id"] == "CVE-2026-1000"

    # invalid source -> 422
    r = client.get("/api/vulns", params={"source": "not_a_source"})
    assert r.status_code == 422

    # first_epss is not a valid record source (no SourceRecords exist for it)
    r = client.get("/api/vulns", params={"source": "first_epss"})
    assert r.status_code == 422


def test_sync_status_lists_all_sources(client, factory):
    body = client.get("/api/sync/status").json()
    sources = [s["source"] for s in body["sources"]]
    for expected in ("cve_now", "cisa_kev", "first_epss", "nvd", "github_advisory",
                     "exploit_db", "metasploit", "nuclei", "poc_in_github", "redhat",
                     "debian_tracker", "ubuntu", "cisa_advisories", "threatfox", "vulners"):
        assert expected in sources
