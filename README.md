# VulnWatch

Self-hosted vulnerability intelligence dashboard for a single-user, local
Debian lab. VulnWatch collects public vulnerability data, keeps a searchable
history, enriches it with FIRST EPSS scores and the CISA KEV catalog, and
computes a transparent VulnWatch priority so you can decide which CVEs to
look at first.

Answers four questions:

1. **What's new?** — Overview shows CVEs collected in the last 24 hours.
2. **Which ones match my watchlist?** — Every view marks watchlist matches and
   says whether the match came from structured product data or keyword
   matching.
3. **Which ones are exploited in the wild?** — CISA KEV listing is shown on
   every row, with a dedicated "Known Exploited" view, ransomware-campaign
   notes, remediation due dates, and CISA's required action.
4. **Which ones should be prioritized?** — Every CVE carries a VulnWatch
   priority (an assessment, not an official rating) computed from severity,
   EPSS exploitation likelihood and KEV listing, with the individual signals
   and the reasons visible on the detail view.

## Architecture

```
frontend/     React 19 + TypeScript + Vite; nginx serves the built SPA
              and proxies /api to the backend (same origin).
backend/      FastAPI + SQLAlchemy 2 + Alembic + PostgreSQL.
              app/sources/       source adapters (cve.now, CISA KEV, FIRST EPSS)
              app/collector.py   idempotent ingestion + enrichment + matching
              app/priority.py    VulnWatch priority classification
              app/collector_main.py  collector loop entrypoint
              app/routes/        API endpoints
compose.yaml  db (Postgres, not published), migrate (one-shot), backend (API),
              collector (separate process, same image), frontend (nginx)
.env.example  documented configuration
```

## Data sources

- **cve.now** — used through its documented JSON API
  (`GET /api/v1/entries` with opaque `nextCursor` cursor pagination, and
  `GET /api/v1/entries/<id>` for per-entry detail). Response shapes were
  verified against the live service. cve.now is a merged public catalog; its
  summaries are model-generated and are labeled as such in the UI.
  *Note:* cve.now rate-limits aggressively; the collector paces requests,
  and brief HTTP 403/429 bursts are handled with bounded retries.
- **CISA Known Exploited Vulnerabilities catalog** — official JSON feed
  (`known_exploited_vulnerabilities.json`); schema verified live (fields:
  `cveID, vendorProject, product, vulnerabilityName, dateAdded, dueDate,
  shortDescription, requiredAction, knownRansomwareCampaignUse, forensicTriage,
  notes, cwes`). Listed CVEs get `urgent` VulnWatch priority, and the CISA
  required action, remediation due date and ransomware-campaign flag are
  stored on the canonical record (fill-on-write: a later feed omitting a
  field never erases a stored value).
- **FIRST EPSS** — official daily bulk CSV
  (`https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`, documented
  at <https://www.first.org/epss/data>, verified live 2026-11-07: gzip CSV
  with a `#model_version`/`score_date` meta line and `cve,epss,percentile`
  rows). EPSS is the estimated probability (0–1) that a CVE will be exploited
  in the wild within 30 days, and the percentile ranks it against all scored
  CVEs. The collector downloads the bulk file **once per score date** (own
  `first_epss` sync state with its own checkpoint), stores the score,
  percentile and score date per canonical CVE — plus provenance (source,
  feed URL, retrieval timestamp, EPSS model version) — and keeps **daily
  snapshots** in a per-CVE history. Scores are stored only for CVEs already
  present in VulnWatch; CVEs the feed knows that VulnWatch has never seen are
  skipped. Parse or fetch failures keep the previous EPSS values and never
  advance the EPSS checkpoint. The official EPSS API
  (`https://api.first.org/data/v1/epss`) is implemented for on-demand
  single-CVE lookups only — never bulk sync, per FIRST's usage guidance.
- **NVD** — official US National Vulnerability Database REST API 2.0
  (`https://services.nvd.nist.gov/rest/json/cves/2.0`, verified live
  2026-11-07). Synced **incrementally by `lastMod` window** (bounded pages
  per cycle, self-paced at 5 requests/30 s without a key; a free
  `NVD_API_KEY` raises that to 50/30 s). NVD supplies **attributed CVSS**
  rows (v2/v3.1/v4 with source and vector — closing the unattributed-CVSS
  gap in the cve.now list feed), English descriptions, publication dates and
  references. Creates canonical records (it is the authoritative CVE
  catalog).
- **GitHub Advisory Database** — public REST API
  (`https://api.github.com/advisories`, verified live 2026-11-07; optional
  `GITHUB_TOKEN` raises the anonymous 60 req/h limit). Synced incrementally
  by `modified` date. Advisories that carry a CVE id create or enrich
  canonical records; GHSA-only advisories are skipped (VulnWatch's canonical
  space is CVE-centric). Stores CVSS, affected packages with first-patched
  versions, and the GHSA id that drives the OSV.dev pass.
- **OSV.dev** — cross-ecosystem advisory linkage. For canonical CVEs with a
  GHSA id (from the GitHub Advisory source) the OSV record is fetched
  (`GET https://api.osv.dev/v1/vulns/{GHSA}`, verified live 2026-11-07) and
  its aliases, affected ecosystems and first-patched versions are stored.
  Enrichment-only, bounded per cycle.
- **Exploit-DB** — public exploit availability, from the Exploit-DB GitLab
  CSV export (`files_exploits.csv`, verified live 2026-11-07, ~47k rows).
  CVE linkage via the `codes` column and description text. Enrichment-only,
  daily.
- **Metasploit Framework** — exploit-module availability from
  rapid7/metasploit-framework `db/modules_metadata_base.json` (verified
  live 2026-11-07). Enrichment-only, daily.
- **Nuclei templates** — detection-template coverage from the
  projectdiscovery/nuclei-templates git tree (verified live 2026-11-07,
  ~4,600 CVE-mapped templates). Enrichment-only, daily.
- **PoC-in-GitHub** — public PoC repositories per CVE, fetched on demand
  (one JSON file per CVE from nomi-sec/PoC-in-GitHub, verified live
  2026-11-07) for the newest canonical CVEs lacking a record.
  Enrichment-only, bounded per cycle.
- **Red Hat Security Data** — public Security Data API
  (`https://access.redhat.com/hydra/rest/securitydata/cve.json`, verified
  live 2026-11-07), incremental by `after` date. Stores Red Hat CVSS v3,
  affected releases with fixed package versions. Creates canonical records.
- **Debian Security Tracker** — the tracker's JSON export
  (`https://security-tracker.debian.org/tracker/data/json`, verified live
  2026-11-07, ~15 MB): per-release package fix status per CVE.
  Enrichment-only (only CVEs already canonical), daily.
- **Ubuntu CVE Tracker** — Canonical's API v0
  (`https://cve.ubuntu.com/api/v0/cves/`). Stores priority labels and
  released fixes per release. Creates canonical records. *Note:* the host
  did not resolve from this deployment's network at implementation time; the
  source degrades gracefully to a per-source error and can be pointed at a
  mirror via `UBUNTU_API_URL`.
- **CISA Advisories** — CISA's Cybersecurity Advisories RSS (alerts,
  advisories, malware reports); advisories mentioning CVE ids are linked to
  those canonical records. *Note:* cisa.gov returns Akamai 403 to
  non-browser clients from some datacenter IPs (verified live 2026-11-07);
  the source degrades gracefully and can be pointed at a mirror via
  `CISA_ADVISORIES_URL`.
- **ThreatFox (abuse.ch)** — malware IOC context from
  `https://threatfox-api.abuse.ch/api/v1/`. **Requires a free Auth-Key**
  (`THREATFOX_AUTH_KEY`, obtainable at <https://auth.abuse.ch/>); until one
  is configured the source reports "unconfigured" and is skipped. CVE
  linkage is best-effort (IOCs rarely name a CVE).
- **Vulners** — aggregated exploit/advisory references for urgent and
  high-priority CVEs (on-demand lookups, bounded per cycle). **Requires an
  API key** (`VULNERS_API_KEY`, free registration); the unauthenticated
  endpoint is Cloudflare-challenged for datacenter IPs (verified live
  2026-11-07), so the source reports "unconfigured" until a key is set.

The CVE list API and UI expose a **source filter** (`?source=nvd` etc.) and
each CVE row carries **source tags** showing every feed that has evidence
for it. Per-source ingest policies are documented in
`backend/app/collector.py` (canonical-creating vs enrichment-only vs
key-gated).

Both adapters live in `backend/app/sources/` and are kept separate from
persistence, API routes, and UI. Every URL is validated to safe http/https
before display. All source text is rendered as text, never HTML.

## Start it on Debian

Requirements: Docker (with the Compose plugin) and git.

```bash
git clone <this repo> vulnwatch && cd vulnwatch
cp .env.example .env      # optional: defaults are fine for a lab
docker compose up -d --build
```

Wait for the migration to finish, then open **http://127.0.0.1:8080**
(bound to localhost by default — PostgreSQL and the API are not published).

```bash
docker compose ps            # all services should be up / exit 0 for migrate
docker compose logs -f collector   # feed ingestion logs
curl http://127.0.0.1:8080/api/health
```

The collector runs one sync at startup and then every hour
(`SYNC_INTERVAL_SECONDS`, default 3600). cve.now and CISA KEV refresh hourly;
the EPSS bulk file is only re-downloaded when the EPSS score date advances
(i.e., at most once per day), with its own checkpoint.

## VulnWatch priority (assessment)

The priority shown in the UI and API is **a VulnWatch assessment — not an
official FIRST, CISA or CVSS rating**. It combines independently visible
signals; nothing is hidden behind a single number, and the detail view lists
the reasons that produced the label.

| Priority | Rule (evaluated top to bottom) |
| --- | --- |
| `urgent` | CVE listed in the CISA KEV catalog (confirmed known exploitation). |
| `high` | Not in KEV, EPSS ≥ `PRIORITY_EPSS_HIGH` (default **0.5**, i.e. better than even odds of exploitation in 30 days) **and** numeric CVSS ≥ 7.0 (or stated High/Critical severity). |
| `medium` | EPSS ≥ `PRIORITY_EPSS_HIGH` with lower impact, **or** EPSS ≥ `PRIORITY_EPSS_ELEVATED` (default **0.1**) with CVSS ≥ 7.0 / stated High-Critical. |
| `low` | Any remaining case where at least one signal (CVSS, stated severity or EPSS) exists. |
| `unknown` | No CVSS, stated severity or EPSS available yet. |

Thresholds are configured via `PRIORITY_EPSS_HIGH` and
`PRIORITY_EPSS_ELEVATED` (percentile-style values in 0–1). Users are expected
to read the individual signals (severity badge, EPSS score/percentile, KEV
badge) alongside the priority.

Limits, stated plainly:

- The priority is ranking guidance, not a measurement of risk to *your*
  systems. VulnWatch has no asset inventory: a label never implies a CVE
  affects a system you actually run, and asset exposure requires asset
  inventory + version matching.
- KEV only covers exploitation CISA has confirmed and catalogued; absence
  from KEV is not evidence that a CVE is not exploited.
- EPSS is a statistical model. It does not guarantee exploitation will or did
  occur, and scores shift when FIRST publishes a new model version (the model
  version is stored per snapshot).
- A merged note ("VulnWatch assessment ...") accompanies every priority in
  the API responses so clients can render the disclaimer.

## One-shot sync and logs

```bash
# run a single sync cycle and exit (uses the same image as the API):
docker compose run --rm collector python -m app.collector_main --once

# follow collector logs:
docker compose logs -f collector

# trigger a sync from the dashboard (API starts it in the background):
curl -X POST http://127.0.0.1:8080/api/sync/run
# check progress:
curl http://127.0.0.1:8080/api/sync/status
```

## Configuration

All variables with documentation live in `.env.example`. Highlights:

| Variable | Default | Meaning |
| --- | --- | --- |
| `VULNWATCH_BIND` | `127.0.0.1` | interface the web UI binds to (keep localhost) |
| `VULNWATCH_PORT` | `8080` | host port of the web UI |
| `SYNC_INTERVAL_SECONDS` | `3600` | collector schedule |
| `HTTP_TIMEOUT_SECONDS` / `HTTP_RETRIES` | `30` / `3` | outbound fetch behavior |
| `CVE_NOW_MAX_PAGES_PER_RUN` | `4` | cve.now pages pulled per cycle (30 entries/page) |
| `PRIORITY_EPSS_HIGH` | `0.5` | VulnWatch priority threshold: EPSS above this with High/Critical impact ⇒ high |
| `PRIORITY_EPSS_ELEVATED` | `0.1` | VulnWatch priority threshold: EPSS above this with any impact ⇒ at least medium when combined with High impact |
| `EPSS_BULK_URL` | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | official FIRST EPSS daily bulk file (redirects; collector follows) |
| `NVD_API_KEY` | *(empty)* | free NVD API key; raises the rate limit from 5 to 50 req/30 s |
| `GITHUB_TOKEN` | *(empty)* | optional GitHub token; raises the advisories API rate limit |
| `UBUNTU_API_URL` / `CISA_ADVISORIES_URL` | official hosts | overrides when the default hosts are unreachable from your network |
| `THREATFOX_AUTH_KEY` | *(empty)* | free abuse.ch Auth-Key (auth.abuse.ch); source stays "unconfigured" without it |
| `VULNERS_API_KEY` | *(empty)* | Vulners API key; source stays "unconfigured" without it |
| `ALLOW_MANUAL_SYNC` | `true` | enables `POST /api/sync/run` |

Database credentials are set inside `compose.yaml` for the internal network
only; the database is not exposed on any host port. There is no
authentication — keep the deployment bound to localhost or put it behind
your own reverse proxy.

## Migrations

Schema changes: edit `backend/app/models.py`, auto-generate a revision, verify,
commit:

```bash
docker compose run --rm -w /srv migrate \
  bash -c "alembic revision --autogenerate -m 'change' && alembic upgrade head"
```

PostgreSQL data persists in the named volume `vulnwatch_db-data`; records
survive restarts and rebuilds as long as the volume is kept.

## API summary

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | health check (app + database) |
| `GET /api/vulns` | paginated CVE list/search (`q`, `severity`, `date_from`, `date_to`, `watchlist_only`, `kev_only`, `ransomware_only`, `priority`, `source`, `min_epss`, `min_epss_percentile`, `sort` (`newest` \| `priority_desc` \| `epss_desc` \| `cvss_desc`), `page`, `page_size`), includes pagination metadata; every item carries a `sources` list (all feeds with evidence for that CVE) |
| `GET /api/vulns/{id}` | CVE detail with provenance, CVSS attributions, EPSS score/percentile/history and CISA KEV context |
| `GET/POST/PATCH/DELETE /api/watchlist` | watchlist CRUD (seeds OpenSSH, Wazuh, pfSense, Docker) |
| `GET /api/sync/status` | per-source last attempt, last success, status, checkpoint, error |
| `POST /api/sync/run` | manual sync trigger (local use) |

Validation errors return HTTP 422 with a message; unknown IDs return 404;
internal errors are logged server-side and returned as generic 500s without
stack traces.

**Backward compatibility:** all new response fields are additive. Existing
clients of `GET /api/vulns` keep receiving every previous field; new fields
(`epss_score`, `epss_percentile`, `epss_score_date`, `kev_ransomware_use`,
`priority`, `priority_note`, …) are simply absent-or-null when no data
exists. The `priority` field is always accompanied by `priority_note`,
which states that it is a VulnWatch assessment.

## Local development (without Docker)

```bash
# backend (needs a PostgreSQL server; or point DATABASE_URL anywhere)
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                                  # backend test suite
uvicorn app.main:app --port 8000        # API
python -m app.collector_main --once     # one-shot sync

# frontend (Vite dev server proxies /api to localhost:8000)
cd ../frontend && npm install && npm run dev
npm run build                           # typecheck + production build
```

## Known limitations

- The first release is single-user, local and unauthenticated by design.
- cve.now supplies recent entries (paginated API); older history is not
  backfilled on first run. Records initially seen only in CISA KEV are stored
  too and merged when cve.now publishes them.
- List-level CVSS scores from cve.now arrive without an explicit scoring
  origin; those rows are attributed "cve_now-list (unattributed)" rather than
  inventing a source. Per-entry detail provides attributed CVSS (source +
  vector), structured affected products, and fix versions for KEV and
  watchlist-matched CVEs.
- EPSS enrichment applies only to CVEs already in VulnWatch's canonical
  table; the full EPSS population (~400k CVEs) is never mirrored locally.
  Scores only start building up after the merge runs (per-score-date
  history). If the EPSS download fails, previously stored scores and history
  remain and the checkpoint stays put.
- The SQL sort/filter helpers for `priority` approximate the Python rules for
  records whose severity comes only from a stated label (no numeric CVSS);
  the serialized per-CVE priority is always the exact one.
- A listed CVE is not proof that a user's own asset is affected; asset
  matching requires an asset inventory and version matching (the watchlist is
  a rough keyword/structured approximation only).
- A watchlist match means a term matched stored data — it is not proof that a
  deployed system is affected.
- Deleted watchlist items keep past matches out of the UI; they are not
  archived.
- Extended sources have bounded per-cycle work: NVD/GitHub Advisory/Red Hat
  sync incrementally, Exploit-DB/Metasploit/Nuclei/Debian pull bulk dumps at
  most daily, and PoC-in-GitHub/OSV/Vulners process a bounded batch per
  cycle — full backfill converges over multiple cycles rather than instantly.
- `cve.ubuntu.com` may not resolve from some datacenter networks and cisa.gov
  blocks non-browser clients from others; both sources degrade gracefully to
  per-source errors and expose URL overrides (`UBUNTU_API_URL`,
  `CISA_ADVISORIES_URL`). ThreatFox and Vulners stay "unconfigured" until
  their API keys are provided.

## Troubleshooting

- **Feeds show errors / stale data.** Check `docker compose logs collector`.
  A failed fetch keeps previously collected data and the checkpoint is not
  advanced; the next cycle retries. cve.now may return HTTP 403 when
  rate-limited — increase `CVE_NOW_PAGE_PAUSE_SECONDS` or reduce
  `CVE_NOW_MAX_PAGES_PER_RUN`.
- **"No CVEs imported yet".** The first sync may take a couple of minutes
  (upstream pacing + retries). Watch `docker compose logs -f collector`.
- **Port already in use.** Set `VULNWATCH_PORT` in `.env`.
- **Database errors on startup.** Ensure the `migrate` service completed
  (`docker compose ps`) and `db` reports healthy before the API starts.
- **Reset everything** (erases the history): `docker compose down -v`.
