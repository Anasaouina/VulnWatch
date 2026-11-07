# VulnWatch

Self-hosted vulnerability intelligence dashboard for a single-user, local
Debian lab. VulnWatch collects public vulnerability data, keeps a searchable
history, and helps prioritize CVEs affecting products you follow.

Answers three questions:

1. **What's new?** — Overview shows CVEs collected in the last 24 hours.
2. **Which ones match my watchlist?** — Every view marks watchlist matches and
   says whether the match came from structured product data or keyword
   matching.
3. **Which ones are exploited in the wild?** — CISA KEV listing is shown on
   every row, with a dedicated "Known Exploited" view.

## Architecture

```
frontend/     React 19 + TypeScript + Vite; nginx serves the built SPA
              and proxies /api to the backend (same origin).
backend/      FastAPI + SQLAlchemy 2 + Alembic + PostgreSQL.
              app/sources/       source adapters (cve.now, CISA KEV)
              app/collector.py   idempotent ingestion + KEV enrichment + matching
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
  notes, cwes`).

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
(`SYNC_INTERVAL_SECONDS`, default 3600).

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
| `GET /api/vulns` | paginated CVE list/search (`q`, `severity`, `date_from`, `date_to`, `watchlist_only`, `kev_only`, `page`, `page_size`), includes pagination metadata |
| `GET /api/vulns/{id}` | CVE detail with source provenance and CVSS attributions |
| `GET/POST/PATCH/DELETE /api/watchlist` | watchlist CRUD (seeds OpenSSH, Wazuh, pfSense, Docker) |
| `GET /api/sync/status` | per-source last attempt, last success, status, error |
| `POST /api/sync/run` | manual sync trigger (local use) |

Validation errors return HTTP 422 with a message; unknown IDs return 404;
internal errors are logged server-side and returned as generic 500s without
stack traces.

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
- A watchlist match means a term matched stored data — it is not proof that a
  deployed system is affected.
- Deleted watchlist items keep past matches out of the UI; they are not
  archived.

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
