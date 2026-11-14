import { useEffect, useState } from "react";
import { api, fmtDateTime, sourceLabel, type SyncStatus } from "../api";
import { useSyncStatus } from "../sync-context";
import { ErrorState, TableSkeleton } from "../components/badges";
import { RefreshIcon } from "../icons";

function sourceDoc(source: string): string {
  if (source === "cve_now")
    return "Merged public catalog (CVE list, GitHub Advisory, OSV, NVD, EUVD, KEV) via the documented /api/v1/entries cursor API. cve.now takes no API key.";
  if (source === "cisa_kev")
    return "CISA Known Exploited Vulnerabilities catalog JSON feed.";
  if (source === "first_epss")
    return "Official FIRST EPSS daily bulk CSV (epss_scores-current.csv.gz). Syncs at most once per day; scores are stored only for CVEs already present in VulnWatch.";
  if (source === "nvd")
    return "NVD REST API 2.0, incremental by lastMod window. Provides attributed CVSS v2/v3.1/v4 scores and English descriptions. Syncs at most hourly; a free NVD_API_KEY raises the rate limit.";
  if (source === "github_advisory")
    return "GitHub Security Advisory Database REST API, incremental by modified date. Advisories with a CVE id create or enrich canonical records. Optional GITHUB_TOKEN raises the rate limit.";
  if (source === "osv_dev")
    return "OSV.dev detail records for the GHSA ids discovered by the GitHub Advisory source (aliases, affected ecosystems, first-patched). Enrichment-only.";
  if (source === "exploit_db")
    return "Exploit-DB public export CSV: public exploit/PoC availability per CVE. Enrichment-only, daily.";
  if (source === "metasploit")
    return "Metasploit Framework module metadata: exploit-module availability per CVE. Enrichment-only, daily.";
  if (source === "nuclei")
    return "ProjectDiscovery nuclei-templates git tree: detection-template coverage per CVE. Enrichment-only, daily.";
  if (source === "poc_in_github")
    return "PoC-in-GitHub per-CVE files, fetched on demand for the newest CVEs without a record. Enrichment-only.";
  if (source === "redhat")
    return "Red Hat Security Data API, incremental by after date: vendor CVSS v3 and first-fixed package releases. Creates canonical records.";
  if (source === "debian_tracker")
    return "Debian security tracker JSON export: per-release package fix status. Enrichment-only, daily (the file is ~15 MB).";
  if (source === "ubuntu")
    return "Ubuntu CVE Tracker API, incremental by modified_since: Canonical package fix status. Creates canonical records. May be unreachable from some networks; override UBUNTU_API_URL.";
  if (source === "cisa_advisories")
    return "CISA Cybersecurity Advisories RSS: advisory titles/links linked to CVEs mentioned in their text. May be blocked from some networks; override CISA_ADVISORIES_URL.";
  if (source === "threatfox")
    return "abuse.ch ThreatFox IOC feed (malware context). Requires a free Auth-Key from auth.abuse.ch (THREATFOX_AUTH_KEY); skipped as unconfigured until then.";
  if (source === "vulners")
    return "Vulners aggregated exploit/advisory data for urgent and high-priority CVEs. Requires an API key (VULNERS_API_KEY); skipped as unconfigured until then.";
  return "";
}

function SourceCard({
  state,
  onTrigger,
  triggering,
}: {
  state: SyncStatus["sources"][number];
  onTrigger: () => void;
  triggering: boolean;
}) {
  const cls =
    state.status === "error"
      ? state.last_success_at
        ? "feed-status-stale"
        : "feed-status-error"
      : state.status === "success"
        ? "feed-status-ok"
        : "feed-status-error";

  let text: string = state.status;
  if (state.status === "never_run") text = "Never run";
  if (state.stale && state.last_success_at) text = "Error — showing stale data";

  return (
    <div className="card">
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          gap: 10,
          alignItems: "center",
          marginBottom: 8,
        }}
      >
        <strong>{sourceLabel(state.source)}</strong>
        <span className={cls}>
          <span
            className={`dot ${
              state.status === "success" ? "dot-ok" : state.stale ? "dot-stale" : "dot-unknown"
            }`}
            aria-hidden="true"
          />
          <span>{text}</span>
        </span>
      </div>
      <p className="help" style={{ margin: "0 0 10px" }}>{sourceDoc(state.source)}</p>
      {state.checkpoint && Object.keys(state.checkpoint).length > 0 && (
        <p className="help" style={{ margin: "0 0 10px", fontFamily: "var(--mono)", fontSize: 12 }}>
          Checkpoint: {Object.entries(state.checkpoint)
            .map(([k, v]) => `${k}=${String(v)}`)
            .join(" · ")}
        </p>
      )}
      <dl className="kv-grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <div className="kv">
          <dt>Last attempt</dt>
          <dd>{fmtDateTime(state.last_attempt_at)}</dd>
        </div>
        <div className="kv">
          <dt>Last successful sync</dt>
          <dd>{fmtDateTime(state.last_success_at)}</dd>
        </div>
        <div className="kv">
          <dt>Records processed (last successful run)</dt>
          <dd>{state.records_processed.toLocaleString()}</dd>
        </div>
        <div className="kv">
          <dt>Status detail</dt>
          <dd>
            {state.error_message ?? "OK"}
          </dd>
        </div>
      </dl>
      {state.stale && (
        <p className="help" style={{ color: "var(--sev-high)" }}>
          The last fetch failed; previously collected records remain available
          for this source and the feed checkpoint was not advanced.
        </p>
      )}
      <div style={{ marginTop: 12 }}>
        <button className="btn" onClick={onTrigger} disabled={triggering} type="button">
          <RefreshIcon width={14} height={14} /> Trigger sync
        </button>
      </div>
    </div>
  );
}

export default function FeedStatus() {
  const { status, error, refresh } = useSyncStatus();
  const [triggering, setTriggering] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const trigger = () => {
    setTriggering(true);
    api
      .triggerSync()
      .then((r) => {
        setNote(r.message);
        refresh();
      })
      .catch((e: Error) => setNote(`Could not trigger sync: ${e.message}`))
      .finally(() => setTriggering(false));
  };

  useEffect(() => {
    document.title = "Feed Status — VulnWatch";
  }, []);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Feed Status</h1>
          <p className="desc">
            One card per source: last attempt, last successful sync and records
            processed. The collector runs once at startup and every{" "}
            {status ? Math.round(status.interval_seconds / 60) : 60} minutes by
            default. Overlapping runs are prevented.
          </p>
        </div>
      </div>
      <div className="content">
        {note && (
          <p className="help" role="status" style={{ marginTop: 0 }}>
            {note}
          </p>
        )}
        {error && <ErrorState message={`Could not load feed status: ${error}`} onRetry={refresh} />}
        {!status && !error && <TableSkeleton rows={4} />}
        <div className="feed-grid">
          {status?.sources.map((s) => (
            <SourceCard key={s.source} state={s} onTrigger={trigger} triggering={triggering} />
          ))}
        </div>
      </div>
    </div>
  );
}
