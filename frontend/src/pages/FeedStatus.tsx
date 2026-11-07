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
