import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtDate, fmtDateTime, type VulnListResponse } from "../api";
import { useSyncStatus } from "../sync-context";
import { SyncIndicator } from "../components/Layout";
import { KevBadge, TableSkeleton } from "../components/badges";

export default function Overview() {
  const { status } = useSyncStatus();
  const [recent, setRecent] = useState<VulnListResponse | null>(null);
  const [recentErr, setRecentErr] = useState<string | null>(null);
  const [stats, setStats] = useState<{
    new24h: number | null;
    watched24h: number | null;
    kevWatched: number | null;
    err: string | null;
  }>({ new24h: null, watched24h: null, kevWatched: null, err: null });

  const load = () => {
    api
      .vulns({ page: 1, page_size: 8 })
      .then(setRecent)
      .catch((e: Error) => setRecentErr(e.message));
    const cutoff = new Date(Date.now() - 24 * 3600 * 1000)
      .toISOString()
      .slice(0, 19);
    Promise.all([
      api.vulns({ page: 1, page_size: 1, date_from: cutoff.slice(0, 10) }),
      api.vulns({ page: 1, page_size: 1, watchlist_only: true, date_from: cutoff.slice(0, 10) }),
      api.vulns({ page: 1, page_size: 1, watchlist_only: true, kev_only: true }),
    ])
      .then(([newCve, watchNew, kevWatch]) => {
        setStats({
          new24h: newCve.total,
          watched24h: watchNew.total,
          kevWatched: kevWatch.total,
          err: null,
        });
      })
      .catch((e: Error) =>
        setStats((p) => ({ ...p, err: e.message })),
      );
  };

  useEffect(() => {
    load();
  }, []);

  const latestSync = status
    ? status.sources
        .map((s) => s.last_success_at)
        .filter((x): x is string => !!x)
        .sort()
        .pop() ?? null
    : null;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Overview</h1>
          <p className="desc">
            Newest public vulnerability data, matched against your watchlist.
            The Known Exploited card counts watchlist products listed in the
            CISA catalog.
          </p>
          {latestSync && (
            <p className="desc">
              Latest successful sync: {fmtDateTime(latestSync)}
            </p>
          )}
        </div>
        <SyncIndicator />
      </div>
      <div className="content">
        <div className="stat-grid">
          <div className="card stat-card">
            <span className="stat-label">New CVEs in last 24 hours</span>
            <span className="stat-value">
              {stats.new24h === null ? "—" : stats.new24h.toLocaleString()}
            </span>
            <span className="stat-sub">
              {stats.new24h === null
                ? stats.err ?? "Loading…"
                : "Based on collected publication date"}
            </span>
          </div>
          <div className="card stat-card">
            <span className="stat-label">Watchlist matches, last 24 hours</span>
            <span className="stat-value">
              {stats.watched24h === null ? "—" : stats.watched24h.toLocaleString()}
            </span>
            <span className="stat-sub">
              A watchlist match is not proof a deployed system is affected.
            </span>
          </div>
          <div className="card stat-card">
            <span className="stat-label">
              Known exploited, matching watchlist
            </span>
            <span className="stat-value">
              {stats.kevWatched === null ? "—" : stats.kevWatched.toLocaleString()}
            </span>
            <span className="stat-sub">
              <Link to="/kev">Review in Known Exploited</Link>
            </span>
          </div>
        </div>

        <div className="detail-section">
          <h2>Newest CVEs</h2>
          {recentErr && (
            <div className="error-state" role="alert">
              <span>Could not load recent CVEs: {recentErr}</span>
            </div>
          )}
          {!recent && !recentErr && <TableSkeleton rows={6} />}
          {recent && (
            <div className="card">
              <table className="cve-table">
                <thead>
                  <tr>
                    <th scope="col">CVE ID and title</th>
                    <th scope="col">First seen</th>
                    <th scope="col">Exploitation</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.items.map((item) => (
                    <tr key={item.vuln_id}>
                      <td data-label="CVE ID and title" style={{ minWidth: 0 }}>
                        <Link className="cve-id" to={`/cves/${item.vuln_id}`}>
                          {item.vuln_id}
                        </Link>
                      </td>
                      <td data-label="First seen">
                        {fmtDate(item.first_seen_at ?? item.published_at)}
                      </td>
                      <td data-label="Exploitation">
                        {item.kev ? (
                          <KevBadge />
                        ) : (
                          <span className="badge badge-unknown">Unknown</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="table-footer" style={{ border: "none" }}>
                <span>
                  <Link to="/cves">All latest CVEs →</Link>
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
