import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  api,
  fmtDate,
  type SeverityBucket,
  type VulnListResponse,
} from "../api";
import { severityDisplay, severityLabel } from "../severity";
import {
  EmptyState,
  ErrorState,
  KevBadge,
  NotKevBadge,
  SevBadgeWithScore,
  TableSkeleton,
  WatchBadge,
} from "./badges";
import { ChevronLeftIcon, ChevronRightIcon } from "../icons";

export interface CveTableProps {
  kevOnlyDefault?: boolean;
  showKevDateColumn?: boolean;
  baseTitle: string;
  description: string;
}

const SEVERITIES: SeverityBucket[] = [
  "critical",
  "high",
  "medium",
  "low",
  "unknown",
];

export default function CveTable({
  kevOnlyDefault = false,
  showKevDateColumn = false,
  baseTitle,
  description,
}: CveTableProps) {
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState<VulnListResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const page = Math.max(1, Number(params.get("page") ?? 1) || 1);
  const q = params.get("q") ?? "";
  const severity = (params.get("severity") ?? "") as SeverityBucket | "";
  const dateFrom = params.get("date_from") ?? "";
  const dateTo = params.get("date_to") ?? "";
  const watchlistOnly = params.get("watchlist") === "true";
  const kevOnly = params.get("kev") ?? (kevOnlyDefault ? "true" : "false");

  const pageNum =
    (data && page > data.pages && data.pages > 0 ? data.pages : page) ?? page;
  const queryKey = useMemo(
    () =>
      `page=${pageNum}&q=${encodeURIComponent(q)}&severity=${severity}&from=${dateFrom}&to=${dateTo}&w=${watchlistOnly}&k=${kevOnly}`,
    [pageNum, q, severity, dateFrom, dateTo, watchlistOnly, kevOnly],
  );

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .vulns({
        page: pageNum,
        page_size: 25,
        q: q || undefined,
        severity: severity || undefined,
        date_from: dateFrom || undefined,
        date_to: dateTo || undefined,
        watchlist_only: watchlistOnly,
        kev_only: kevOnly === "true",
      })
      .then((d) => {
        if (alive) {
          setData(d);
          setLoading(false);
        }
      })
      .catch((e: Error) => {
        if (alive) {
          setError(e.message);
          setLoading(false);
        }
      });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queryKey]);

  /** update one query param, resetting page */
  function setFilter(patch: Record<string, string | null>) {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v === null || v === "") next.delete(k);
      else next.set(k, v);
    }
    if (!("page" in patch)) next.delete("page");
    setParams(next);
  }

  function clearFilters() {
    const next = new URLSearchParams();
    if (kevOnlyDefault) next.set("kev", "true");
    setParams(next);
  }

  const activeChips: { key: string; label: string }[] = [];
  if (q) activeChips.push({ key: "q", label: `Search: ${q}` });
  if (severity)
    activeChips.push({
      key: "severity",
      label: `Severity: ${severityLabel[severity]}`,
    });
  if (dateFrom) activeChips.push({ key: "date_from", label: `From: ${dateFrom}` });
  if (dateTo) activeChips.push({ key: "date_to", label: `To: ${dateTo}` });
  if (watchlistOnly && !kevOnlyDefault)
    activeChips.push({ key: "watchlist", label: "Watchlist only" });

  const hasFilters =
    !!(q || severity || dateFrom || dateTo || (watchlistOnly && !kevOnlyDefault));

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>{baseTitle}</h1>
          <p className="desc">{description}</p>
        </div>
      </div>
      <div className="content">
        <form
          className="filters"
          onSubmit={(e) => {
            e.preventDefault();
            setFilter({ q: (e.currentTarget.elements.namedItem("q") as HTMLInputElement).value });
          }}
        >
          <label>
            CVE ID or keyword
            <input
              type="text"
              name="q"
              defaultValue={q}
              placeholder="e.g. CVE-2026-1111, openssh"
              aria-label="CVE ID or keyword"
            />
          </label>
          <label>
            Severity
            <select
              name="severity"
              value={severity}
              onChange={(e) => setFilter({ severity: e.target.value })}
              aria-label="Severity"
            >
              <option value="">All severities</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {severityLabel[s]}
                </option>
              ))}
            </select>
          </label>
          <label>
            Published from
            <input
              type="date"
              name="from"
              value={dateFrom}
              onChange={(e) => setFilter({ date_from: e.target.value })}
              aria-label="Published from date"
            />
          </label>
          <label>
            Published to
            <input
              type="date"
              name="to"
              value={dateTo}
              onChange={(e) => setFilter({ date_to: e.target.value })}
              aria-label="Published to date"
            />
          </label>
          {!kevOnlyDefault && (
            <label>
              <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
                <input
                  type="checkbox"
                  name="watchlist"
                  checked={watchlistOnly}
                  onChange={(e) => setFilter({ watchlist: e.target.checked ? "true" : null })}
                  aria-label="Watchlist matches only"
                />
                Watchlist only
              </span>
            </label>
          )}
          <label>
            <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
              <input
                type="checkbox"
                name="kev"
                checked={kevOnly === "true"}
                onChange={(e) => setFilter({ kev: e.target.checked ? "true" : "false" })}
                aria-label="Known exploited only"
              />
              Exploited only
            </span>
          </label>
          <button className="btn" type="submit">
            Apply search
          </button>
        </form>

        {(activeChips.length > 0 || hasFilters) && (
          <div className="chips">
            {activeChips.map((c) => (
              <span className="chip" key={c.key}>
                {c.label}
                <button
                  onClick={() => setFilter({ [c.key]: null })}
                  aria-label={`Remove filter ${c.label}`}
                  type="button"
                >
                  ×
                </button>
              </span>
            ))}
            <button className="chip-clear" onClick={clearFilters} type="button">
              Clear filters
            </button>
          </div>
        )}

        {error && <ErrorState message={`Could not load CVEs: ${error}`} onRetry={() => setFilter({ page: String(page) })} />}

        {loading && <TableSkeleton rows={8} />}

        {!loading && !error && data && (
          <>
            {data.total === 0 && (
              <EmptyState
                headline={
                  data.page === 1 ? "No results match your filters" : "No CVEs on this page"
                }
                hint="Try removing a filter or searching a different keyword."
              >
                <button className="btn" onClick={clearFilters} type="button">
                  Clear filters
                </button>
              </EmptyState>
            )}
            {data.total > 0 && (
              <table className="cve-table">
                <thead>
                  <tr>
                    <th scope="col">CVE ID and title</th>
                    <th scope="col">Published</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Watchlist</th>
                    {showKevDateColumn && <th scope="col">CISA date added</th>}
                    <th scope="col">Exploitation</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr key={item.vuln_id}>
                      <td className="cell-title" data-label="CVE ID and title">
                        <Link className="cve-id" to={`/cves/${item.vuln_id}`}>
                          {item.vuln_id}
                        </Link>
                        <div className="cve-title">{item.title ?? "Unknown title"}</div>
                      </td>
                      <td data-label="Published">{fmtDate(item.published_at ?? item.first_seen_at)}</td>
                      <td data-label="Severity">
                        <SevBadgeWithScore
                          bucket={item.severity_bucket}
                          text={severityDisplay(item)}
                        />
                      </td>
                      <td data-label="Watchlist">
                        <WatchBadge matches={item.watchlist_matches} />
                      </td>
                      {showKevDateColumn && (
                        <td data-label="CISA date added">{fmtDate(item.kev_date_added)}</td>
                      )}
                      <td data-label="Exploitation">
                        {item.kev ? <KevBadge /> : <NotKevBadge />}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            <div className="table-footer">
              <span>
                {data.total.toLocaleString()} match{data.total === 1 ? "" : "es"}
                {` · page ${data.page} of ${data.pages}`}
              </span>
              <div className="pager">
                <button
                  aria-label="Previous page"
                  disabled={data.page <= 1}
                  onClick={() => setFilter({ page: String(data.page - 1) })}
                  type="button"
                >
                  <ChevronLeftIcon width={14} height={14} />
                </button>
                <button
                  aria-label="Next page"
                  disabled={data.page >= data.pages}
                  onClick={() => setFilter({ page: String(data.page + 1) })}
                  type="button"
                >
                  <ChevronRightIcon width={14} height={14} />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
