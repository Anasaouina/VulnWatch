export type SeverityBucket =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "unknown";

/** VulnWatch assessment label — not an official FIRST, CISA or CVSS rating. */
export type Priority =
  | "urgent"
  | "high"
  | "medium"
  | "low"
  | "unknown";

export interface WatchMatch {
  item_id: number;
  name: string;
  match_type: "structured" | "keyword";
  matched_term: string;
}

export interface VulnListItem {
  vuln_id: string;
  title: string | null;
  published_at: string | null;
  first_seen_at: string | null;
  severity_bucket: SeverityBucket;
  cvss_score: number | null;
  cvss_source: string | null;
  cvss_version: string | null;
  stated_severity: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  epss_score_date: string | null;
  kev: boolean;
  kev_date_added: string | null;
  kev_ransomware_use: string | null;
  priority: Priority;
  priority_note: string;
  /** all intelligence sources that carry a record (or score) for this CVE */
  sources: string[];
  watchlist_matches: WatchMatch[];
  watchlist_match_type: "structured" | "keyword" | null;
}

export interface VulnListResponse {
  items: VulnListItem[];
  page: number;
  page_size: number;
  total: number;
  pages: number;
}

export interface CvssAttribution {
  score: number;
  version: string;
  source: string;
  vector: string | null;
}

export interface EpssSnapshot {
  score_date: string | null;
  score: number;
  percentile: number;
  retrieved_at: string | null;
  source: string;
  source_url: string | null;
  model_version: string | null;
}

export interface SourceRecordInfo {
  source: string;
  vuln_id: string;
  url: string | null;
  first_synced_at: string | null;
  last_synced_at: string | null;
  data: Record<string, unknown> | null;
}

export interface VulnDetail extends VulnListItem {
  summary: string | null;
  summary_source: string | null;
  last_updated_at: string | null;
  created_at: string | null;
  records_collected_at: string | null;
  priority_reasons: string[];
  kev_required_action: string | null;
  kev_due_date: string | null;
  kev_catalog_released: string | null;
  epss_retrieved_at: string | null;
  epss_source: string | null;
  epss_source_url: string | null;
  epss_model_version: string | null;
  epss_history: EpssSnapshot[];
  cvss_scores: CvssAttribution[];
  affected_products: {
    vendor: string;
    product: string;
    versions: unknown[] | null;
    fixes: unknown[] | null;
    source: string;
  }[];
  source_records: SourceRecordInfo[];
}

export interface WatchlistItemDTO {
  id: number;
  name: string;
  keywords: string[];
  match_count: number;
  created_at: string | null;
}

export interface SyncSourceState {
  source: string;
  status: "running" | "success" | "error" | "never_run";
  last_attempt_at: string | null;
  last_success_at: string | null;
  error_message: string | null;
  records_processed: number;
  checkpoint: Record<string, unknown> | null;
  stale: boolean;
}

export interface SyncStatus {
  sources: SyncSourceState[];
  interval_seconds: number;
  running: boolean;
}

export interface VulnQuery {
  page?: number;
  page_size?: number;
  q?: string;
  severity?: SeverityBucket;
  date_from?: string;
  date_to?: string;
  watchlist_only?: boolean;
  kev_only?: boolean;
  ransomware_only?: boolean;
  priority?: Exclude<Priority, "unknown">;
  source?: string;
  min_epss?: number;
  min_epss_percentile?: number;
  sort?: "newest" | "priority_desc" | "epss_desc" | "cvss_desc";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(path, {
    headers: { Accept: "application/json" },
    ...init,
  });
  if (!resp.ok) {
    let message = `Request failed (${resp.status})`;
    try {
      const body = await resp.json();
      const detail = body?.detail ?? body?.message;
      if (detail) {
        message =
          typeof detail === "string"
            ? detail
            : (detail.message ?? JSON.stringify(detail));
      }
    } catch {
      /* keep default message */
    }
    const err = new Error(message) as Error & { status?: number };
    err.status = resp.status;
    throw err;
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

export function toParams(q: VulnQuery): string {
  const params = new URLSearchParams();
  if (q.page) params.set("page", String(q.page));
  if (q.page_size) params.set("page_size", String(q.page_size));
  if (q.q) params.set("q", q.q);
  if (q.severity) params.set("severity", q.severity);
  if (q.date_from) params.set("date_from", q.date_from);
  if (q.date_to) params.set("date_to", q.date_to);
  if (q.watchlist_only) params.set("watchlist_only", "true");
  if (q.kev_only) params.set("kev_only", "true");
  if (q.ransomware_only) params.set("ransomware_only", "true");
  if (q.priority) params.set("priority", q.priority);
  if (q.source) params.set("source", q.source);
  if (q.min_epss !== undefined) params.set("min_epss", String(q.min_epss));
  if (q.min_epss_percentile !== undefined)
    params.set("min_epss_percentile", String(q.min_epss_percentile));
  if (q.sort && q.sort !== "newest") params.set("sort", q.sort);
  const s = params.toString();
  return s ? `?${s}` : "";
}

export const api = {
  health: () => request<{ status: string; database: string; time: string }>("/api/health"),
  vulns: (q: VulnQuery) => request<VulnListResponse>(`/api/vulns${toParams(q)}`),
  vuln: (id: string) => request<VulnDetail>(`/api/vulns/${encodeURIComponent(id)}`),
  watchlist: () =>
    request<{ items: WatchlistItemDTO[] }>("/api/watchlist"),
  createWatchlist: (name: string, keywords: string[]) =>
    request<WatchlistItemDTO>("/api/watchlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, keywords }),
    }),
  updateWatchlist: (id: number, name: string, keywords: string[]) =>
    request<WatchlistItemDTO>(`/api/watchlist/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, keywords }),
    }),
  deleteWatchlist: (id: number) =>
    request<void>(`/api/watchlist/${id}`, { method: "DELETE" }),
  syncStatus: () => request<SyncStatus>("/api/sync/status"),
  triggerSync: () =>
    request<{ accepted: boolean; message: string }>("/api/sync/run", {
      method: "POST",
    }),
};

const DT = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  timeZone: "UTC",
});

const D = new Intl.DateTimeFormat("en-GB", {
  year: "numeric",
  month: "short",
  day: "2-digit",
  timeZone: "UTC",
});

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "Unknown";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "Unknown";
  return `${DT.format(d)} UTC`;
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "Unknown";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "Unknown";
  return D.format(d);
}

export function sourceLabel(source: string): string {
  const labels: Record<string, string> = {
    cve_now: "cve.now",
    cisa_kev: "CISA KEV",
    first_epss: "FIRST EPSS",
    nvd: "NVD",
    github_advisory: "GitHub Adv.",
    osv_dev: "OSV.dev",
    exploit_db: "Exploit-DB",
    metasploit: "Metasploit",
    nuclei: "Nuclei",
    poc_in_github: "PoC-in-GitHub",
    redhat: "Red Hat",
    debian_tracker: "Debian",
    ubuntu: "Ubuntu",
    cisa_advisories: "CISA Advisories",
    threatfox: "ThreatFox",
    vulners: "Vulners",
  };
  return labels[source] ?? source;
}

/** Valid values for the API `source` filter (mirrors backend SOURCE_RECORD_SOURCES). */
export const SOURCE_FILTER_OPTIONS = [
  "cve_now",
  "cisa_kev",
  "nvd",
  "github_advisory",
  "osv_dev",
  "exploit_db",
  "metasploit",
  "nuclei",
  "poc_in_github",
  "redhat",
  "debian_tracker",
  "ubuntu",
  "cisa_advisories",
  "threatfox",
  "vulners",
] as const;
