import type { ReactNode } from "react";
import type { Priority, SeverityBucket, WatchMatch } from "../api";
import { PRIORITY_DOC, priorityLabel, severityLabel } from "../severity";
import { sourceLabel } from "../api";

/** Neutral tag chip showing one intelligence source that carries this CVE. */
export function SourceBadge({ source }: { source: string }) {
  return (
    <span className="badge badge-source" title={sourceLabel(source)}>
      {sourceLabel(source)}
    </span>
  );
}

export function SevBadge({ bucket }: { bucket: SeverityBucket }) {
  return (
    <span className={`badge badge-${bucket}`}>
      <span className="dot" aria-hidden="true" />
      <span>{severityLabel[bucket]}</span>
    </span>
  );
}

export function PriorityBadge({ priority }: { priority: Priority }) {
  return (
    <span
      className={`badge badge-prio-${priority}`}
      title={`${PRIORITY_DOC} Signals are shown per CVE in the detail view.`}
    >
      <span className="dot" aria-hidden="true" />
      <span>{priorityLabel[priority]}</span>
    </span>
  );
}

export function SevBadgeWithScore({
  bucket,
  text,
}: {
  bucket: SeverityBucket;
  text: string;
}) {
  return <span className={`badge badge-${bucket}`}>{text}</span>;
}

export function KevBadge() {
  return (
    <span
      className="badge badge-kev"
      title="Listed in the CISA Known Exploited Vulnerabilities catalog"
    >
      <span className="dot" aria-hidden="true" />
      Known exploited
    </span>
  );
}

export function NotKevBadge() {
  return <span className="badge badge-unknown">Exploitation status unknown</span>;
}

export function WatchBadge({ matches }: { matches: WatchMatch[] }) {
  if (matches.length === 0) {
    return <span className="badge badge-unknown">—</span>;
  }
  const kind =
    matches.find((m) => m.match_type === "structured")?.match_type ??
    matches[0].match_type;
  const label = kind === "structured" ? "Matched" : "Keyword match";
  const names = Array.from(new Set(matches.map((m) => m.name))).join(", ");
  return (
    <span className="badge badge-match" title={names}>
      {label}
      {matches.length > 1 ? ` ×${matches.length}` : ""}
    </span>
  );
}

export function EmptyState({
  headline,
  hint,
  children,
}: {
  headline: string;
  hint?: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="primary-note">{headline}</div>
      {hint && <div>{hint}</div>}
      {children && <div style={{ marginTop: 12 }}>{children}</div>}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="error-state" role="alert">
      <span>{message}</span>
      {onRetry && (
        <button className="btn" onClick={onRetry} type="button">
          Retry
        </button>
      )}
    </div>
  );
}

export function TableSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="card skeleton-table" aria-busy="true" aria-live="polite">
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          className="skeleton kl"
          style={{ width: `${90 - (i % 4) * 12}%` }}
        />
      ))}
    </div>
  );
}
