import { useState } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import { api, fmtDateTime } from "../api";
import { useSyncStatus } from "../sync-context";
import {
  AlertTriangleIcon,
  HomeIcon,
  ListIcon,
  MenuIcon,
  RssIcon,
  ShieldIcon,
  StarIcon,
} from "../icons";

const nav = [
  { to: "/", label: "Overview", icon: <HomeIcon /> },
  { to: "/cves", label: "Latest CVEs", icon: <ListIcon /> },
  { to: "/watchlist", label: "My Watchlist", icon: <StarIcon /> },
  { to: "/kev", label: "Known Exploited", icon: <AlertTriangleIcon /> },
  { to: "/feeds", label: "Feed Status", icon: <RssIcon /> },
];

export function SyncIndicator() {
  const { status, error } = useSyncStatus();
  const latest = status
    ? status.sources
        .map((s) => s.last_success_at)
        .filter((x): x is string => !!x)
        .sort()
        .pop() ?? null
    : null;

  let dotClass = "dot-unknown";
  let label = "Sync status unknown";
  if (error) label = "Sync status unavailable";
  else if (status?.running) label = "Sync in progress…";
  else if (status) {
    const anyStale = status.sources.some((s) => s.stale);
    const anyError = status.sources.some((s) => s.status === "error");
    const anyNever = status.sources.some(
      (s) => s.status === "never_run" || s.last_success_at === null,
    );
    if (anyNever) {
      dotClass = "dot-unknown";
      label = "Sync not completed yet";
    } else if (anyStale) {
      dotClass = "dot-stale";
      label = "Feeds stale";
    } else if (anyError) {
      dotClass = "dot-stale";
      label = "Last sync had errors";
    } else if (latest) {
      dotClass = "dot-ok";
      label = `Last successful sync ${fmtDateTime(latest)}`;
    }
  }

  return (
    <div className="sync-indicator">
      <span className={`dot ${dotClass}`} aria-hidden="true" />
      <span>{label}</span>
      <Link to="/feeds">Feed Status</Link>
      <button
        className="icon-btn"
        onClick={() => api.triggerSync().catch(() => undefined)}
        title="Trigger a manual sync in the background"
        aria-label="Trigger manual sync"
        type="button"
      >
        <RssIcon width={14} height={14} />
      </button>
    </div>
  );
}

export default function Shell() {
  const [open, setOpen] = useState(false);

  return (
    <div className="shell">
      {open && (
        <div
          className="mobile-nav-backdrop show"
          onClick={() => setOpen(false)}
          aria-hidden="true"
        />
      )}
      <nav
        className={`sidebar${open ? " open" : ""}`}
        aria-label="Main navigation"
      >
        <div className="brand">
          <ShieldIcon width={22} height={22} />
          VulnWatch
        </div>
        {nav.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.to === "/"}
            className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
            onClick={() => setOpen(false)}
          >
            {n.icon}
            {n.label}
          </NavLink>
        ))}
        <div className="sidebar-footer">Local, single-user deployment.</div>
      </nav>
      <div className="main">
        <div style={{ display: "flex", alignItems: "center", padding: "12px 16px 0" }}>
          <button
            className="mobile-nav-toggle"
            aria-label="Open navigation menu"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
            type="button"
          >
            <MenuIcon />
          </button>
        </div>
        <Outlet />
      </div>
    </div>
  );
}
