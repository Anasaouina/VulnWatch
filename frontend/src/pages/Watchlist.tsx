import { useEffect, useState } from "react";
import {
  api,
  type WatchlistItemDTO,
} from "../api";
import {
  EmptyState,
  ErrorState,
  TableSkeleton,
} from "../components/badges";
import { TrashIcon } from "../icons";

export default function Watchlist() {
  const [items, setItems] = useState<WatchlistItemDTO[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [draftName, setDraftName] = useState("");
  const [draftKeywords, setDraftKeywords] = useState("");
  const [newName, setNewName] = useState("");
  const [newKeywords, setNewKeywords] = useState("");
  const [saving, setSaving] = useState(false);

  const load = () =>
    api
      .watchlist()
      .then((r) => {
        setItems(r.items);
        setError(null);
      })
      .catch((e: Error) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  async function mutate(fn: () => Promise<unknown>) {
    setSaving(true);
    setError(null);
    try {
      await fn();
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>My Watchlist</h1>
          <p className="desc">
            Products you care about. Entries below show the term that matched
            and whether the match came from structured product data or keyword
            matching. A watchlist match does not prove a deployed system is
            affected.
          </p>
        </div>
      </div>
      <div className="content">
        <div className="card" style={{ marginBottom: 14 }}>
          <form
            className="watch-row"
            onSubmit={(e) => {
              e.preventDefault();
              if (!newName.trim()) return;
              mutate(() =>
                api.createWatchlist(
                  newName.trim(),
                  newKeywords
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean),
                ),
              );
              setNewName("");
              setNewKeywords("");
            }}
          >
            <input
              type="text"
              placeholder="Product name (e.g. OpenSSH)"
              aria-label="New watchlist product name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              maxLength={200}
            />
            <input
              type="text"
              className="keywords-field"
              placeholder="Optional extra match keywords, comma-separated"
              aria-label="New watchlist keywords"
              value={newKeywords}
              onChange={(e) => setNewKeywords(e.target.value)}
              maxLength={2000}
            />
            <button
              className="btn btn-primary"
              type="submit"
              disabled={saving || !newName.trim()}
            >
              Add product
            </button>
          </form>
        </div>

        {error && <ErrorState message={error} onRetry={load} />}
        {!items && !error && <TableSkeleton rows={4} />}

        {items && items.length === 0 && (
          <EmptyState
            headline="No watchlist products yet"
            hint="Add the products you want to track above."
          />
        )}

        {items &&
          items.map((item) =>
            editingId === item.id ? (
              <div className="card" key={item.id} style={{ marginBottom: 10 }}>
                <form
                  className="watch-row"
                  onSubmit={(e) => {
                    e.preventDefault();
                    mutate(() =>
                      api.updateWatchlist(
                        item.id,
                        draftName.trim() || item.name,
                        draftKeywords
                          .split(",")
                          .map((s) => s.trim())
                          .filter(Boolean),
                      ),
                    ).then(() => setEditingId(null));
                  }}
                >
                  <input
                    type="text"
                    aria-label={`Product name for ${item.name}`}
                    value={draftName}
                    onChange={(e) => setDraftName(e.target.value)}
                    maxLength={200}
                  />
                  <input
                    type="text"
                    className="keywords-field"
                    aria-label={`Extra keywords for ${item.name}, comma-separated`}
                    value={draftKeywords}
                    onChange={(e) => setDraftKeywords(e.target.value)}
                    maxLength={2000}
                  />
                  <button className="btn btn-primary" type="submit" disabled={saving}>
                    Save
                  </button>
                  <button
                    className="btn"
                    type="button"
                    onClick={() => setEditingId(null)}
                  >
                    Cancel
                  </button>
                </form>
              </div>
            ) : (
              <div
                className="card"
                key={item.id}
                style={{
                  marginBottom: 10,
                  display: "flex",
                  alignItems: "center",
                  gap: 14,
                  flexWrap: "wrap",
                }}
              >
                <div style={{ minWidth: 160, fontWeight: 600 }}>{item.name}</div>
                <div style={{ color: "var(--text-secondary)", fontSize: 13, flex: 1 }}>
                  {item.keywords.length > 0
                    ? `Extra keywords: ${item.keywords.join(", ")}`
                    : "Matching on product name."}{" "}
                  · {item.match_count} recorded match{item.match_count === 1 ? "" : "es"}
                  {item.match_count > 0 && (
                    <> · <a href={`/cves?watchlist=true`}>view CVEs</a></>
                  )}
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <button
                    className="btn"
                    type="button"
                    onClick={() => {
                      setEditingId(item.id);
                      setDraftName(item.name);
                      setDraftKeywords(item.keywords.join(", "));
                    }}
                  >
                    Edit
                  </button>
                  <button
                    className="btn btn-danger"
                    type="button"
                    aria-label={`Remove ${item.name} from watchlist`}
                    onClick={() => mutate(() => api.deleteWatchlist(item.id))}
                  >
                    <TrashIcon width={15} height={15} label="Remove" />
                    Remove
                  </button>
                </div>
              </div>
            ),
          )}
      </div>
    </div>
  );
}
