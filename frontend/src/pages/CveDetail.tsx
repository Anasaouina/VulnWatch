import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  api,
  fmtDate,
  fmtDateTime,
  sourceLabel,
  type VulnDetail,
} from "../api";
import { PRIORITY_DOC, priorityLabel, severityLabel } from "../severity";
import { ErrorState, KevBadge, NotKevBadge, PriorityBadge, SevBadgeWithScore, TableSkeleton } from "../components/badges";
import { ArrowLeftIcon } from "../icons";

function ProvenanceLabel({ summarySource }: { summarySource: string | null }) {
  if (!summarySource) return null;
  if (summarySource.startsWith("cve_now:model-summary"))
    return "Summary provided by cve.now (model-generated, cve.now labels this in their FAQ); original record text preserved in source details below.";
  if (summarySource === "cisa_kev:short_description")
    return "This description comes from the CISA Known Exploited Vulnerabilities catalog (short description).";
  if (summarySource === "cve_now:cvelistV5-description")
    return "Text from the published CVE record (via cve.now).";
  return "Description provenance: " + summarySource;
}

export default function CveDetail() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [vuln, setVuln] = useState<VulnDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setError(null);
    api
      .vuln(id)
      .then(setVuln)
      .catch((e: Error) => setError(e.message));
  };

  useEffect(load, [id]);

  if (error) {
    return (
      <div className="content">
        <div className="detail-head" style={{ marginTop: 12 }}>
          <button className="btn" onClick={() => navigate(-1)} type="button">
            <ArrowLeftIcon width={14} height={14} /> Back
          </button>
        </div>
        <ErrorState message={`Could not load CVE: ${error}`} onRetry={load} />
      </div>
    );
  }

  if (!vuln) {
    return (
      <div className="content">
        <div style={{ marginTop: 12, marginBottom: 12 }}>
          <Link className="cve-id" to="/cves" onClick={(e) => { e.preventDefault(); navigate(-1); }}>
            <ArrowLeftIcon width={12} height={12} /> Back to list
          </Link>
        </div>
        <TableSkeleton rows={6} />
      </div>
    );
  }

  return (
    <div className="content" style={{ maxWidth: 1080 }}>
      <div style={{ marginBottom: 12 }}>
        <button className="btn" onClick={() => navigate(-1)} type="button">
          <ArrowLeftIcon width={14} height={14} /> Back
        </button>
      </div>
      <div className="card" style={{ padding: 20 }}>
        <div className="detail-head">
          <span className="cve-id-big">{vuln.vuln_id}</span>
          <SevBadgeWithScore
            bucket={vuln.severity_bucket}
            text={
              vuln.cvss_score != null
                ? `${severityLabel[vuln.severity_bucket]} (CVSS ${vuln.cvss_score})`
                : severityLabel[vuln.severity_bucket]
            }
          />
          <PriorityBadge priority={vuln.priority} />
          {vuln.kev ? <KevBadge /> : <NotKevBadge />}
        </div>
        <h1 style={{ fontSize: 17, margin: "6px 0 0", overflowWrap: "anywhere" }}>
          {vuln.title ?? "No title provided"}
        </h1>
        {vuln.kev ? (
          <div className="detail-prov" style={{ marginTop: 8 }}>
            CISA states this CVE was exploited in the wild. VulnWatch priority:{" "}
            <strong>{priorityLabel[vuln.priority]}</strong> — VulnWatch assessment, not an official CISA rating.
          </div>
        ) : (
          <div className="detail-prov" style={{ marginTop: 8 }}>
            Not listed in the CISA Known Exploited Vulnerabilities catalog shown here
            — the catalog is not an exhaustive list of all exploited vulnerabilities.
          </div>
        )}
      </div>

      <section className="detail-section">
        <h2>VulnWatch priority</h2>
        <div className="card">
          <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 8 }}>
            <PriorityBadge priority={vuln.priority} />
            <span className="detail-prov" style={{ margin: 0 }}>{PRIORITY_DOC}</span>
          </div>
          {vuln.priority_reasons.length > 0 ? (
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {vuln.priority_reasons.map((r, i) => (
                <li key={i} style={{ marginBottom: 4, overflowWrap: "anywhere" }}>{r}</li>
              ))}
            </ul>
          ) : (
            <div className="detail-desc">
              Unknown — no CVSS, EPSS or KEV signal is available yet for this record.
            </div>
          )}
        </div>
      </section>

      <section className="detail-section">
        <h2>Summary</h2>
        <div className="card">
          {vuln.summary ? (
            <div>
              <div className="detail-desc">{vuln.summary}</div>
              <div className="detail-prov">
                <ProvenanceLabel summarySource={vuln.summary_source} />
              </div>
            </div>
          ) : (
            <div className="detail-desc">Not provided by the collected sources.</div>
          )}
        </div>
      </section>

      <section className="detail-section">
        <h2>Key dates</h2>
        <dl className="kv-grid">
          <div className="kv">
            <dt>Published</dt>
            <dd>{fmtDateTime(vuln.published_at)}</dd>
          </div>
          <div className="kv">
            <dt>First seen (source)</dt>
            <dd>{fmtDateTime(vuln.first_seen_at)}</dd>
          </div>
          <div className="kv">
            <dt>Last updated (source)</dt>
            <dd>{fmtDateTime(vuln.last_updated_at)}</dd>
          </div>
          <div className="kv">
            <dt>CISA date added</dt>
            <dd>{vuln.kev ? fmtDate(vuln.kev_date_added) : "Not listed"}</dd>
          </div>
          <div className="kv">
            <dt>Record collected</dt>
            <dd>{fmtDateTime(vuln.created_at)}</dd>
          </div>
        </dl>
      </section>

      <section className="detail-section">
        <h2>Severity attributions</h2>
        {vuln.cvss_scores.length === 0 ? (
          <div className="card">
            <div className="detail-desc">Unknown</div>
            {vuln.stated_severity && (
              <div className="detail-prov">
                This record has no numeric CVSS data; a source stated severity:{" "}
                <strong>{vuln.stated_severity}</strong>.
              </div>
            )}
          </div>
        ) : (
          <dl className="kv-grid">
            {vuln.cvss_scores.map((s, i) => (
              <div className="kv" key={i}>
                <dt>CVSS {s.version === "unknown" ? "version unknown" : s.version} — score {s.score}</dt>
                <dd>
                  Source: {s.source}
                  {s.vector ? <div style={{ fontFamily: "var(--mono)", fontSize: 12.5 }}>{s.vector}</div> : null}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </section>

      <section className="detail-section">
        <h2>Exploit prediction (FIRST EPSS)</h2>
        <div className="card">
          {vuln.epss_score == null ? (
            <div className="detail-desc">
              Unknown — no EPSS score available for this CVE yet. VulnWatch stores
              scores daily from the FIRST EPSS bulk feed.
            </div>
          ) : (
            <div>
              <dl className="kv-grid">
                <div className="kv">
                  <dt>EPSS score</dt>
                  <dd>
                    {vuln.epss_score.toFixed(4)} — estimated probability of
                    exploitation in the wild within the next 30 days
                  </dd>
                </div>
                <div className="kv">
                  <dt>EPSS percentile</dt>
                  <dd>
                    {vuln.epss_percentile != null
                      ? `${(vuln.epss_percentile * 100).toFixed(2)}% of all scored CVEs have an equal or lower score`
                      : "Unknown"}
                  </dd>
                </div>
                <div className="kv">
                  <dt>Score date (feed)</dt>
                  <dd>{fmtDate(vuln.epss_score_date)}</dd>
                </div>
                <div className="kv">
                  <dt>Scored model / retrieved</dt>
                  <dd>
                    {vuln.epss_model_version || "Unknown model"}
                    {" · "}
                    {fmtDateTime(vuln.epss_retrieved_at)}
                  </dd>
                </div>
                <div className="kv">
                  <dt>Source</dt>
                  <dd>
                    {sourceLabel(vuln.epss_source ?? "first_epss")}
                    {vuln.epss_source_url ? (
                      <>
                        {" — "}
                        <a href={vuln.epss_source_url} target="_blank" rel="noopener noreferrer nofollow">
                          FIRST EPSS data ↗
                        </a>
                      </>
                    ) : null}
                  </dd>
                </div>
              </dl>
              {vuln.epss_history.length > 1 ? (
                <div style={{ marginTop: 10 }}>
                  <div className="detail-prov" style={{ marginBottom: 6 }}>
                    Daily score history (most recent first; one snapshot per score
                    date from VulnWatch imports).
                  </div>
                  <table className="cve-table" style={{ width: "100%" }}>
                    <thead>
                      <tr>
                        <th scope="col">Score date</th>
                        <th scope="col">EPSS score</th>
                        <th scope="col">Percentile</th>
                        <th scope="col">Model</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vuln.epss_history.map((h, i) => (
                        <tr key={i}>
                          <td data-label="Score date">{fmtDate(h.score_date)}</td>
                          <td data-label="EPSS score">{h.score.toFixed(4)}</td>
                          <td data-label="Percentile">
                            {h.percentile != null ? h.percentile.toFixed(4) : "Unknown"}
                          </td>
                          <td data-label="Model">{h.model_version || "Unknown"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <div className="detail-prov" style={{ marginTop: 6 }}>
                    EPSS is a statistical estimate and model versions change over
                    time; scores across a model-version boundary are not directly
                    comparable.
                  </div>
                </div>
              ) : (
                <div className="detail-prov" style={{ marginTop: 8 }}>
                  Only one score snapshot so far; history builds up day by day.
                </div>
              )}
            </div>
          )}
        </div>
      </section>

      {vuln.kev && (
        <section className="detail-section">
          <h2>CISA KEV context</h2>
          <dl className="kv-grid">
            <div className="kv">
              <dt>Date added to CISA catalog</dt>
              <dd>{fmtDate(vuln.kev_date_added)}</dd>
            </div>
            <div className="kv">
              <dt>Due date (CISA required remediation)</dt>
              <dd>{vuln.kev_due_date ? fmtDate(vuln.kev_due_date) : "Unknown"}</dd>
            </div>
            <div className="kv">
              <dt>Ransomware campaign use</dt>
              <dd>
                {vuln.kev_ransomware_use
                  ? vuln.kev_ransomware_use === "Known"
                    ? "Known — CISA reports use in ransomware campaigns"
                    : vuln.kev_ransomware_use
                  : "Unknown"}
              </dd>
            </div>
            <div className="kv">
              <dt>Catalog version / released</dt>
              <dd>
                {vuln.kev_catalog_released
                  ? `Feed released ${fmtDate(vuln.kev_catalog_released)}`
                  : "Unknown"}
              </dd>
            </div>
          </dl>
          {vuln.kev_required_action && (
            <div className="detail-prov" style={{ marginTop: 8 }}>
              CISA required action: {vuln.kev_required_action}
            </div>
          )}
          <div className="detail-prov" style={{ marginTop: 8 }}>
            Being listed does not guarantee exploitation of systems you run;
            verify affected products and versions against your own assets.
          </div>
        </section>
      )}

      <section className="detail-section">
        <h2>Watchlist matches</h2>
        {vuln.watchlist_matches.length === 0 ? (
          <div className="card">
            <div className="detail-desc">No watchlist products match this CVE.</div>
          </div>
        ) : (
          <div className="card">
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {vuln.watchlist_matches.map((m, i) => (
                <span className="match-pill" key={i}>
                  <span>{m.name}</span>
                  <span className="kind">
                    {m.match_type === "structured" ? "Structured product match" : "Keyword match"}
                  </span>
                  <span>term: {m.matched_term}</span>
                </span>
              ))}
            </div>
            <div className="detail-prov">
              A match means the term appears in collected record data; a watchlist
              match does not prove a deployed system is affected.
            </div>
          </div>
        )}
      </section>

      <section className="detail-section">
        <h2>Affected products and remediation (where a source supplied it)</h2>
        {vuln.affected_products.length === 0 ? (
          <div className="card">
            <div className="detail-desc">Unknown — no structured affected-product data was collected.</div>
          </div>
        ) : (
          <dl className="kv-grid">
            {vuln.affected_products.map((a, i) => (
              <div className="kv" key={i}>
                <dt>
                  {a.vendor ? `${a.vendor} — ` : ""}
                  {a.product || "Unknown product"}
                </dt>
                <dd>
                  {a.versions && a.versions.length > 0 ? (
                    <div>Affected versions: {a.versions.map(String).join(", ")}</div>
                  ) : (
                    <div>Affected versions: Unknown</div>
                  )}
                  {a.fixes && a.fixes.length > 0 && (
                    <div>Fixes: {a.fixes.map(String).join(", ")}</div>
                  )}
                  <div className="detail-prov">Source: {sourceLabel(a.source)}</div>
                </dd>
              </div>
            ))}
          </dl>
        )}
      </section>

      <section className="detail-section">
        <h2>Source records and links</h2>
        <dl className="kv-grid">
          {vuln.source_records.map((r, i) => (
            <div className="kv" key={i}>
              <dt>{sourceLabel(r.source)}</dt>
              <dd>
                {r.url ? (
                  <a href={r.url} target="_blank" rel="noopener noreferrer nofollow">
                    View record ↗
                  </a>
                ) : (
                  "No link"
                )}
                <div className="detail-prov">
                  First synced {fmtDateTime(r.first_synced_at)} · Last synced{" "}
                  {fmtDateTime(r.last_synced_at)}
                </div>
                {r.data?.kind ? (
                  <div className="detail-prov">Record type: {String(r.data.kind)}</div>
                ) : null}
                {r.data && (r.data as { requiredAction?: unknown }).requiredAction ? (
                  <div className="detail-prov">
                    CISA required action:{" "}
                    {String((r.data as { requiredAction?: unknown }).requiredAction)}
                  </div>
                ) : null}
              </dd>
            </div>
          ))}
        </dl>
      </section>
    </div>
  );
}
