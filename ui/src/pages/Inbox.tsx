import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, InboxResponse, InboxRow } from "../api";

export default function Inbox() {
  const [rows, setRows] = useState<InboxRow[]>([]);
  const [env, setEnv] = useState("prod");
  const [severity, setSeverity] = useState("");
  const [subscriptionId, setSubscriptionId] = useState("");
  const [lastVisit, setLastVisit] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [ask, setAsk] = useState("");
  const [answer, setAnswer] = useState<unknown>(null);
  const [askBusy, setAskBusy] = useState(false);

  async function load() {
    try {
      const params = new URLSearchParams();
      if (env) params.set("environment", env);
      if (severity) params.set("severity", severity);
      if (subscriptionId.trim()) {
        params.set("subscription_id", subscriptionId.trim());
      }
      const q = params.toString() ? `?${params}` : "";
      const data = await api<InboxResponse>(`/inbox${q}`);
      setRows(data.rows || []);
      setLastVisit(data.last_visit ?? null);
      setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  useEffect(() => {
    load();
  }, [env, severity, subscriptionId]);

  const sinceCount = rows.filter((r) => r.since_last_visit).length;

  async function askAboutView() {
    setAskBusy(true);
    try {
      const data = await api("/connectors/chat/ask", {
        method: "POST",
        body: JSON.stringify({
          question: ask,
          environment: env || null,
          severity: severity || null,
          subscription_id: subscriptionId.trim() || null,
          include_ticket_notes: false,
        }),
      });
      setAnswer(data);
    } catch (e: unknown) {
      setAnswer({
        error: e instanceof Error ? e.message : String(e),
        gaps: ["chat unavailable or not configured"],
      });
    } finally {
      setAskBusy(false);
    }
  }

  return (
    <div>
      <div className="toolbar">
        <label>
          Environment
          <select value={env} onChange={(e) => setEnv(e.target.value)}>
            <option value="prod">Prod</option>
            <option value="nonprod">Non-prod</option>
            <option value="">All</option>
          </select>
        </label>
        <label>
          Severity
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
          >
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </label>
        <label>
          Subscription ID
          <input
            placeholder="Paste subscription GUID"
            value={subscriptionId}
            onChange={(e) => setSubscriptionId(e.target.value)}
          />
        </label>
        <button onClick={load}>Refresh</button>
        <button
          className="secondary"
          onClick={async () => {
            await api("/scan", { method: "POST", body: "{}" });
            setTimeout(load, 1500);
          }}
        >
          Run scan
        </button>
      </div>

      <div className="muted" style={{ marginBottom: "0.75rem" }}>
        {lastVisit
          ? `${sinceCount} change(s) since last visit (${lastVisit})`
          : "First visit — all rows marked since last visit"}
      </div>

      {error && <div className="panel">{error}</div>}

      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>Resource</th>
            <th>Change</th>
            <th>Environment</th>
            <th>Triage</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.change?.id}>
              <td>
                <div>{r.change?.times?.observation_time}</div>
                <div className="muted">
                  {r.change?.times?.event_time || "—"}
                </div>
                {r.since_last_visit && (
                  <span className="badge since">Since last visit</span>
                )}
              </td>
              <td>
                <Link
                  to={`/resources/${encodeURIComponent(r.change?.resource_id || "")}`}
                >
                  {r.resource?.name || r.change?.resource_id}
                </Link>
                <div className="muted">{r.resource?.resource_type}</div>
              </td>
              <td>{r.change?.label}</td>
              <td>
                <span
                  className={`badge ${r.classification?.environment || ""}`}
                >
                  {r.classification?.environment}
                </span>
                <div className="muted">{r.classification?.reason}</div>
              </td>
              <td>
                {r.triage ? (
                  <>
                    <span className={`badge ${r.triage.state}`}>
                      {r.triage.state}
                    </span>
                    <div className="muted">{r.triage.reason}</div>
                    {r.disposition && (
                      <div className="muted">
                        {r.disposition.disposition}
                        {r.disposition.owner
                          ? ` · ${r.disposition.owner}`
                          : ""}
                      </div>
                    )}
                  </>
                ) : r.evaluation ? (
                  <span className={`badge ${r.evaluation.outcome}`}>
                    {r.evaluation.outcome}
                  </span>
                ) : (
                  "—"
                )}
              </td>
            </tr>
          ))}
          {!rows.length && (
            <tr>
              <td colSpan={5} className="muted">
                No production changes yet. Refresh Azure scope, track a
                subscription, and run a scan.
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <div className="panel" style={{ marginTop: "1.25rem" }}>
        <strong>Ask about this view</strong>
        <div className="muted" style={{ marginBottom: "0.5rem" }}>
          Uses current inbox filters. Ticket notes stay opt-in (off).
        </div>
        <textarea
          rows={3}
          value={ask}
          onChange={(e) => setAsk(e.target.value)}
          placeholder="How many actionable findings are in this view?"
        />
        <div className="toolbar">
          <button disabled={!ask.trim() || askBusy} onClick={askAboutView}>
            {askBusy ? "Asking…" : "Ask"}
          </button>
        </div>
        {answer != null && (
          <div className="pre">{JSON.stringify(answer, null, 2)}</div>
        )}
      </div>
    </div>
  );
}
