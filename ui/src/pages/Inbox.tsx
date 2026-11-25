import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, InboxResponse, InboxRow } from "../api";

interface SubscriptionOption {
  subscription: {
    id: string;
    name: string;
    tenant_id: string;
    state: string;
  };
  decision: string;
}

interface DiscoveredSubscription {
  id: string;
  name: string;
  tenant_id: string;
  state: string;
}

export default function Inbox() {
  const [rows, setRows] = useState<InboxRow[]>([]);
  const [env, setEnv] = useState("prod");
  const [severity, setSeverity] = useState("");
  const [subscriptionId, setSubscriptionId] = useState(
    () => localStorage.getItem("estatetrace.subscription_id") || "",
  );
  const [subscriptions, setSubscriptions] = useState<DiscoveredSubscription[]>([]);
  const [lastVisit, setLastVisit] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [ask, setAsk] = useState("");
  const [answer, setAnswer] = useState<unknown>(null);
  const [askBusy, setAskBusy] = useState(false);
  const [refreshBusy, setRefreshBusy] = useState(false);
  const [scanBusy, setScanBusy] = useState(false);
  const [actionMsg, setActionMsg] = useState("");

  async function loadSubscriptions() {
    const data = await api<{ subscriptions: DiscoveredSubscription[] }>("/subscriptions");
    setSubscriptions(data.subscriptions || []);
  }

  async function refreshSubscriptions() {
    setRefreshBusy(true);
    setActionMsg("Discovering Azure subscriptions…");
    try {
      const result = await api<{ tenants: number; subscriptions: number }>(
        "/azure/refresh",
        {
          method: "POST",
          body: "{}",
        },
      );
      await loadSubscriptions();
      setActionMsg(
        `Found ${result.subscriptions} subscription(s) in ${result.tenants} tenant(s).`,
      );
      setError("");
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      setActionMsg("");
      setError(`Azure discovery failed: ${message}`);
    } finally {
      setRefreshBusy(false);
    }
  }

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
    loadSubscriptions();
  }, []);

  useEffect(() => {
    if (subscriptionId) {
      localStorage.setItem("estatetrace.subscription_id", subscriptionId);
    } else {
      localStorage.removeItem("estatetrace.subscription_id");
    }
  }, [subscriptionId]);

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

  async function runScan() {
    setScanBusy(true);
    setActionMsg("Starting scan…");
    try {
      await api("/scan", {
        method: "POST",
        body: JSON.stringify(
          subscriptionId
            ? { subscription_ids: [subscriptionId] }
            : { subscription_ids: null },
        ),
      });
      setActionMsg(
        subscriptionId
          ? "Selected subscription scan started."
          : "Azure scan started.",
      );
      window.setTimeout(() => {
        load();
        setActionMsg(
          subscriptionId
            ? "Selected subscription scan completed or is still updating."
            : "Azure scan completed or is still updating.",
        );
      }, 3000);
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      setActionMsg("");
      setError(`Scan failed to start: ${message}`);
    } finally {
      setScanBusy(false);
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
            <option value="dev">Dev</option>
            <option value="sandbox">Sandbox</option>
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
          Subscription
          <select
            value={subscriptionId}
            onChange={(e) => setSubscriptionId(e.target.value)}
          >
            <option value="">All subscriptions</option>
            {subscriptions
              .filter((sub) => sub.state !== "Disabled")
              .map((sub) => (
                <option key={sub.id} value={sub.id}>
                  {sub.name}
                </option>
              ))}
          </select>
        </label>
        <button
          className="secondary"
          onClick={refreshSubscriptions}
          disabled={refreshBusy}
        >
          {refreshBusy ? "Refreshing Azure…" : "Refresh Azure subscriptions"}
        </button>
        <button onClick={load} disabled={scanBusy || refreshBusy}>
          Refresh inbox
        </button>
        <button
          className="secondary"
          onClick={runScan}
          disabled={scanBusy || refreshBusy}
        >
          {scanBusy
            ? "Starting scan…"
            : subscriptionId
            ? "Scan selected subscription"
            : "Run scan"}
        </button>
      </div>

      <div className="muted" style={{ marginBottom: "0.75rem" }}>
        {lastVisit
          ? `${sinceCount} change(s) since last visit (${lastVisit})`
          : "First visit — all rows marked since last visit"}
      </div>

      {error && <div className="panel">{error}</div>}
      {actionMsg && <div className="panel muted">{actionMsg}</div>}

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
