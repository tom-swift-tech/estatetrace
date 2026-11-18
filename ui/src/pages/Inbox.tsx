import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

export default function Inbox() {
  const [rows, setRows] = useState<any[]>([]);
  const [env, setEnv] = useState("prod");
  const [error, setError] = useState("");

  async function load() {
    try {
      const q = env ? `?environment=${encodeURIComponent(env)}` : "";
      const data = await api<{ rows: any[] }>(`/inbox${q}`);
      setRows(data.rows || []);
      setError("");
    } catch (e: any) {
      setError(e.message);
    }
  }

  useEffect(() => {
    load();
  }, [env]);

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
      {error && <div className="panel">{error}</div>}
      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>Resource</th>
            <th>Change</th>
            <th>Environment</th>
            <th>Compliance</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.change?.id}>
              <td>
                <div>{r.change?.times?.observation_time}</div>
                <div className="muted">{r.change?.times?.event_time || "—"}</div>
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
                <span className={`badge ${r.classification?.environment || ""}`}>
                  {r.classification?.environment}
                </span>
                <div className="muted">{r.classification?.reason}</div>
              </td>
              <td>
                {r.evaluation ? (
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
    </div>
  );
}