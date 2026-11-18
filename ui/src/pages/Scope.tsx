import { useEffect, useState } from "react";
import { api } from "../api";

export default function Scope() {
  const [rows, setRows] = useState<any[]>([]);
  const [filter, setFilter] = useState("");
  const [preview, setPreview] = useState<any>(null);
  const [msg, setMsg] = useState("");

  async function load() {
    const data = await api<{ rows: any[] }>("/scope");
    setRows(data.rows || []);
  }

  useEffect(() => {
    load().catch((e) => setMsg(e.message));
  }, []);

  const visible = rows.filter((r) => {
    if (!filter) return true;
    const f = filter.toLowerCase();
    return (
      r.subscription?.name?.toLowerCase().includes(f) ||
      r.subscription?.id?.toLowerCase().includes(f)
    );
  });

  return (
    <div>
      <div className="toolbar">
        <button
          onClick={async () => {
            setMsg("Refreshing Azure…");
            await api("/azure/refresh", { method: "POST", body: "{}" });
            await load();
            setMsg("Scope refreshed");
          }}
        >
          Refresh Azure discovery
        </button>
        <input
          placeholder="Search name or paste subscription ID"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <button
          className="secondary"
          onClick={async () => {
            const body = {
              name_contains: filter || "MSDN",
              offer_mapping: "MSDN",
            };
            const p = await api("/scope/exclusion-preview", {
              method: "POST",
              body: JSON.stringify(body),
            });
            setPreview(p);
          }}
        >
          Preview exclusion
        </button>
        <button
          className="secondary"
          onClick={async () => {
            await api("/scope/exclusion-rules", {
              method: "POST",
              body: JSON.stringify({
                id: "",
                name: `Exclude ${filter || "MSDN"}`,
                tenant_id: null,
                filter: {
                  name_contains: filter || "MSDN",
                  offer_mapping: "MSDN",
                },
                enabled: true,
                created_at: new Date().toISOString(),
              }),
            });
            await load();
            setMsg("Exclusion rule saved");
          }}
        >
          Save exclusion rule
        </button>
      </div>
      {msg && <div className="muted">{msg}</div>}
      {preview && (
        <div className="panel">
          Matches: {preview.match_count}. Samples:{" "}
          {(preview.sample_names || []).join(", ")}
        </div>
      )}
      <table>
        <thead>
          <tr>
            <th>Subscription</th>
            <th>Tenant</th>
            <th>State</th>
            <th>Effective decision</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {visible.map((r) => (
            <tr key={r.subscription.id}>
              <td>
                <div>{r.subscription.name}</div>
                <div className="muted">{r.subscription.id}</div>
              </td>
              <td className="muted">{r.subscription.tenant_id}</td>
              <td>{r.subscription.state}</td>
              <td>
                <span className={`badge ${r.decision}`}>{r.decision}</span>
                <div className="muted">
                  {r.source}: {r.reason}
                </div>
              </td>
              <td>
                <button
                  onClick={async () => {
                    await api("/scope/decision", {
                      method: "POST",
                      body: JSON.stringify({
                        tenant_id: r.subscription.tenant_id,
                        subscription_id: r.subscription.id,
                        decision: "track",
                        reason: "explicit track",
                      }),
                    });
                    await load();
                  }}
                >
                  Track
                </button>{" "}
                <button
                  className="secondary"
                  onClick={async () => {
                    await api("/scope/decision", {
                      method: "POST",
                      body: JSON.stringify({
                        tenant_id: r.subscription.tenant_id,
                        subscription_id: r.subscription.id,
                        decision: "exclude",
                        reason: "explicit exclude",
                      }),
                    });
                    await load();
                  }}
                >
                  Exclude
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}