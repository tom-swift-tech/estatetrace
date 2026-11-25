import { useEffect, useState } from "react";
import { api } from "../api";

export default function Scope() {
  const [rows, setRows] = useState<any[]>([]);
  const [filter, setFilter] = useState("");
  const [preview, setPreview] = useState<any>(null);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState("");

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

  async function refreshAzure() {
    setBusy("refresh");
    setMsg("Refreshing Azure subscriptions…");
    try {
      const result = await api<{ tenants: number; subscriptions: number }>(
        "/azure/refresh",
        {
          method: "POST",
          body: "{}",
        }
      );
      await load();
      setMsg(
        `Found ${result.subscriptions} subscription(s) across ${result.tenants} tenant(s).`
      );
    } catch (e: unknown) {
      setMsg(
        `Azure discovery failed: ${
          e instanceof Error ? e.message : String(e)
        }`
      );
    } finally {
      setBusy("");
    }
  }

  async function setSubscriptionDecision(
    row: any,
    decision: "track" | "exclude"
  ) {
    setBusy(`${decision}:${row.subscription.id}`);
    setMsg(`${decision === "track" ? "Tracking" : "Excluding"} ${row.subscription.name}…`);
    try {
      await api("/scope/decision", {
        method: "POST",
        body: JSON.stringify({
          tenant_id: row.subscription.tenant_id,
          subscription_id: row.subscription.id,
          decision,
          reason: `explicit ${decision}`,
        }),
      });
      await load();
      setMsg(
        `${row.subscription.name} is now ${decision === "track" ? "tracked" : "excluded"}.`
      );
    } catch (e: unknown) {
      setMsg(
        `Could not ${decision} ${row.subscription.name}: ${
          e instanceof Error ? e.message : String(e)
        }`
      );
    } finally {
      setBusy("");
    }
  }

  return (
    <div>
      <div className="toolbar">
        <button onClick={refreshAzure} disabled={busy === "refresh"}>
          {busy === "refresh" ? "Refreshing…" : "Refresh Azure discovery"}
        </button>
        <input
          placeholder="Search name or paste subscription ID"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <button
          className="secondary"
          disabled={busy !== ""}
          onClick={async () => {
            setBusy("preview");
            setMsg("Previewing exclusion matches…");
            try {
              const body = {
                name_contains: filter || "MSDN",
                offer_mapping: "MSDN",
              };
              const p = await api<{ match_count: number }>("/scope/exclusion-preview", {
                method: "POST",
                body: JSON.stringify(body),
              });
              setPreview(p);
              setMsg(`Preview complete: ${p.match_count} match(es).`);
            } catch (e: unknown) {
              setMsg(`Preview failed: ${e instanceof Error ? e.message : String(e)}`);
            } finally {
              setBusy("");
            }
          }}
        >
          {busy === "preview" ? "Previewing…" : "Preview exclusion"}
        </button>
        <button
          className="secondary"
          disabled={busy !== ""}
          onClick={async () => {
            setBusy("save-rule");
            setMsg("Saving exclusion rule…");
            try {
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
              setMsg("Exclusion rule saved.");
            } catch (e: unknown) {
              setMsg(`Could not save exclusion rule: ${e instanceof Error ? e.message : String(e)}`);
            } finally {
              setBusy("");
            }
          }}
        >
          {busy === "save-rule" ? "Saving…" : "Save exclusion rule"}
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
                    setSubscriptionDecision(r, "track");
                  }}
                  disabled={busy.startsWith("track:")}
                >
                  {busy.startsWith("track:") ? "Tracking…" : "Track"}
                </button>{" "}
                <button
                  className="secondary"
                  onClick={async () => {
                    setSubscriptionDecision(r, "exclude");
                  }}
                  disabled={busy.startsWith("exclude:")}
                >
                  {busy.startsWith("exclude:") ? "Excluding…" : "Exclude"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}