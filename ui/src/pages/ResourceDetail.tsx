import { FormEvent, useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { api, apiBlob, ResourceTimeline, TimelineChange } from "../api";

function DiffTable({ change }: { change: TimelineChange }) {
  const diffs = change.property_diffs || {};
  const keys = Object.keys(diffs);
  if (!keys.length) {
    return (
      <div className="pre">
        {JSON.stringify(
          { before: change.before, after: change.after },
          null,
          2,
        )}
      </div>
    );
  }
  return (
    <table>
      <thead>
        <tr>
          <th>Property</th>
          <th>Before</th>
          <th>After</th>
        </tr>
      </thead>
      <tbody>
        {keys.map((k) => (
          <tr key={k}>
            <td>{k}</td>
            <td className="pre">
              {JSON.stringify(diffs[k]?.before ?? null, null, 2)}
            </td>
            <td className="pre">
              {JSON.stringify(diffs[k]?.after ?? null, null, 2)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function ResourceDetail() {
  const loc = useLocation();
  const id = decodeURIComponent(loc.pathname.replace(/^\/resources\//, ""));
  const [data, setData] = useState<ResourceTimeline | null>(null);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");

  const [disp, setDisp] = useState({
    evaluation_id: "",
    owner: "",
    disposition: "investigating",
    ticket_ref: "",
  });
  const [ex, setEx] = useState({
    control_id: "",
    reason: "",
    approved_by: "",
    expires_at: "",
  });

  async function load() {
    try {
      const d = await api<ResourceTimeline>(
        `/resources/${encodeURIComponent(id)}/timeline`,
      );
      setData(d);
      const firstEval = d.evaluations?.[0];
      if (firstEval) {
        setDisp((s) => ({ ...s, evaluation_id: firstEval.id }));
        setEx((s) => ({ ...s, control_id: firstEval.control_id }));
      }
      setError("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  useEffect(() => {
    load();
  }, [id]);

  async function submitDisposition(e: FormEvent) {
    e.preventDefault();
    await api("/dispositions", {
      method: "POST",
      body: JSON.stringify({
        evaluation_id: disp.evaluation_id,
        owner: disp.owner || null,
        disposition: disp.disposition,
        ticket_ref: disp.ticket_ref || null,
      }),
    });
    setMsg("Disposition saved");
    await load();
  }

  async function submitException(e: FormEvent) {
    e.preventDefault();
    await api("/exceptions", {
      method: "POST",
      body: JSON.stringify({
        resource_id: id,
        control_id: ex.control_id,
        reason: ex.reason || null,
        approved_by: ex.approved_by || null,
        expires_at: ex.expires_at || null,
      }),
    });
    setMsg("Exception saved");
    await load();
  }

  if (error) return <div className="panel">{error}</div>;
  if (!data) return <div>Loading…</div>;

  return (
    <div>
      <h2>{data.resource?.name || id}</h2>
      <div className="muted">{id}</div>
      {data.triage && (
        <div style={{ margin: "0.75rem 0" }}>
          <span className={`badge ${data.triage.state}`}>
            {data.triage.state}
          </span>{" "}
          <span className="muted">{data.triage.reason}</span>
        </div>
      )}
      {msg && <div className="muted">{msg}</div>}

      <div className="panel">
        <strong>Timeline</strong>
        {(data.changes || []).map((c) => (
          <div key={c.id} style={{ marginTop: "0.75rem" }}>
            <div>
              <span className="badge">{c.label}</span> event{" "}
              {c.times?.event_time || "—"} · observed{" "}
              {c.times?.observation_time}
            </div>
            <DiffTable change={c} />
          </div>
        ))}
        {!data.changes?.length && (
          <div className="muted">No changes recorded.</div>
        )}
      </div>

      <div className="panel">
        <strong>Evaluations</strong>
        {(data.evaluations || []).map((e) => (
          <div key={e.id} style={{ marginTop: "0.5rem" }}>
            {e.control_id}@{e.control_revision}:{" "}
            <span className={`badge ${e.outcome}`}>{e.outcome}</span>
            <button
              className="secondary"
              style={{ marginLeft: "0.5rem" }}
              onClick={() =>
                setDisp((s) => ({
                  ...s,
                  evaluation_id: e.id,
                }))
              }
            >
              Dispose
            </button>
          </div>
        ))}
      </div>

      <div className="panel">
        <strong>Record disposition</strong>
        <form onSubmit={submitDisposition}>
          <label>Evaluation ID</label>
          <input
            value={disp.evaluation_id}
            onChange={(e) =>
              setDisp({ ...disp, evaluation_id: e.target.value })
            }
            required
          />
          <label>Owner</label>
          <input
            value={disp.owner}
            onChange={(e) => setDisp({ ...disp, owner: e.target.value })}
          />
          <label>Disposition</label>
          <select
            value={disp.disposition}
            onChange={(e) =>
              setDisp({ ...disp, disposition: e.target.value })
            }
          >
            <option value="investigating">Investigating</option>
            <option value="accepted_risk">Accepted risk</option>
            <option value="remediating">Remediating</option>
            <option value="resolved">Resolved</option>
          </select>
          <label>Ticket ref</label>
          <input
            value={disp.ticket_ref}
            onChange={(e) =>
              setDisp({ ...disp, ticket_ref: e.target.value })
            }
          />
          <div className="toolbar">
            <button type="submit">Save disposition</button>
          </div>
        </form>
        {(data.dispositions || []).map((d) => (
          <div key={d.id} className="muted">
            {d.disposition}
            {d.owner ? ` · ${d.owner}` : ""}
            {d.ticket_ref ? ` · ${d.ticket_ref}` : ""}
          </div>
        ))}
      </div>

      <div className="panel">
        <strong>Approve exception</strong>
        <form onSubmit={submitException}>
          <label>Control ID</label>
          <input
            value={ex.control_id}
            onChange={(e) => setEx({ ...ex, control_id: e.target.value })}
            required
          />
          <label>Reason</label>
          <input
            value={ex.reason}
            onChange={(e) => setEx({ ...ex, reason: e.target.value })}
          />
          <label>Approved by</label>
          <input
            value={ex.approved_by}
            onChange={(e) => setEx({ ...ex, approved_by: e.target.value })}
          />
          <label>Expires at (RFC3339)</label>
          <input
            placeholder="2027-01-01T00:00:00Z"
            value={ex.expires_at}
            onChange={(e) => setEx({ ...ex, expires_at: e.target.value })}
          />
          <div className="toolbar">
            <button type="submit">Save exception</button>
          </div>
        </form>
        {(data.exceptions || []).map((x) => (
          <div key={x.id} className="muted">
            {x.control_id}: {x.reason || "—"}
            {x.expires_at ? ` · expires ${x.expires_at}` : " · no expiry"}
          </div>
        ))}
      </div>

      <div className="panel">
        <strong>Tickets</strong>
        {(data.tickets || []).length ? (
          <div className="pre">{JSON.stringify(data.tickets, null, 2)}</div>
        ) : (
          <div className="muted">No ticket relationships.</div>
        )}
      </div>

      <button
        onClick={async () => {
          const blob = await apiBlob("/evidence/export", {
            method: "POST",
            body: JSON.stringify({ resource_id: id }),
          });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = "evidence.json";
          a.click();
        }}
      >
        Export evidence
      </button>
    </div>
  );
}
