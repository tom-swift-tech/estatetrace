import { FormEvent, useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import {
  api,
  apiBlob,
  CLOSE_REASON_LABELS,
  createException,
  ExceptionRecord,
  FindingInterval,
  isStale,
  ResourceTimeline,
  TimelineChange,
  TriageInfo,
} from "../api";

type ExceptionScope = "resource" | "resource_group" | "subscription";

/** Subscription and resource group from an ARM ID (case-insensitive segment names). */
function armScope(resourceId: string): { sub: string; rg: string } {
  const segs = resourceId.split("/").filter(Boolean);
  if (segs.length < 2 || segs[0].toLowerCase() !== "subscriptions") {
    return { sub: "", rg: "" };
  }
  const rg =
    segs.length >= 4 && segs[2].toLowerCase() === "resourcegroups"
      ? segs[3]
      : "";
  return { sub: segs[1], rg };
}

function describeScope(x: ExceptionRecord): string {
  if (x.resource_id) return "this resource";
  if (x.resource_group) return `resource group ${x.resource_group}`;
  return `subscription ${x.subscription_id}`;
}

function isExpired(x: ExceptionRecord): boolean {
  return !!x.expires_at && new Date(x.expires_at).getTime() < Date.now();
}

/** One interval: "fail since <opened_at> (rev 3)", plus the close reason when closed. */
function FindingRow({
  f,
  triage,
  lastScanAt,
  onDispose,
}: {
  f: FindingInterval;
  triage: TriageInfo | null;
  lastScanAt?: string | null;
  onDispose: (f: FindingInterval) => void;
}) {
  const open = !f.closed_at;
  return (
    <div style={{ marginTop: "0.4rem" }} className={open ? "" : "muted"}>
      <span className={`badge ${f.outcome}`}>{f.outcome}</span> since{" "}
      {f.opened_at}{" "}
      <span className="muted">
        (rev {f.pack_revision}
        {f.clause_revision && f.clause_revision !== f.pack_revision
          ? `, clause ${f.clause_revision}`
          : ""}
        )
      </span>
      {open ? (
        <>
          {triage && (
            <>
              {" "}
              <span className={`badge ${triage.state}`}>{triage.state}</span>{" "}
              <span className="muted">{triage.reason}</span>
            </>
          )}
          {isStale(f, lastScanAt) && (
            <span
              className="badge stale"
              title="Not re-evaluated by the last scan (for example a partial scan)"
            >
              stale: last evaluated {f.last_evaluated_at}
            </span>
          )}
          <button
            className="secondary"
            style={{ marginLeft: "0.5rem" }}
            onClick={() => onDispose(f)}
          >
            Dispose
          </button>
        </>
      ) : (
        <>
          {" "}
          until {f.closed_at}{" "}
          <span className="badge closed">
            {f.close_reason
              ? CLOSE_REASON_LABELS[f.close_reason] ?? f.close_reason
              : "closed"}
          </span>
        </>
      )}
      {f.detail && <div className="muted">{f.detail}</div>}
    </div>
  );
}

/** Intervals grouped by pack and control, newest first (server order). */
function groupFindings(
  findings: FindingInterval[],
  triage: Array<TriageInfo | null>,
): [string, Array<[FindingInterval, TriageInfo | null]>][] {
  const groups = new Map<string, Array<[FindingInterval, TriageInfo | null]>>();
  findings.forEach((f, i) => {
    const key = `${f.control_id} · ${f.pack_id}`;
    const list = groups.get(key) ?? [];
    list.push([f, triage[i] ?? null]);
    groups.set(key, list);
  });
  return [...groups.entries()];
}

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
    scope: "resource" as ExceptionScope,
    reason: "",
    approved_by: "",
    ticket_ref: "",
    expires_at: "",
  });
  const scopeIds = armScope(id);

  async function load() {
    try {
      const d = await api<ResourceTimeline>(
        `/resources/${encodeURIComponent(id)}/timeline`,
      );
      setData(d);
      // Default to the first open finding (most recent interval of the first control).
      const firstOpen = (d.findings || []).find((f) => !f.closed_at);
      if (firstOpen) {
        setDisp((s) => ({ ...s, evaluation_id: firstOpen.id }));
        setEx((s) => ({ ...s, control_id: firstOpen.control_id }));
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
    try {
      const res = await createException({
        control_id: ex.control_id,
        resource_id: ex.scope === "resource" ? id : null,
        subscription_id: ex.scope === "resource" ? null : scopeIds.sub,
        resource_group: ex.scope === "resource_group" ? scopeIds.rg : null,
        reason: ex.reason || null,
        approved_by: ex.approved_by || null,
        ticket_ref: ex.ticket_ref || null,
        expires_at: ex.expires_at || null,
      });
      setMsg(
        res.expired
          ? "Exception saved, but its expiry is in the past so it does not apply"
          : "Exception saved",
      );
    } catch (err: unknown) {
      setMsg(
        `Exception not saved: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
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
          {data.triage.exception_expired && (
            <span className="muted"> · exception expired</span>
          )}
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
        <strong>Findings</strong>
        <div className="muted">
          Each line is one interval of a control's outcome. Re-evaluations with
          the same outcome extend it; a change, a pack revision or the resource
          leaving scope closes it.
          {data.last_scan_at ? ` Last scan started ${data.last_scan_at}.` : ""}
        </div>
        {groupFindings(data.findings || [], data.findings_triage || []).map(
          ([key, items]) => (
            <div key={key} style={{ marginTop: "0.75rem" }}>
              <div>
                <strong>{key}</strong>
              </div>
              {items.map(([f, t]) => (
                <FindingRow
                  key={f.id}
                  f={f}
                  triage={t}
                  lastScanAt={data.last_scan_at}
                  onDispose={(x) => {
                    setDisp((s) => ({ ...s, evaluation_id: x.id }));
                    setEx((s) => ({ ...s, control_id: x.control_id }));
                  }}
                />
              ))}
            </div>
          ),
        )}
        {!data.findings?.length && (
          <div className="muted">No findings recorded for this resource.</div>
        )}
      </div>

      <div className="panel">
        <strong>Record disposition</strong>
        <form onSubmit={submitDisposition}>
          <label>Finding ID</label>
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
          <label>Scope</label>
          <select
            value={ex.scope}
            onChange={(e) =>
              setEx({ ...ex, scope: e.target.value as ExceptionScope })
            }
          >
            <option value="resource">This resource only</option>
            <option value="resource_group" disabled={!scopeIds.rg}>
              Resource group {scopeIds.rg || "(none)"}
            </option>
            <option value="subscription" disabled={!scopeIds.sub}>
              Subscription {scopeIds.sub || "(none)"}
            </option>
          </select>
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
          <label>Ticket ref</label>
          <input
            value={ex.ticket_ref}
            onChange={(e) => setEx({ ...ex, ticket_ref: e.target.value })}
          />
          <label>Expires on (end of day, UTC; blank for no expiry)</label>
          <input
            type="date"
            value={ex.expires_at}
            onChange={(e) => setEx({ ...ex, expires_at: e.target.value })}
          />
          <div className="toolbar">
            <button type="submit">Save exception</button>
          </div>
        </form>
        {(data.exceptions || []).map((x) => (
          <div key={x.id} className="muted">
            {x.control_id} · {describeScope(x)}: {x.reason || "—"}
            {x.ticket_ref ? ` · ${x.ticket_ref}` : ""}
            {x.expires_at ? ` · expires ${x.expires_at}` : " · no expiry"}
            {isExpired(x) ? " · expired" : ""}
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
