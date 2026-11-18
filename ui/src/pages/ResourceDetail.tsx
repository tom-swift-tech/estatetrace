import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { api } from "../api";

export default function ResourceDetail() {
  const loc = useLocation();
  const id = decodeURIComponent(loc.pathname.replace(/^\/resources\//, ""));
  const [data, setData] = useState<any>(null);

  useEffect(() => {
    api(`/resources/${encodeURIComponent(id)}/timeline`).then(setData);
  }, [id]);

  if (!data) return <div>Loading…</div>;

  return (
    <div>
      <h2>{data.resource?.name || id}</h2>
      <div className="muted">{id}</div>
      <div className="panel">
        <strong>Timeline</strong>
        {(data.changes || []).map((c: any) => (
          <div key={c.id} style={{ marginTop: "0.75rem" }}>
            <div>
              <span className="badge">{c.label}</span>{" "}
              event {c.times?.event_time || "—"} · observed{" "}
              {c.times?.observation_time}
            </div>
            <div className="pre">
              {JSON.stringify(
                { before: c.before, after: c.after, diffs: c.property_diffs },
                null,
                2,
              )}
            </div>
          </div>
        ))}
      </div>
      <div className="panel">
        <strong>Evaluations</strong>
        {(data.evaluations || []).map((e: any) => (
          <div key={e.id}>
            {e.control_id}@{e.control_revision}:{" "}
            <span className={`badge ${e.outcome}`}>{e.outcome}</span>
          </div>
        ))}
      </div>
      <div className="panel">
        <strong>Tickets</strong>
        <div className="pre">{JSON.stringify(data.tickets || [], null, 2)}</div>
      </div>
      <button
        onClick={async () => {
          const res = await fetch("/api/evidence/export", {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "x-session-token": (await api<{ token: string }>("/session")).token,
            },
            body: JSON.stringify({ resource_id: id }),
          });
          const blob = await res.blob();
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