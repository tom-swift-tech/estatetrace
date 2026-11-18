import { useEffect, useState } from "react";
import { api } from "../api";

export default function Operations() {
  const [queues, setQueues] = useState<any>(null);
  const [incidentDetail, setIncidentDetail] = useState<any>(null);
  const [error, setError] = useState("");

  async function load() {
    try {
      const q = await api("/connectors/servicenow/queues");
      setQueues(q);
      setError("");
    } catch (e: any) {
      setError(e.message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  function QueueTable({
    title,
    rows,
  }: {
    title: string;
    rows: any[];
  }) {
    return (
      <div className="panel">
        <strong>
          {title} ({rows?.length || 0})
        </strong>
        <table>
          <thead>
            <tr>
              <th>Number</th>
              <th>Summary</th>
              <th>State</th>
              <th>When</th>
            </tr>
          </thead>
          <tbody>
            {(rows || []).slice(0, 8).map((r) => (
              <tr key={r.sys_id}>
                <td>
                  <a href={r.link} target="_blank" rel="noreferrer">
                    {r.number}
                  </a>
                </td>
                <td>{r.short_description}</td>
                <td>
                  {r.priority ? `P${r.priority} ` : ""}
                  {r.state}
                </td>
                <td className="muted">
                  {r.actual_end || r.planned_start || r.opened_at}
                  {title.includes("incident") && (
                    <div>
                      <button
                        className="secondary"
                        onClick={async () => {
                          const d = await api(
                            `/connectors/servicenow/incidents/${r.sys_id}/changes-before`,
                          );
                          setIncidentDetail(d);
                        }}
                      >
                        Changes before incident
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div>
      <div className="toolbar">
        <button
          onClick={async () => {
            try {
              const q = await api("/connectors/servicenow/queues", {
                method: "POST",
                body: "{}",
              });
              setQueues(q);
            } catch (e: any) {
              setError(
                "ServiceNow disconnected or unavailable. Core dashboard still works.",
              );
            }
          }}
        >
          Refresh queues
        </button>
        <span className="muted">
          TZ: {queues?.timezone || "local"} · connector optional
        </span>
      </div>
      {error && <div className="panel">{error}</div>}
      <QueueTable title="Changes executed (48h)" rows={queues?.executed} />
      <QueueTable title="Changes scheduled today" rows={queues?.scheduled_today} />
      <QueueTable
        title="Ongoing high-priority incidents"
        rows={queues?.high_priority_incidents}
      />
      {incidentDetail && (
        <div className="panel">
          <strong>Changes before incident</strong>
          <div className="pre">{JSON.stringify(incidentDetail, null, 2)}</div>
        </div>
      )}
    </div>
  );
}