import { useEffect, useState } from "react";
import { api, ComplianceSummary } from "../api";

export default function Compliance() {
  const [data, setData] = useState<ComplianceSummary | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<ComplianceSummary>("/compliance")
      .then(setData)
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : String(e)),
      );
  }, []);

  if (error) return <div className="panel">{error}</div>;
  if (!data) return <div className="muted">Loading compliance…</div>;

  return (
    <div className="grid-3">
      <div className="panel">
        <div className="muted">Passing</div>
        <div className="stat" style={{ color: "var(--et-pass)" }}>
          {data.passing}
        </div>
      </div>
      <div className="panel">
        <div className="muted">Failing</div>
        <div className="stat" style={{ color: "var(--et-fail)" }}>
          {data.failing}
        </div>
      </div>
      <div className="panel">
        <div className="muted">Unknown / inapplicable</div>
        <div className="stat">
          {data.unknown} / {data.inapplicable}
        </div>
      </div>
      <div className="panel">
        <div className="muted">Pending remediation (actionable)</div>
        <div className="stat">{data.pending_remediation}</div>
      </div>
      <div className="panel">
        <div className="muted">Awaiting grace</div>
        <div className="stat">{data.awaiting_grace ?? 0}</div>
      </div>
      <div className="panel">
        <div className="muted">Verified corrected</div>
        <div className="stat">{data.verified_corrected ?? 0}</div>
      </div>
      <div className="panel">
        <div className="muted">Active exceptions</div>
        <div className="stat">{data.exceptions}</div>
      </div>
      <div className="panel">
        <div className="muted">Freshness</div>
        <div>{data.freshness}</div>
      </div>
    </div>
  );
}
