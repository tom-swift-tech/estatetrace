import { useEffect, useState } from "react";
import { api } from "../api";

export default function Compliance() {
  const [data, setData] = useState<any>(null);
  useEffect(() => {
    api("/compliance").then(setData);
  }, []);
  if (!data) return null;
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
        <div className="muted">Pending remediation</div>
        <div className="stat">{data.pending_remediation}</div>
      </div>
      <div className="panel">
        <div className="muted">Freshness</div>
        <div>{data.freshness}</div>
      </div>
    </div>
  );
}