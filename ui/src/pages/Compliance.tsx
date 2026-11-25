import { useEffect, useState } from "react";
import { api, ComplianceSummary, CoverageGap, GapCategory } from "../api";

const GAP_LABELS: Record<GapCategory, string> = {
  outside_azure: "Evidence outside Azure",
  more_collection: "Needs more collection",
  deep_collection: "Needs per-resource (deep) collection",
  needs_decision: "Needs an owner decision",
  by_construction: "True by construction",
};

const GAP_ORDER: GapCategory[] = [
  "outside_azure",
  "more_collection",
  "deep_collection",
  "needs_decision",
  "by_construction",
];

function groupGaps(gaps: CoverageGap[]): [GapCategory, CoverageGap[]][] {
  const by = new Map<GapCategory, CoverageGap[]>();
  for (const g of gaps) {
    const list = by.get(g.category) ?? [];
    list.push(g);
    by.set(g.category, list);
  }
  const known = GAP_ORDER.filter((c) => by.has(c)).map(
    (c) => [c, by.get(c)!] as [GapCategory, CoverageGap[]],
  );
  const other = [...by.entries()].filter(([c]) => !GAP_ORDER.includes(c));
  return [...known, ...other];
}

function NotEvaluated({ data }: { data: ComplianceSummary }) {
  const gaps = data.coverage_gaps ?? [];
  const total = data.controls_total ?? 0;
  const evaluated = data.controls_evaluated ?? 0;
  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <h3 style={{ marginTop: 0 }}>Not evaluated</h3>
      <div className="muted">
        {evaluated} of {total} active controls are checked per resource. The
        rest are listed here with the reason, not counted as passing.
      </div>
      {gaps.length === 0 ? (
        <div className="muted" style={{ marginTop: 8 }}>
          {total > evaluated
            ? "Coverage gaps appear after the next scan."
            : "Every active control is evaluated."}
        </div>
      ) : (
        groupGaps(gaps).map(([category, rows]) => (
          <div key={category} style={{ marginTop: 12 }}>
            <div>
              <strong>{GAP_LABELS[category] ?? category}</strong>{" "}
              <span className="muted">({rows.length})</span>
            </div>
            <table>
              <thead>
                <tr>
                  <th>Control</th>
                  <th>Pack</th>
                  <th>Resource type</th>
                  <th>Resources</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((g) => (
                  <tr key={`${g.pack_id}|${g.control_id}|${g.resource_type ?? ""}`}>
                    <td>{g.control_id}</td>
                    <td>{g.pack_id}</td>
                    <td>{g.resource_type ?? "—"}</td>
                    <td>{g.resource_type ? g.resource_count : "—"}</td>
                    <td>{g.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))
      )}
    </div>
  );
}

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
    <div>
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
          <div className="muted">Controls evaluated</div>
          <div className="stat">
            {data.controls_evaluated ?? 0} / {data.controls_total ?? 0}
          </div>
        </div>
        <div className="panel">
          <div className="muted">Last scan</div>
          <div>{data.last_scan_at ?? "never"}</div>
          {(data.stale ?? 0) > 0 && (
            <div className="muted">
              <span className="badge stale">{data.stale} stale</span> open
              findings were not re-evaluated by the last scan
            </div>
          )}
        </div>
      </div>
      <NotEvaluated data={data} />
    </div>
  );
}
