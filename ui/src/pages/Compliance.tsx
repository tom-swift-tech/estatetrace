import { useEffect, useState } from "react";
import {
  api,
  AgingBucket,
  AgingRow,
  complianceAging,
  complianceFlow,
  complianceQueue,
  complianceTrend,
  ComplianceSummary,
  CoverageGap,
  exportReadout,
  FlowRow,
  GapCategory,
  QueueGroupBy,
  QueueRow,
  TrendRow,
} from "../api";

type Lane = "security" | "hygiene";

const LANE_LABELS: Record<Lane, string> = {
  security: "Security",
  hygiene: "Hygiene",
};

const BUCKETS: AgingBucket[] = ["0-7", "8-30", "31-90", "90+"];

const GROUP_LABELS: Record<QueueGroupBy, string> = {
  application: "Application",
  owner: "Owner",
  subscription: "Subscription",
  line_of_business: "Line of business",
};

/** A horizontal bar scaled to `max`, in a compliance status colour. */
function Bar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.max(2, Math.round((value / max) * 100)) : 0;
  return (
    <div style={{ background: "#edf2f7", height: 8, borderRadius: 2, minWidth: 80 }}>
      {value > 0 && (
        <div style={{ width: `${pct}%`, height: 8, borderRadius: 2, background: color }} />
      )}
    </div>
  );
}

function QueuePanel({ lane }: { lane: Lane }) {
  const [groupBy, setGroupBy] = useState<QueueGroupBy | "">("");
  const [rows, setRows] = useState<QueueRow[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setRows(null);
    complianceQueue(lane, groupBy)
      .then((d) => {
        setRows(d.rows);
        setError("");
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  }, [lane, groupBy]);

  const max = Math.max(0, ...(rows ?? []).map((r) => r.count));
  return (
    <div className="panel">
      <div className="toolbar" style={{ justifyContent: "space-between" }}>
        <h3 style={{ margin: 0 }}>Remediation queue · {LANE_LABELS[lane]}</h3>
        <label style={{ margin: 0 }}>
          Group by
          <select
            value={groupBy}
            onChange={(e) => setGroupBy(e.target.value as QueueGroupBy | "")}
          >
            <option value="">None</option>
            {(Object.keys(GROUP_LABELS) as QueueGroupBy[]).map((g) => (
              <option key={g} value={g}>
                {GROUP_LABELS[g]}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="muted" style={{ marginBottom: 8 }}>
        Open failing findings by control and environment, largest first.
        {lane === "security"
          ? " Tag and metadata hygiene controls are on the Hygiene tab."
          : " Hygiene controls are kept apart so they do not crowd out security work."}
      </div>
      {error && <div className="badge fail">{error}</div>}
      {!rows ? (
        <div className="muted">Loading queue…</div>
      ) : rows.length === 0 ? (
        <div className="muted">No open failing findings in this lane.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Control</th>
              {groupBy && <th>{GROUP_LABELS[groupBy]}</th>}
              <th>Environment</th>
              <th>Open</th>
              <th style={{ width: "25%" }}></th>
              <th>Subscriptions</th>
              <th>Oldest</th>
              <th>New since last visit</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.control_id}|${r.group_key}|${r.environment}`}>
                <td>{r.control_id}</td>
                {groupBy && <td>{r.group_key || <span className="muted">unassigned</span>}</td>}
                <td>
                  <span className={`badge ${r.environment}`}>{r.environment}</span>
                </td>
                <td>
                  <span className="badge fail">{r.count}</span>
                </td>
                <td>
                  <Bar value={r.count} max={max} color="var(--et-fail)" />
                </td>
                <td>{r.subscriptions}</td>
                <td>{r.oldest_opened_at.slice(0, 10)}</td>
                <td>
                  {r.new_since_last_visit > 0 ? (
                    <span className="badge since">{r.new_since_last_visit} new</span>
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function AgingPanel({ lane }: { lane: Lane }) {
  const [rows, setRows] = useState<AgingRow[] | null>(null);
  useEffect(() => {
    setRows(null);
    complianceAging(lane)
      .then((d) => setRows(d.rows))
      .catch(() => setRows([]));
  }, [lane]);

  const byControl = new Map<string, Record<string, number>>();
  for (const r of rows ?? []) {
    const m = byControl.get(r.control_id) ?? {};
    m[r.bucket] = (m[r.bucket] ?? 0) + r.count;
    byControl.set(r.control_id, m);
  }
  const totals = BUCKETS.map((b) =>
    (rows ?? []).filter((r) => r.bucket === b).reduce((n, r) => n + r.count, 0),
  );
  const max = Math.max(0, ...totals);
  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Aging · {LANE_LABELS[lane]}</h3>
      <div className="muted" style={{ marginBottom: 8 }}>
        Days since each open failing finding was first seen.
      </div>
      {!rows ? (
        <div className="muted">Loading…</div>
      ) : rows.length === 0 ? (
        <div className="muted">Nothing open.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Control</th>
              {BUCKETS.map((b) => (
                <th key={b}>{b} days</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[...byControl.entries()].map(([control, m]) => (
              <tr key={control}>
                <td>{control}</td>
                {BUCKETS.map((b) => (
                  <td key={b}>{m[b] ?? "—"}</td>
                ))}
              </tr>
            ))}
            <tr>
              <th>All controls</th>
              {totals.map((n, i) => (
                <th key={BUCKETS[i]}>
                  {n}
                  <Bar
                    value={n}
                    max={max}
                    color={i === 0 ? "var(--et-unknown)" : "var(--et-fail)"}
                  />
                </th>
              ))}
            </tr>
          </tbody>
        </table>
      )}
    </div>
  );
}

function FlowPanel({ lane }: { lane: Lane }) {
  const [rows, setRows] = useState<FlowRow[] | null>(null);
  const [trend, setTrend] = useState<{ started_at: string; open: number }[]>([]);
  useEffect(() => {
    setRows(null);
    complianceFlow(lane, 90)
      .then((d) => setRows(d.rows))
      .catch(() => setRows([]));
    complianceTrend(lane)
      .then((d) => {
        const open = new Map<string, number>();
        for (const r of d.rows as TrendRow[]) {
          open.set(r.scan_id, (open.get(r.scan_id) ?? 0) + r.open);
        }
        setTrend(d.scans.map((s) => ({ started_at: s.started_at, open: open.get(s.scan_id) ?? 0 })));
      })
      .catch(() => setTrend([]));
  }, [lane]);

  // Daily totals across controls, newest first.
  const days = new Map<string, { opened: number; closed: number }>();
  for (const r of rows ?? []) {
    const d = days.get(r.day) ?? { opened: 0, closed: 0 };
    d.opened += r.opened;
    d.closed += r.closed;
    days.set(r.day, d);
  }
  const daily = [...days.entries()].sort((a, b) => b[0].localeCompare(a[0]));
  const max = Math.max(0, ...daily.map(([, d]) => Math.max(d.opened, d.closed)));
  const trendMax = Math.max(0, ...trend.map((t) => t.open));
  const opened = daily.reduce((n, [, d]) => n + d.opened, 0);
  const closed = daily.reduce((n, [, d]) => n + d.closed, 0);
  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Flow · {LANE_LABELS[lane]}</h3>
      <div className="muted" style={{ marginBottom: 8 }}>
        Failing findings opened and closed per day over the last 90 days:{" "}
        <span style={{ color: "var(--et-fail)" }}>{opened} opened</span>,{" "}
        <span style={{ color: "var(--et-pass)" }}>{closed} closed</span>.
      </div>
      {!rows ? (
        <div className="muted">Loading…</div>
      ) : daily.length === 0 ? (
        <div className="muted">No failing findings opened or closed in the window.</div>
      ) : (
        <div style={{ maxHeight: 320, overflow: "auto" }}>
          <table>
            <thead>
              <tr>
                <th>Day (UTC)</th>
                <th>Opened</th>
                <th>Closed</th>
              </tr>
            </thead>
            <tbody>
              {daily.map(([day, d]) => (
                <tr key={day}>
                  <td>{day}</td>
                  <td>
                    {d.opened}
                    <Bar value={d.opened} max={max} color="var(--et-fail)" />
                  </td>
                  <td>
                    {d.closed}
                    <Bar value={d.closed} max={max} color="var(--et-pass)" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {trend.length > 0 && (
        <>
          <h4>Open failing findings at each recent scan</h4>
          <table>
            <tbody>
              {trend.map((t) => (
                <tr key={t.started_at}>
                  <td style={{ width: "30%" }}>{t.started_at.slice(0, 16).replace("T", " ")}</td>
                  <td style={{ width: "10%" }}>{t.open}</td>
                  <td>
                    <Bar value={t.open} max={trendMax} color="var(--et-fail)" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

/** Security-first remediation view (AC-P6-1): Security is the default tab, Hygiene is separate. */
function Remediation() {
  const [lane, setLane] = useState<Lane>("security");
  const [exportMsg, setExportMsg] = useState("");

  async function downloadReadout() {
    try {
      const blob = await exportReadout();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `estatetrace-readout-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setExportMsg("Readout downloaded (aggregates only, no resource IDs).");
    } catch (e: unknown) {
      setExportMsg(`Readout export failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  return (
    <div style={{ marginTop: 16 }}>
      <div className="toolbar" role="tablist">
        {(["security", "hygiene"] as Lane[]).map((l) => (
          <button
            key={l}
            role="tab"
            aria-selected={lane === l}
            className={lane === l ? "" : "secondary"}
            onClick={() => setLane(l)}
          >
            {LANE_LABELS[l]}
          </button>
        ))}
        <button className="secondary" onClick={downloadReadout}>
          Export leadership readout
        </button>
        {exportMsg && <span className="muted">{exportMsg}</span>}
      </div>
      <QueuePanel lane={lane} />
      <AgingPanel lane={lane} />
      <FlowPanel lane={lane} />
    </div>
  );
}

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
      <Remediation />
      <NotEvaluated data={data} />
    </div>
  );
}
