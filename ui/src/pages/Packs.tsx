import { useEffect, useState } from "react";
import { api, compilePack, type CompilePackResult } from "../api";

type ImportTab = "yaml" | "check_map";

/** A labelled textarea that can also be filled from a local file. */
function TextSource(props: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  rows?: number;
}) {
  return (
    <div style={{ marginBottom: "0.75rem" }}>
      <label>{props.label}</label>
      <div>
        <input
          type="file"
          accept=".yaml,.yml,.json,.txt"
          onChange={async (e) => {
            const f = e.target.files?.[0];
            if (f) props.onChange(await f.text());
            e.target.value = "";
          }}
        />
      </div>
      <textarea
        rows={props.rows ?? 10}
        style={{ maxWidth: "100%", width: "100%" }}
        value={props.value}
        onChange={(e) => props.onChange(e.target.value)}
      />
    </div>
  );
}

function CheckMapImport(props: { onImported: (r: unknown) => void }) {
  const [catalog, setCatalog] = useState("");
  const [checkMap, setCheckMap] = useState("");
  const [settings, setSettings] = useState("");
  const [compiled, setCompiled] = useState<CompilePackResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const issues = compiled?.issues ?? [];
  const errors = issues.filter((i) => i.severity === "error");
  const warnings = issues.filter((i) => i.severity === "warning");
  const canImport = !!compiled?.pack && errors.length === 0;

  async function compile() {
    setBusy(true);
    setError("");
    try {
      setCompiled(
        await compilePack({ catalog, check_map: checkMap, settings: settings || undefined }),
      );
    } catch (e) {
      setCompiled(null);
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function importCompiled() {
    if (!compiled?.pack) return;
    setBusy(true);
    setError("");
    try {
      const r = await api("/packs", {
        method: "POST",
        body: JSON.stringify({
          json: JSON.stringify(compiled.pack),
          reviewed_by: "operator",
          activate: true,
        }),
      });
      props.onImported(r);
    } catch (e) {
      setError(`Import failed: ${String(e)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel">
      <p>
        Compile a policy catalog and its check map into a pack. Every catalog control must be
        in the check map's <code>checks</code> or <code>not_evaluated</code>. Settings supply{" "}
        <code>named_values</code>, <code>suppress</code> and <code>check_overrides</code>.
      </p>
      <TextSource label="Catalog (YAML or JSON)" value={catalog} onChange={setCatalog} />
      <TextSource label="Check map (YAML or JSON)" value={checkMap} onChange={setCheckMap} />
      <TextSource
        label="Settings (optional, YAML or JSON)"
        value={settings}
        onChange={setSettings}
        rows={5}
      />
      <div className="toolbar">
        <button disabled={busy || !catalog.trim() || !checkMap.trim()} onClick={compile}>
          Compile
        </button>
        <button disabled={busy || !canImport} onClick={importCompiled}>
          Import compiled pack
        </button>
      </div>
      {error && <p className="badge fail">{error}</p>}
      {compiled && (
        <div>
          <p>
            {errors.length} error(s), {warnings.length} warning(s)
            {compiled.pack && (
              <>
                {" "}
                · pack <strong>{String(compiled.pack.id)}</strong> revision{" "}
                {String(compiled.pack.revision)} with{" "}
                {Array.isArray(compiled.pack.controls) ? compiled.pack.controls.length : 0}{" "}
                control(s)
              </>
            )}
          </p>
          {issues.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Control</th>
                  <th>Issue</th>
                </tr>
              </thead>
              <tbody>
                {[...errors, ...warnings].map((i, n) => (
                  <tr key={n}>
                    <td>
                      <span className={`badge ${i.severity === "error" ? "fail" : "unknown"}`}>
                        {i.severity}
                      </span>
                    </td>
                    <td>{i.control_id ?? "—"}</td>
                    <td>{i.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

export default function Packs() {
  const [packs, setPacks] = useState<any[]>([]);
  const [yaml, setYaml] = useState("");
  const [result, setResult] = useState<any>(null);
  const [tab, setTab] = useState<ImportTab>("yaml");

  async function load() {
    const d = await api<{ packs: any[] }>("/packs");
    setPacks(d.packs || []);
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div>
      <div className="toolbar">
        <button
          onClick={async () => {
            const r = await api("/packs/pilot", { method: "POST", body: "{}" });
            setResult(r);
            await load();
          }}
        >
          Load pilot pack
        </button>
      </div>
      <div className="toolbar" role="tablist">
        <button
          role="tab"
          aria-selected={tab === "yaml"}
          disabled={tab === "yaml"}
          onClick={() => setTab("yaml")}
        >
          YAML pack
        </button>
        <button
          role="tab"
          aria-selected={tab === "check_map"}
          disabled={tab === "check_map"}
          onClick={() => setTab("check_map")}
        >
          Catalog + check map
        </button>
      </div>
      {tab === "yaml" ? (
        <div className="panel">
          <label>Import reviewed YAML pack</label>
          <textarea
            rows={12}
            style={{ maxWidth: "100%", width: "100%" }}
            value={yaml}
            onChange={(e) => setYaml(e.target.value)}
          />
          <div className="toolbar">
            <button
              onClick={async () => {
                const r = await api("/packs", {
                  method: "POST",
                  body: JSON.stringify({
                    yaml,
                    reviewed_by: "operator",
                    activate: true,
                  }),
                });
                setResult(r);
                await load();
              }}
            >
              Validate & activate
            </button>
          </div>
        </div>
      ) : (
        <CheckMapImport
          onImported={async (r) => {
            setResult(r);
            await load();
          }}
        />
      )}
      {result && (
        <div className="panel">
          <div className="pre">{JSON.stringify(result, null, 2)}</div>
        </div>
      )}
      <table>
        <thead>
          <tr>
            <th>Pack</th>
            <th>Revision</th>
            <th>Activated</th>
            <th>Reviewed by</th>
          </tr>
        </thead>
        <tbody>
          {packs.map((p) => (
            <tr key={`${p.id}-${p.revision}`}>
              <td>
                {p.name} ({p.id})
              </td>
              <td>{p.revision}</td>
              <td>{p.activated ? "yes" : "no"}</td>
              <td>{p.reviewed_by}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
