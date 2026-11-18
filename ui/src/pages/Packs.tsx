import { useEffect, useState } from "react";
import { api } from "../api";

export default function Packs() {
  const [packs, setPacks] = useState<any[]>([]);
  const [yaml, setYaml] = useState("");
  const [result, setResult] = useState<any>(null);

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