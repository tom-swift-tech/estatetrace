import { useEffect, useState } from "react";
import { api } from "../api";

export default function Exports() {
  const [exportsList, setExportsList] = useState<any[]>([]);
  const [preview, setPreview] = useState<any>(null);
  const [controlId, setControlId] = useState("FIN-014");
  const [scope, setScope] = useState("/subscriptions/00000000-0000-0000-0000-000000000000");

  async function load() {
    const d = await api<{ exports: any[] }>("/exports");
    setExportsList(d.exports || []);
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div>
      <div className="panel">
        <label>Control ID</label>
        <input value={controlId} onChange={(e) => setControlId(e.target.value)} />
        <label>Target scope</label>
        <input value={scope} onChange={(e) => setScope(e.target.value)} />
        <div className="toolbar">
          <button
            onClick={async () => {
              const packs = await api<{ packs: any[] }>("/packs");
              const pack = packs.packs?.[0];
              if (!pack) {
                setPreview({ error: "Load a pack first" });
                return;
              }
              const p = await api("/exports/preview", {
                method: "POST",
                body: JSON.stringify({
                  pack_id: pack.id,
                  pack_revision: pack.revision,
                  control_id: controlId,
                  target_scope: scope,
                }),
              });
              setPreview(p);
            }}
          >
            Preview
          </button>
          <button
            className="secondary"
            onClick={async () => {
              const packs = await api<{ packs: any[] }>("/packs");
              const pack = packs.packs?.[0];
              if (!pack) return;
              await api("/exports", {
                method: "POST",
                body: JSON.stringify({
                  pack_id: pack.id,
                  pack_revision: pack.revision,
                  control_id: controlId,
                  target_scope: scope,
                  parameters: {},
                }),
              });
              await load();
            }}
          >
            Export Bicep
          </button>
        </div>
      </div>
      {preview && (
        <div className="panel">
          <div>
            {preview.effect} · supported={String(preview.supported)} ·{" "}
            {preview.reason}
          </div>
          <div className="pre">{preview.bicep}</div>
        </div>
      )}
      <table>
        <thead>
          <tr>
            <th>Control</th>
            <th>State</th>
            <th>Updated</th>
          </tr>
        </thead>
        <tbody>
          {exportsList.map((e) => (
            <tr key={e.id}>
              <td>
                {e.control_id} ({e.pack_revision})
              </td>
              <td>{e.state}</td>
              <td>{e.updated_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}