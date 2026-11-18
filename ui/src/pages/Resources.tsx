import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

export default function Resources() {
  const [rows, setRows] = useState<any[]>([]);
  useEffect(() => {
    api<{ resources: any[] }>("/resources").then((d) => setRows(d.resources || []));
  }, []);
  return (
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Type</th>
          <th>Subscription</th>
          <th>Environment</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.resource.id}>
            <td>
              <Link
                to={`/resources/${encodeURIComponent(r.resource.resource_id)}`}
              >
                {r.resource.name}
              </Link>
            </td>
            <td>{r.resource.resource_type}</td>
            <td className="muted">{r.resource.subscription_id}</td>
            <td>
              <span className={`badge ${r.classification?.environment}`}>
                {r.classification?.environment}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}