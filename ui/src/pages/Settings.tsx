import { useEffect, useState } from "react";
import { api } from "../api";

export default function Settings() {
  const [status, setStatus] = useState<any>(null);
  const [snow, setSnow] = useState({
    instance_url: "",
    username: "",
    password: "",
  });
  const [chat, setChat] = useState({
    gateway_url: "",
    deployment: "",
    key: "",
    header_name: "Ocp-Apim-Subscription-Key",
  });
  const [themeYaml, setThemeYaml] = useState(
    "name: Company\nheader: \"#1f2933\"\nsidebar: \"#243b53\"\ncanvas: \"#f5f7fa\"\naccent: \"#0b6e4f\"\n",
  );
  const [msg, setMsg] = useState("");
  const [ask, setAsk] = useState("");
  const [answer, setAnswer] = useState<any>(null);

  useEffect(() => {
    api("/connectors/status").then(setStatus);
  }, []);

  return (
    <div>
      <div className="panel">
        <strong>Connectors</strong>
        <div className="pre">{JSON.stringify(status, null, 2)}</div>
      </div>

      <div className="panel">
        <strong>ServiceNow</strong>
        <label>Instance URL</label>
        <input
          value={snow.instance_url}
          onChange={(e) => setSnow({ ...snow, instance_url: e.target.value })}
        />
        <label>Username</label>
        <input
          value={snow.username}
          onChange={(e) => setSnow({ ...snow, username: e.target.value })}
        />
        <label>Password (Credential Manager)</label>
        <input
          type="password"
          value={snow.password}
          onChange={(e) => setSnow({ ...snow, password: e.target.value })}
        />
        <div className="toolbar">
          <button
            onClick={async () => {
              const r = await api("/connectors/servicenow/test", {
                method: "POST",
                body: JSON.stringify({
                  config: {
                    instance_url: snow.instance_url,
                    username: snow.username,
                    operating_scope_services: [],
                    operating_scope_assignment_groups: [],
                    high_priorities: ["1", "2"],
                    ongoing_incident_states: ["1", "2", "3"],
                    refresh_interval_minutes: 5,
                  },
                  password: snow.password,
                }),
              });
              setMsg(JSON.stringify(r));
              setStatus(await api("/connectors/status"));
            }}
          >
            Test and save
          </button>
          <button
            className="secondary"
            onClick={async () => {
              await api("/connectors/servicenow/disconnect", {
                method: "POST",
                body: "{}",
              });
              setStatus(await api("/connectors/status"));
            }}
          >
            Disconnect
          </button>
        </div>
      </div>

      <div className="panel">
        <strong>APIM chat (BYOK)</strong>
        <label>Gateway URL</label>
        <input
          value={chat.gateway_url}
          onChange={(e) => setChat({ ...chat, gateway_url: e.target.value })}
        />
        <label>Deployment</label>
        <input
          value={chat.deployment}
          onChange={(e) => setChat({ ...chat, deployment: e.target.value })}
        />
        <label>Key</label>
        <input
          type="password"
          value={chat.key}
          onChange={(e) => setChat({ ...chat, key: e.target.value })}
        />
        <div className="toolbar">
          <button
            onClick={async () => {
              const r = await api("/connectors/chat/test", {
                method: "POST",
                body: JSON.stringify({
                  config: {
                    gateway_url: chat.gateway_url,
                    deployment: chat.deployment,
                    header_name: chat.header_name,
                    api_version: "2024-02-15-preview",
                  },
                  key: chat.key,
                }),
              });
              setMsg(JSON.stringify(r));
              setStatus(await api("/connectors/status"));
            }}
          >
            Test and save
          </button>
          <button
            className="secondary"
            onClick={async () => {
              await api("/connectors/chat/disconnect", {
                method: "POST",
                body: "{}",
              });
              setStatus(await api("/connectors/status"));
            }}
          >
            Disconnect
          </button>
        </div>
        <label>Ask about this view</label>
        <input value={ask} onChange={(e) => setAsk(e.target.value)} />
        <button
          onClick={async () => {
            const r = await api("/connectors/chat/ask", {
              method: "POST",
              body: JSON.stringify({
                question: ask,
                environment: "prod",
                include_ticket_notes: false,
              }),
            });
            setAnswer(r);
          }}
        >
          Ask
        </button>
        {answer && <div className="pre">{JSON.stringify(answer, null, 2)}</div>}
      </div>

      <div className="panel">
        <strong>Company theme.yaml</strong>
        <textarea
          rows={8}
          style={{ width: "100%", maxWidth: "100%" }}
          value={themeYaml}
          onChange={(e) => setThemeYaml(e.target.value)}
        />
        <button
          onClick={async () => {
            const r = await api<{ preview: unknown }>("/theme", {
              method: "POST",
              body: JSON.stringify({ yaml: themeYaml }),
            });
            setMsg("Theme applied. Preview: " + JSON.stringify(r.preview));
            location.reload();
          }}
        >
          Apply theme
        </button>
      </div>

      <div className="panel">
        <button
          onClick={async () => {
            const r = await api<{ path: string }>("/backup", {
              method: "POST",
              body: "{}",
            });
            setMsg(`Backup written to ${r.path}`);
          }}
        >
          Backup now
        </button>
      </div>
      {msg && <div className="panel">{msg}</div>}
    </div>
  );
}