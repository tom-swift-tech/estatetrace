import { useEffect, useState } from "react";
import {
  api,
  ClassificationQuality,
  ClassificationRule,
  ClassificationRuleKind,
  classificationQuality,
  EnvironmentClass,
  listClassificationRules,
  OwnershipConfig,
  saveClassificationRule,
  saveOwnershipConfig,
  suggestedClassificationRules,
} from "../api";

const RULE_KINDS: Array<{ value: ClassificationRuleKind; label: string }> = [
  { value: "subscription", label: "Subscription ID" },
  { value: "subscription_name_pattern", label: "Subscription name pattern" },
  { value: "resource_group", label: "Resource group" },
  { value: "tag", label: "Resource tag" },
  { value: "tag_segment", label: "Resource tag segment (e.g. 1183.DEV)" },
  { value: "resource_group_tag", label: "Resource group tag" },
  { value: "name_token", label: "Resource name token" },
];

const ENVIRONMENTS: EnvironmentClass[] = ["prod", "nonprod", "dev", "sandbox", "unknown"];

function emptyRule(): ClassificationRule {
  return {
    id: "",
    kind: "subscription_name_pattern",
    subscription_id: null,
    resource_group: null,
    tag_key: null,
    tag_value: null,
    environment: "prod",
    priority: 100,
    pattern: null,
    segment_map: null,
  };
}

/** "key=value" lines <-> map. Blank text gives null. */
function parseMap(text: string): Record<string, string> | null {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const i = line.indexOf("=");
    if (i <= 0) continue;
    const k = line.slice(0, i).trim();
    const v = line.slice(i + 1).trim();
    if (k && v) out[k] = v;
  }
  return Object.keys(out).length ? out : null;
}

function formatMap(m?: Record<string, string> | null): string {
  return m ? Object.entries(m).map(([k, v]) => `${k}=${v}`).join("\n") : "";
}

function ruleSummary(r: ClassificationRule): string {
  switch (r.kind) {
    case "subscription":
      return `subscription ${r.subscription_id ?? "?"}`;
    case "resource_group":
      return `RG ${r.resource_group ?? "?"}${r.subscription_id ? ` in ${r.subscription_id}` : ""}`;
    case "subscription_name_pattern":
      return `name ~ ${r.pattern ?? "?"}`;
    case "name_token":
      return r.pattern ? `name token ~ ${r.pattern}` : "name token (mapped)";
    default: {
      const where = r.kind === "resource_group_tag" ? "RG tag" : "tag";
      const how = r.tag_value
        ? `= ${r.tag_value}`
        : r.kind === "tag_segment" || (r.kind === "resource_group_tag" && r.segment_map)
        ? "segments mapped"
        : "value mapped";
      return `${where} ${r.tag_key ?? "?"} ${how}`;
    }
  }
}

/** Environment comes from the map / tag value for these shapes, not from the rule. */
function envFromValue(r: ClassificationRule): boolean {
  if (r.kind === "tag_segment") return true;
  if (r.kind === "name_token") return !r.pattern;
  if (r.kind === "tag" || r.kind === "resource_group_tag") return !r.tag_value;
  return false;
}

function ClassificationSettings({ onMessage }: { onMessage: (m: string) => void }) {
  const [rules, setRules] = useState<ClassificationRule[]>([]);
  const [drafts, setDrafts] = useState<ClassificationRule[]>([]);
  const [form, setForm] = useState<ClassificationRule>(emptyRule());
  const [mapText, setMapText] = useState("");
  const [ruleError, setRuleError] = useState("");
  const [quality, setQuality] = useState<ClassificationQuality | null>(null);
  const [own, setOwn] = useState<OwnershipConfig>({ lob_names: {}, placeholder_values: [] });
  const [lobText, setLobText] = useState("");
  const [placeholderText, setPlaceholderText] = useState("");

  async function reload() {
    try {
      setRules((await listClassificationRules()).rules || []);
      setQuality(await classificationQuality());
    } catch (e: unknown) {
      setRuleError(e instanceof Error ? e.message : String(e));
    }
  }

  useEffect(() => {
    reload();
    api<{ settings: { ownership?: OwnershipConfig | null } }>("/settings").then((s) => {
      const o = s.settings.ownership;
      if (o) {
        setOwn({ ...o, lob_names: o.lob_names || {}, placeholder_values: o.placeholder_values || [] });
        setLobText(formatMap(o.lob_names));
        setPlaceholderText((o.placeholder_values || []).join(", "));
      }
    });
  }, []);

  function edit(r: ClassificationRule) {
    setForm({ ...r });
    setMapText(formatMap(r.segment_map));
    setRuleError("");
  }

  const blank = (s: string) => (s.trim() ? s : null);

  async function save(rule: ClassificationRule) {
    await saveClassificationRule(rule);
    setDrafts((d) => d.filter((x) => x.id !== rule.id));
    await reload();
  }

  async function saveForm() {
    setRuleError("");
    try {
      await save({ ...form, segment_map: parseMap(mapText) });
      onMessage(`Classification rule ${form.id} saved.`);
      setForm(emptyRule());
      setMapText("");
    } catch (e: unknown) {
      setRuleError(e instanceof Error ? e.message : String(e));
    }
  }

  const k = form.kind;
  const showSub = k === "subscription" || k === "resource_group";
  const showRg = k === "resource_group";
  const showTag = k === "tag" || k === "tag_segment" || k === "resource_group_tag";
  const showTagValue = k === "tag" || k === "resource_group_tag";
  const showPattern = k === "subscription_name_pattern" || k === "name_token";
  const showMap = k === "tag_segment" || k === "name_token" || ((k === "tag" || k === "resource_group_tag") && !form.tag_value);

  return (
    <>
      <div className="panel">
        <strong>Environment classification rules</strong>
        <div className="muted" style={{ marginBottom: "0.5rem" }}>
          Highest priority wins. When matching rules disagree the resource is flagged as
          conflicting. Patterns use Rust regex syntax (no lookarounds), matched
          case-insensitively; write whole-token matches as{" "}
          <code>(^|[^a-z0-9])prod([^a-z0-9]|$)</code>.
        </div>
        <table>
          <thead>
            <tr>
              <th>Priority</th>
              <th>Rule</th>
              <th>Match</th>
              <th>Environment</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {[...rules]
              .sort((a, b) => b.priority - a.priority)
              .map((r) => (
                <tr key={r.id}>
                  <td>{r.priority}</td>
                  <td>
                    {r.id}
                    <div className="muted">{r.kind}</div>
                  </td>
                  <td>
                    {ruleSummary(r)}
                    {r.segment_map && <div className="muted">{formatMap(r.segment_map).replace(/\n/g, ", ")}</div>}
                  </td>
                  <td>{envFromValue(r) ? "from value" : r.environment}</td>
                  <td>
                    <button className="secondary" onClick={() => edit(r)}>
                      Edit
                    </button>
                  </td>
                </tr>
              ))}
            {!rules.length && (
              <tr>
                <td colSpan={5} className="muted">
                  No rules saved. Every resource is Unknown until a rule matches.
                </td>
              </tr>
            )}
          </tbody>
        </table>

        <div className="toolbar">
          <button
            className="secondary"
            onClick={async () => {
              try {
                const r = await suggestedClassificationRules();
                setDrafts(r.rules || []);
                onMessage("Suggested rules loaded for review. Nothing is saved until you save it.");
              } catch (e: unknown) {
                setRuleError(e instanceof Error ? e.message : String(e));
              }
            }}
          >
            Load suggested rules
          </button>
        </div>

        {drafts.length > 0 && (
          <>
            <strong>Suggested rules (not saved)</strong>
            <div className="muted">
              Tag names such as <code>business-service</code> are placeholders. Edit them to
              your organisation's tag names before saving.
            </div>
            <table>
              <tbody>
                {drafts.map((r) => (
                  <tr key={r.id}>
                    <td>{r.priority}</td>
                    <td>{r.id}</td>
                    <td>{ruleSummary(r)}</td>
                    <td>{envFromValue(r) ? "from value" : r.environment}</td>
                    <td>
                      <button className="secondary" onClick={() => edit(r)}>
                        Edit
                      </button>{" "}
                      <button
                        onClick={async () => {
                          try {
                            await save(r);
                          } catch (e: unknown) {
                            setRuleError(e instanceof Error ? e.message : String(e));
                          }
                        }}
                      >
                        Save
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="toolbar">
              <button
                onClick={async () => {
                  try {
                    for (const r of drafts) await save(r);
                    onMessage("Suggested rules saved.");
                  } catch (e: unknown) {
                    setRuleError(e instanceof Error ? e.message : String(e));
                  }
                }}
              >
                Save all suggested
              </button>
              <button className="secondary" onClick={() => setDrafts([])}>
                Discard suggestions
              </button>
            </div>
          </>
        )}

        <strong>{rules.some((r) => r.id === form.id) ? `Edit rule ${form.id}` : "New rule"}</strong>
        <label>Rule ID</label>
        <input value={form.id} onChange={(e) => setForm({ ...form, id: e.target.value })} />
        <label>Kind</label>
        <select
          value={form.kind}
          onChange={(e) => setForm({ ...form, kind: e.target.value as ClassificationRuleKind })}
        >
          {RULE_KINDS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <label>Priority</label>
        <input
          type="number"
          value={form.priority}
          onChange={(e) => setForm({ ...form, priority: Number(e.target.value) || 0 })}
        />
        {showSub && (
          <>
            <label>Subscription ID{k === "resource_group" ? " (optional)" : ""}</label>
            <input
              value={form.subscription_id ?? ""}
              onChange={(e) => setForm({ ...form, subscription_id: blank(e.target.value) })}
            />
          </>
        )}
        {showRg && (
          <>
            <label>Resource group</label>
            <input
              value={form.resource_group ?? ""}
              onChange={(e) => setForm({ ...form, resource_group: blank(e.target.value) })}
            />
          </>
        )}
        {showTag && (
          <>
            <label>Tag name (case-insensitive)</label>
            <input
              value={form.tag_key ?? ""}
              onChange={(e) => setForm({ ...form, tag_key: blank(e.target.value) })}
            />
          </>
        )}
        {showTagValue && (
          <>
            <label>Tag value (blank: map the tag's value to an environment)</label>
            <input
              value={form.tag_value ?? ""}
              onChange={(e) => setForm({ ...form, tag_value: blank(e.target.value) })}
            />
          </>
        )}
        {showPattern && (
          <>
            <label>
              Pattern{k === "name_token" ? " (optional; a matching name token gives the environment below)" : ""}
            </label>
            <input
              value={form.pattern ?? ""}
              onChange={(e) => setForm({ ...form, pattern: blank(e.target.value) })}
            />
          </>
        )}
        {showMap && (
          <>
            <label>
              Value map, one <code>value=environment</code> per line (blank: built-in names)
            </label>
            <textarea rows={4} value={mapText} onChange={(e) => setMapText(e.target.value)} />
          </>
        )}
        {!envFromValue({ ...form, segment_map: parseMap(mapText) }) && (
          <>
            <label>Environment</label>
            <select
              value={form.environment}
              onChange={(e) => setForm({ ...form, environment: e.target.value as EnvironmentClass })}
            >
              {ENVIRONMENTS.map((env) => (
                <option key={env} value={env}>
                  {env}
                </option>
              ))}
            </select>
          </>
        )}
        <div className="toolbar">
          <button disabled={!form.id.trim()} onClick={saveForm}>
            Save rule
          </button>
          <button
            className="secondary"
            onClick={() => {
              setForm(emptyRule());
              setMapText("");
              setRuleError("");
            }}
          >
            Clear
          </button>
        </div>
        {ruleError && <div className="panel">{ruleError}</div>}
      </div>

      <div className="panel">
        <strong>Classification data quality</strong>
        {quality ? (
          <>
            <div className="muted">
              {quality.total} tracked resource(s) · {quality.conflicting} conflicting ·{" "}
              {quality.missing_tag} missing an Environment tag
            </div>
            <table>
              <thead>
                <tr>
                  <th>Classified by</th>
                  <th>Resources</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(quality.by_source).map(([src, n]) => (
                  <tr key={src}>
                    <td>{src === "none" ? "no rule (Unknown)" : src.replace(/_/g, " ")}</td>
                    <td>{n}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ marginTop: "0.5rem" }}>
              Tracked subscriptions whose name gives no environment (
              {quality.name_rules === "saved" ? "saved name patterns" : "suggested name patterns"}):{" "}
              {quality.subscriptions_without_environment_token.length
                ? quality.subscriptions_without_environment_token.map((s) => s.name).join(", ")
                : "none"}
            </div>
          </>
        ) : (
          <div className="muted">Loading…</div>
        )}
      </div>

      <div className="panel">
        <strong>Ownership tags</strong>
        <div className="muted" style={{ marginBottom: "0.5rem" }}>
          Read from the resource's tags, falling back to its resource group. Applied when
          pages load, so changes need no rescan. Values of <code>undefined</code> count as
          empty.
        </div>
        {(
          [
            ["application_tag", "Application tag"],
            ["application_id_tag", "Application ID tag"],
            ["owner_tag", "Owner tag"],
            ["line_of_business_tag", "Line-of-business tag"],
            ["lob_rollup_pattern", "LOB roll-up pattern (e.g. ^\\d+ turns 11.3 into 11)"],
          ] as Array<[keyof OwnershipConfig, string]>
        ).map(([key, label]) => (
          <div key={key}>
            <label>{label}</label>
            <input
              value={(own[key] as string | null | undefined) ?? ""}
              onChange={(e) => setOwn({ ...own, [key]: blank(e.target.value) })}
            />
          </div>
        ))}
        <label>
          LOB names, one <code>id=name</code> per line
        </label>
        <textarea rows={4} value={lobText} onChange={(e) => setLobText(e.target.value)} />
        <label>Other placeholder values (comma-separated)</label>
        <input value={placeholderText} onChange={(e) => setPlaceholderText(e.target.value)} />
        <div className="toolbar">
          <button
            onClick={async () => {
              try {
                await saveOwnershipConfig({
                  ...own,
                  lob_names: parseMap(lobText) || {},
                  placeholder_values: placeholderText
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean),
                });
                onMessage("Ownership settings saved.");
              } catch (e: unknown) {
                onMessage(`Ownership settings not saved: ${e instanceof Error ? e.message : String(e)}`);
              }
            }}
          >
            Save ownership settings
          </button>
        </div>
      </div>
    </>
  );
}

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
  const [snowBusy, setSnowBusy] = useState(false);
  const [chatBusy, setChatBusy] = useState(false);

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
              setSnowBusy(true);
              setMsg("Testing ServiceNow connection…");
              try {
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
                setMsg(`ServiceNow connected and saved. ${JSON.stringify(r)}`);
                setStatus(await api("/connectors/status"));
              } catch (e: unknown) {
                setMsg(`ServiceNow test failed: ${e instanceof Error ? e.message : String(e)}`);
              } finally {
                setSnowBusy(false);
              }
            }}
            disabled={snowBusy}
          >
            {snowBusy ? "Testing..." : "Test and save"}
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
              setChatBusy(true);
              setMsg("Testing APIM chat connection…");
              try {
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
                setMsg(`APIM chat connected and saved. ${JSON.stringify(r)}`);
                setStatus(await api("/connectors/status"));
              } catch (e: unknown) {
                setMsg(`APIM chat test failed: ${e instanceof Error ? e.message : String(e)}`);
              } finally {
                setChatBusy(false);
              }
            }}
            disabled={chatBusy}
          >
            {chatBusy ? "Testing..." : "Test and save"}
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

      <ClassificationSettings onMessage={setMsg} />

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