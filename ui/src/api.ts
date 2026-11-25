let sessionToken = "";

export async function ensureSession() {
  if (sessionToken) return sessionToken;
  const res = await fetch("/api/session");
  const data = await res.json();
  sessionToken = data.token;
  return sessionToken;
}

export async function api<T = unknown>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  await ensureSession();
  const headers = new Headers(init.headers);
  headers.set("x-session-token", sessionToken);
  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  const res = await fetch(`/api${path}`, { ...init, headers });
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    return res.json();
  }
  return undefined as T;
}

export async function apiBlob(
  path: string,
  init: RequestInit = {},
): Promise<Blob> {
  await ensureSession();
  const headers = new Headers(init.headers);
  headers.set("x-session-token", sessionToken);
  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  const res = await fetch(`/api${path}`, { ...init, headers });
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  return res.blob();
}

/** Shared types for Phase 1 pages (Inbox, ResourceDetail, Compliance). */

export type TriageState =
  | "pass"
  | "fail"
  | "unknown"
  | "inapplicable"
  | "awaiting_grace"
  | "actionable"
  | "verified_corrected";

export interface TriageInfo {
  state: TriageState;
  grace_deadline?: string | null;
  grace_period_hours?: number | null;
  reason: string;
}

export interface InboxRow {
  change?: {
    id: string;
    resource_id: string;
    subscription_id?: string;
    label?: string;
    times?: { observation_time?: string; event_time?: string | null };
  };
  resource?: {
    name?: string;
    resource_type?: string;
    subscription_id?: string;
  };
  classification?: {
    environment?: string;
    reason?: string;
    source?: string;
    winning_rule_id?: string | null;
    conflicting?: boolean;
    missing_tag?: boolean;
  };
  /** P4: derived at read time from resource tags, falling back to RG tags. */
  ownership?: Ownership;
  /** P4: present when the inbox was requested with `group_by`. */
  group_key?: string | null;
  evaluation?: {
    id: string;
    outcome?: string;
    severity?: string;
    control_id?: string;
    control_revision?: string;
  };
  triage?: TriageInfo;
  disposition?: {
    owner?: string;
    disposition?: string;
    ticket_ref?: string;
  };
  since_last_visit?: boolean;
}

export interface InboxResponse {
  rows: InboxRow[];
  last_visit?: string | null;
  filter?: Record<string, string | null | undefined>;
  groups?: InboxGroup[];
}

export interface ComplianceSummary {
  passing: number;
  failing: number;
  unknown: number;
  inapplicable: number;
  exceptions: number;
  pending_remediation: number;
  awaiting_grace?: number;
  verified_corrected?: number;
  freshness?: string;
  scope?: string[];
}

export interface PropertyDiff {
  before?: unknown;
  after?: unknown;
}

export interface TimelineChange {
  id: string;
  label?: string;
  times?: { event_time?: string | null; observation_time?: string };
  before?: unknown;
  after?: unknown;
  property_diffs?: Record<string, PropertyDiff>;
}

export interface ResourceTimeline {
  resource?: {
    name?: string;
    resource_id?: string;
    resource_type?: string;
    location?: string;
    tags?: Record<string, unknown>;
  };
  changes?: TimelineChange[];
  evaluations?: Array<{
    id: string;
    control_id: string;
    control_revision: string;
    outcome: string;
    severity?: string;
    evidence?: Record<string, unknown>;
  }>;
  triage?: TriageInfo;
  exceptions?: Array<{
    id: string;
    control_id: string;
    reason?: string;
    approved_by?: string;
    expires_at?: string | null;
  }>;
  dispositions?: Array<{
    id: string;
    evaluation_id: string;
    owner?: string;
    disposition: string;
    ticket_ref?: string;
  }>;
  tickets?: unknown[];
}

/* ---- P4: environment classification and ownership ---- */

export type EnvironmentClass = "prod" | "nonprod" | "dev" | "sandbox" | "unknown";

export type ClassificationRuleKind =
  | "subscription"
  | "resource_group"
  | "tag"
  | "subscription_name_pattern"
  | "tag_segment"
  | "resource_group_tag"
  | "name_token";

export type ClassificationSource =
  | "subscription"
  | "subscription_name"
  | "resource_group"
  | "resource_tag"
  | "resource_group_tag"
  | "tag_segment"
  | "name_token"
  | "none";

export interface ClassificationRule {
  id: string;
  kind: ClassificationRuleKind;
  subscription_id: string | null;
  resource_group: string | null;
  tag_key: string | null;
  tag_value: string | null;
  environment: EnvironmentClass;
  priority: number;
  pattern?: string | null;
  segment_map?: Record<string, string> | null;
}

export interface ClassificationResult {
  environment: EnvironmentClass;
  winning_rule_id?: string | null;
  conflicting?: boolean;
  missing_tag?: boolean;
  reason?: string;
  source?: ClassificationSource;
}

export interface Ownership {
  application?: string | null;
  application_id?: string | null;
  owner?: string | null;
  line_of_business?: string | null;
  line_of_business_name?: string | null;
  from_resource_group?: boolean;
}

export interface OwnershipConfig {
  application_tag?: string | null;
  application_id_tag?: string | null;
  owner_tag?: string | null;
  line_of_business_tag?: string | null;
  lob_rollup_pattern?: string | null;
  lob_names: Record<string, string>;
  placeholder_values: string[];
}

export interface ClassificationQuality {
  total: number;
  by_source: Partial<Record<ClassificationSource, number>>;
  by_environment: Partial<Record<EnvironmentClass, number>>;
  conflicting: number;
  missing_tag: number;
  subscriptions_without_environment_token: Array<{ id: string; name: string }>;
  name_rules: "saved" | "suggested";
}

export interface InboxGroup {
  key: string | null;
  count: number;
}

/** POST that surfaces the server's `{error}` message (e.g. a 400 for a bad regex). */
async function postWithError<T>(path: string, body: unknown): Promise<T> {
  await ensureSession();
  const res = await fetch(`/api${path}`, {
    method: "POST",
    headers: {
      "x-session-token": sessionToken,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("application/json") ? await res.json() : undefined;
  if (!res.ok) {
    const detail = data && typeof data.error === "string" ? `: ${data.error}` : "";
    throw new Error(`${res.status} ${res.statusText}${detail}`);
  }
  return data as T;
}

export function listClassificationRules() {
  return api<{ rules: ClassificationRule[] }>("/classification/rules");
}

export function saveClassificationRule(rule: ClassificationRule) {
  return postWithError<{ ok: boolean }>("/classification/rules", rule);
}

/** Suggested defaults for review. The server never saves these on its own. */
export function suggestedClassificationRules() {
  return api<{ rules: ClassificationRule[] }>("/classification/suggested-rules");
}

export function classificationQuality() {
  return api<ClassificationQuality>("/classification/quality");
}

/** Merge an ownership config into the current settings document and save it. */
export async function saveOwnershipConfig(ownership: OwnershipConfig | null) {
  const current = await api<{ settings: Record<string, unknown> }>("/settings");
  return postWithError<{ ok: boolean }>("/settings", {
    ...current.settings,
    ownership,
  });
}
