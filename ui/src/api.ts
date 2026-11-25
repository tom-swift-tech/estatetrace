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
  | "verified_corrected"
  | "excepted";

export interface TriageInfo {
  state: TriageState;
  grace_deadline?: string | null;
  grace_period_hours?: number | null;
  reason: string;
  exception_id?: string | null;
  exception_expired?: boolean;
}

/** Scoped exception (spec §4.5): resource_id, or subscription_id (+ resource_group). */
export interface ExceptionRecord {
  id: string;
  control_id: string;
  resource_id?: string | null;
  subscription_id?: string | null;
  resource_group?: string | null;
  reason?: string | null;
  approved_by?: string | null;
  ticket_ref?: string | null;
  expires_at?: string | null;
  created_at?: string;
}

export interface ExceptionCreate {
  control_id: string;
  resource_id?: string | null;
  subscription_id?: string | null;
  resource_group?: string | null;
  reason?: string | null;
  approved_by?: string | null;
  ticket_ref?: string | null;
  /** RFC 3339, or YYYY-MM-DD (end of that day, UTC). */
  expires_at?: string | null;
}

export function createException(
  body: ExceptionCreate,
): Promise<{ exception: ExceptionRecord; expired: boolean }> {
  return api("/exceptions", { method: "POST", body: JSON.stringify(body) });
}

/* ---- P3: findings as intervals (spec §4.4) ---- */

export type EvalOutcome = "pass" | "fail" | "unknown" | "inapplicable";

export type CloseReason =
  | "state_changed"
  | "pack_revision"
  | "no_longer_targeted"
  | "resource_missing"
  | "pack_deactivated";

/** One outcome of one control on one resource, from opened_at until closed_at. */
export interface FindingInterval {
  id: string;
  pack_id: string;
  pack_revision: string;
  clause_revision: string;
  resource_id: string;
  subscription_id: string;
  control_id: string;
  outcome: EvalOutcome;
  severity: string;
  environment: string;
  detail: string;
  evidence: Record<string, unknown>;
  opened_at: string;
  opened_scan_id: string;
  last_evaluated_at: string;
  last_scan_id: string;
  closed_at: string | null;
  close_reason: CloseReason | null;
  grace_period_hours: number | null;
  predecessor_outcome?: EvalOutcome | null;
  predecessor_close_reason?: CloseReason | null;
}

export interface TriagedFinding {
  finding: FindingInterval;
  triage: TriageInfo;
}

export const CLOSE_REASON_LABELS: Record<CloseReason, string> = {
  state_changed: "outcome changed",
  pack_revision: "pack revision changed",
  no_longer_targeted: "control no longer applies",
  resource_missing: "resource not found by a complete scan",
  pack_deactivated: "pack deactivated",
};

/** An open finding the newest scan did not re-evaluate (e.g. after a partial scan). */
export function isStale(
  f: Pick<FindingInterval, "closed_at" | "last_evaluated_at">,
  lastScanAt?: string | null,
): boolean {
  if (f.closed_at || !lastScanAt) return false;
  return new Date(f.last_evaluated_at).getTime() < new Date(lastScanAt).getTime();
}

export interface FindingQuery {
  subscription_id?: string;
  control_id?: string;
  outcome?: EvalOutcome;
  environment?: string;
  lane?: "security" | "hygiene";
  /** With resource_id the response is that resource's full history (open + closed). */
  resource_id?: string;
  limit?: number;
}

export interface FindingsResponse {
  findings: FindingInterval[];
  /** `triage[i]` triages `findings[i]`. */
  triage: TriageInfo[];
  last_scan_at?: string | null;
}

export function listFindings(q: FindingQuery = {}): Promise<FindingsResponse> {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v !== undefined && v !== null && v !== "") params.set(k, String(v));
  }
  const qs = params.toString();
  return api<FindingsResponse>(`/findings${qs ? `?${qs}` : ""}`);
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
  /** Most urgent open finding of the resource (row-level summary). */
  finding?: FindingInterval | null;
  /** Every open finding of the resource, triaged per control, most urgent first. */
  findings?: TriagedFinding[];
  /** Most urgent triage across the resource's controls. */
  triage?: TriageInfo | null;
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
  /** Start of the newest finished scan; an older `last_evaluated_at` is stale. */
  last_scan_at?: string | null;
  filter?: Record<string, string | null | undefined>;
  groups?: InboxGroup[];
}

export interface ComplianceSummary {
  passing: number;
  failing: number;
  unknown: number;
  inapplicable: number;
  exceptions: number;
  excepted?: number;
  pending_remediation: number;
  awaiting_grace?: number;
  verified_corrected?: number;
  freshness?: string;
  /** Start of the newest finished scan. */
  last_scan_at?: string | null;
  /** Open findings the newest scan did not re-evaluate. */
  stale?: number;
  scope?: string[];
  coverage_gaps?: CoverageGap[];
  controls_evaluated?: number;
  controls_total?: number;
}

export type GapCategory =
  | "outside_azure"
  | "more_collection"
  | "by_construction"
  | "needs_decision"
  | "deep_collection";

/** A control (or deep-only target type) that the scan cannot judge per resource. */
export interface CoverageGap {
  pack_id: string;
  control_id: string;
  category: GapCategory;
  note: string;
  resource_type: string | null;
  resource_count: number;
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
  /** Full interval history of the resource, open and closed. */
  findings?: FindingInterval[];
  /** `findings_triage[i]` triages `findings[i]`; null for closed intervals. */
  findings_triage?: Array<TriageInfo | null>;
  /** Most urgent triage across the open findings. */
  triage?: TriageInfo | null;
  last_scan_at?: string | null;
  exceptions?: ExceptionRecord[];
  dispositions?: Array<{
    id: string;
    /** Finding interval ID (the column keeps its pre-P3 name). */
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

/** Phase 7: one compile lint issue (spec §4.8). */
export interface CompileIssue {
  severity: "error" | "warning";
  control_id?: string | null;
  message: string;
}

export interface CompilePackResult {
  /** The compiled pack, or null when any issue is an error (HTTP 422). */
  pack: Record<string, unknown> | null;
  issues: CompileIssue[];
}

/** Compile catalog + check map (+ settings) text into a pack. A 422 still returns its issues. */
export async function compilePack(body: {
  catalog: string;
  check_map: string;
  settings?: string;
}): Promise<CompilePackResult> {
  await ensureSession();
  const res = await fetch("/api/packs/compile", {
    method: "POST",
    headers: {
      "x-session-token": sessionToken,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("application/json") ? await res.json() : undefined;
  if (res.ok || (res.status === 422 && data && Array.isArray(data.issues))) {
    return { pack: data.pack ?? null, issues: data.issues ?? [] };
  }
  throw new Error(`${res.status} ${res.statusText}`);
}
