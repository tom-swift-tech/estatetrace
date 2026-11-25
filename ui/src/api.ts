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
  classification?: { environment?: string; reason?: string };
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
  exceptions?: ExceptionRecord[];
  dispositions?: Array<{
    id: string;
    evaluation_id: string;
    owner?: string;
    disposition: string;
    ticket_ref?: string;
  }>;
  tickets?: unknown[];
}
