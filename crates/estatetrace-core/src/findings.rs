//! Findings as intervals (spec §4.4) and their triage: grace → actionable → verified
//! corrected (UI-02 / AC-07), with the scoped exception overlay (spec §4.5).

use crate::{EnvironmentClass, EvalOutcome, ResourceId, Severity, SubscriptionId};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TriageState {
    Pass,
    Fail,
    Unknown,
    Inapplicable,
    AwaitingGrace,
    Actionable,
    VerifiedCorrected,
    /// A failing finding covered by an active scoped exception. Overlay only: the stored
    /// outcome stays `fail` (spec invariant 11).
    Excepted,
}

impl TriageState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TriageState::Pass => "pass",
            TriageState::Fail => "fail",
            TriageState::Unknown => "unknown",
            TriageState::Inapplicable => "inapplicable",
            TriageState::AwaitingGrace => "awaiting_grace",
            TriageState::Actionable => "actionable",
            TriageState::VerifiedCorrected => "verified_corrected",
            TriageState::Excepted => "excepted",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageInfo {
    pub state: TriageState,
    pub grace_deadline: Option<DateTime<Utc>>,
    pub grace_period_hours: Option<u64>,
    pub reason: String,
    /// Exception that matched this (resource, control), active or expired.
    #[serde(default)]
    pub exception_id: Option<String>,
    /// True when the matching exception has expired, so the finding stays actionable.
    #[serde(default)]
    pub exception_expired: bool,
}

/// Scoped exception (spec §4.5). The scope is one of: `resource_id`, `subscription_id`,
/// or `subscription_id` + `resource_group`. When `resource_id` is set, the subscription and
/// resource group are ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionRecord {
    pub id: String,
    pub control_id: String,
    #[serde(default)]
    pub resource_id: Option<String>,
    #[serde(default)]
    pub subscription_id: Option<String>,
    #[serde(default)]
    pub resource_group: Option<String>,
    pub reason: Option<String>,
    pub approved_by: Option<String>,
    #[serde(default)]
    pub ticket_ref: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl ExceptionRecord {
    /// Active means no expiry, or an expiry at or after `now`.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.map(|e| e >= now).unwrap_or(true)
    }

    /// True when the record names neither a resource nor a subscription.
    pub fn scope_is_empty(&self) -> bool {
        non_blank(&self.resource_id).is_none() && non_blank(&self.subscription_id).is_none()
    }

    /// One entry of azcompliance `Find-Exception`: same control (case-insensitive) and a
    /// scope that covers the resource (see [`ExceptionRecord::covers`]).
    pub fn matches(&self, control_id: &str, resource_id: &str) -> bool {
        self.control_id.trim().eq_ignore_ascii_case(control_id.trim()) && self.covers(resource_id)
    }

    /// Scope check only. A `resource_id` scope is an exact, case-insensitive match. Otherwise
    /// the subscription must match and, when set, the resource group too. Both are derived
    /// from the ARM resource ID.
    pub fn covers(&self, resource_id: &str) -> bool {
        if let Some(rid) = non_blank(&self.resource_id) {
            return rid.eq_ignore_ascii_case(resource_id.trim());
        }
        let Some(sub) = non_blank(&self.subscription_id) else {
            return false;
        };
        let (res_sub, res_rg) = arm_scope(resource_id);
        if !res_sub.is_some_and(|s| s.eq_ignore_ascii_case(sub)) {
            return false;
        }
        match non_blank(&self.resource_group) {
            Some(rg) => res_rg.is_some_and(|r| r.eq_ignore_ascii_case(rg)),
            None => true,
        }
    }
}

fn non_blank(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Subscription ID and resource group parsed from an ARM resource ID
/// (`/subscriptions/<sub>/resourceGroups/<rg>/...`). Segment names match case-insensitively.
pub fn arm_scope(resource_id: &str) -> (Option<&str>, Option<&str>) {
    let segs: Vec<&str> = resource_id.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() < 2 || !segs[0].eq_ignore_ascii_case("subscriptions") {
        return (None, None);
    }
    let rg = if segs.len() >= 4 && segs[2].eq_ignore_ascii_case("resourceGroups") {
        Some(segs[3])
    } else {
        None
    };
    (Some(segs[1]), rg)
}

/// First exception for `control_id` whose scope covers `resource_id`, regardless of expiry
/// (port of azcompliance `Find-Exception`).
pub fn find_exception<'a>(
    exs: &'a [ExceptionRecord],
    control_id: &str,
    resource_id: &str,
) -> Option<&'a ExceptionRecord> {
    exs.iter().find(|x| x.matches(control_id, resource_id))
}

/// Exception overlay on triage (spec invariant 11). It applies to `Fail` only. An active
/// matching exception gives `Excepted` with `exception_id`. When every match has expired, the
/// finding is `Actionable` with `exception_expired = true`. An active match wins over an
/// expired one. Other outcomes, and fails with no match, are returned unchanged.
pub fn apply_exception(
    info: TriageInfo,
    outcome: &EvalOutcome,
    control_id: &str,
    resource_id: &str,
    exceptions: &[ExceptionRecord],
    now: DateTime<Utc>,
) -> TriageInfo {
    if *outcome != EvalOutcome::Fail {
        return info;
    }
    let mut matching = exceptions
        .iter()
        .filter(|x| x.matches(control_id, resource_id));
    let Some(first) = matching.next() else {
        return info;
    };
    let active = if first.is_active(now) {
        Some(first)
    } else {
        matching.find(|x| x.is_active(now))
    };
    match active {
        Some(x) => TriageInfo {
            state: TriageState::Excepted,
            reason: match x.expires_at {
                Some(e) => format!("excepted by {} until {}", x.id, e.to_rfc3339()),
                None => format!("excepted by {} (no expiry)", x.id),
            },
            exception_id: Some(x.id.clone()),
            exception_expired: false,
            ..info
        },
        None => TriageInfo {
            state: TriageState::Actionable,
            reason: match first.expires_at {
                Some(e) => format!("exception {} expired at {}", first.id, e.to_rfc3339()),
                None => format!("exception {} has expired", first.id),
            },
            exception_id: Some(first.id.clone()),
            exception_expired: true,
            ..info
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispositionRecord {
    pub id: String,
    pub evaluation_id: String,
    pub owner: Option<String>,
    pub disposition: String,
    pub ticket_ref: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Why an interval closed (spec §4.4, invariant 8).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    /// The outcome changed; a new interval opened with the new outcome.
    StateChanged,
    /// The pack revision changed (on activation or at the next scan).
    PackRevision,
    /// The resource was observed by a complete pass but the control no longer selects it.
    NoLongerTargeted,
    /// A complete from-the-beginning pass of the subscription did not observe the resource.
    ResourceMissing,
    /// The pack was deactivated.
    PackDeactivated,
}

impl CloseReason {
    pub const ALL: [CloseReason; 5] = [
        CloseReason::StateChanged,
        CloseReason::PackRevision,
        CloseReason::NoLongerTargeted,
        CloseReason::ResourceMissing,
        CloseReason::PackDeactivated,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            CloseReason::StateChanged => "state_changed",
            CloseReason::PackRevision => "pack_revision",
            CloseReason::NoLongerTargeted => "no_longer_targeted",
            CloseReason::ResourceMissing => "resource_missing",
            CloseReason::PackDeactivated => "pack_deactivated",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        CloseReason::ALL.into_iter().find(|r| r.as_str() == s.trim())
    }
}

/// One stored finding interval: the outcome of one control on one resource from `opened_at`
/// until `closed_at` (open while `None`). Re-evaluations with the same outcome only move
/// `last_evaluated_at` / `last_scan_id` (spec §4.4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingInterval {
    pub id: String,
    pub pack_id: String,
    pub pack_revision: String,
    pub clause_revision: String,
    pub resource_id: ResourceId,
    pub subscription_id: SubscriptionId,
    pub control_id: String,
    pub outcome: EvalOutcome,
    pub severity: Severity,
    pub environment: EnvironmentClass,
    pub detail: String,
    pub evidence: Value,
    pub opened_at: DateTime<Utc>,
    pub opened_scan_id: String,
    pub last_evaluated_at: DateTime<Utc>,
    pub last_scan_id: String,
    pub closed_at: Option<DateTime<Utc>>,
    pub close_reason: Option<CloseReason>,
    /// From the evidence (`grace_period_hours` of the control at evaluation time).
    pub grace_period_hours: Option<u64>,
    /// Outcome of the previous interval for the same (pack, resource, control), filled by the
    /// query so triage never scans history (`VerifiedCorrected`, spec §3.2).
    #[serde(default)]
    pub predecessor_outcome: Option<EvalOutcome>,
    /// Close reason of that previous interval.
    #[serde(default)]
    pub predecessor_close_reason: Option<CloseReason>,
}

impl FindingInterval {
    pub fn is_open(&self) -> bool {
        self.closed_at.is_none()
    }
}

/// Counts from one `record_pack_evaluation` call.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntervalStats {
    pub opened: u64,
    pub continued: u64,
    pub closed: u64,
}

/// Filter for `list_open_findings` and `GET /api/findings` (spec §4.4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingQuery {
    pub subscription_id: Option<String>,
    pub control_id: Option<String>,
    pub outcome: Option<EvalOutcome>,
    pub environment: Option<String>,
    /// `security` | `hygiene`, matched against the evidence `lane` (a missing lane is
    /// `security`, the pack default).
    pub lane: Option<String>,
    pub resource_id: Option<String>,
    pub limit: Option<i64>,
    /// Scope filter (invariant 13): only these subscriptions, case-insensitive. Set by the
    /// server from `tracked_subscription_ids`, never from the query string.
    #[serde(skip)]
    pub subscriptions: Option<Vec<String>>,
    /// Only these resources (inbox batch lookup). Server-side only.
    #[serde(skip)]
    pub resource_ids: Option<Vec<String>>,
}

/// Operator-facing triage of one interval at `now` (spec §3.2, invariants 9-11).
///
/// - Grace runs from `opened_at` of the interval, never from the latest re-evaluation.
/// - An open pass whose predecessor closed as `fail` with `state_changed` is
///   `VerifiedCorrected` (fresh passing evidence after a fail).
/// - The exception overlay applies last, to `fail` only.
pub fn triage_interval(
    f: &FindingInterval,
    exceptions: &[ExceptionRecord],
    now: DateTime<Utc>,
) -> TriageInfo {
    let hours = f.grace_period_hours;
    let base = |state, deadline, reason: String| TriageInfo {
        state,
        grace_deadline: deadline,
        grace_period_hours: hours,
        reason,
        exception_id: None,
        exception_expired: false,
    };
    let info = match f.outcome {
        EvalOutcome::Inapplicable => TriageInfo {
            grace_period_hours: None,
            ..base(TriageState::Inapplicable, None, "control not applicable".into())
        },
        EvalOutcome::Pass => {
            if f.is_open()
                && f.predecessor_outcome == Some(EvalOutcome::Fail)
                && f.predecessor_close_reason == Some(CloseReason::StateChanged)
            {
                base(
                    TriageState::VerifiedCorrected,
                    None,
                    format!(
                        "passing since {} after a prior fail",
                        f.opened_at.to_rfc3339()
                    ),
                )
            } else {
                base(TriageState::Pass, None, "passing evidence".into())
            }
        }
        EvalOutcome::Fail | EvalOutcome::Unknown => match hours {
            Some(h) => {
                let deadline = f.opened_at + Duration::hours(h as i64);
                if now < deadline {
                    base(
                        TriageState::AwaitingGrace,
                        Some(deadline),
                        format!("grace until {}", deadline.to_rfc3339()),
                    )
                } else {
                    base(
                        TriageState::Actionable,
                        Some(deadline),
                        format!("grace period elapsed at {}", deadline.to_rfc3339()),
                    )
                }
            }
            None if f.outcome == EvalOutcome::Fail => {
                base(TriageState::Actionable, None, "failing without grace".into())
            }
            None => base(TriageState::Unknown, None, "unknown evidence".into()),
        },
    };
    apply_exception(
        info,
        &f.outcome,
        &f.control_id,
        f.resource_id.as_str(),
        exceptions,
        now,
    )
}

/// Urgency rank of a triage state for sorting and "worst of" rollups (lower is more urgent).
pub fn triage_rank(state: &TriageState) -> u8 {
    match state {
        TriageState::Actionable => 0,
        TriageState::AwaitingGrace => 1,
        TriageState::Fail | TriageState::Unknown => 2,
        TriageState::Excepted => 3,
        TriageState::VerifiedCorrected => 4,
        TriageState::Pass => 5,
        TriageState::Inapplicable => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RID: &str = "/subscriptions/s/resourceGroups/rg/providers/x/y";

    fn interval(outcome: EvalOutcome, hours: Option<u64>, opened: DateTime<Utc>) -> FindingInterval {
        FindingInterval {
            id: "f1".into(),
            pack_id: "P".into(),
            pack_revision: "1".into(),
            clause_revision: "1".into(),
            resource_id: ResourceId::new(RID),
            subscription_id: SubscriptionId::new("s"),
            control_id: "FIN-014".into(),
            outcome,
            severity: Severity::Medium,
            environment: EnvironmentClass::Prod,
            detail: String::new(),
            evidence: json!({ "grace_period_hours": hours }),
            opened_at: opened,
            opened_scan_id: "scan-1".into(),
            // Re-evaluated every hour up to now: grace must not move with it.
            last_evaluated_at: Utc::now(),
            last_scan_id: "scan-9".into(),
            closed_at: None,
            close_reason: None,
            grace_period_hours: hours,
            predecessor_outcome: None,
            predecessor_close_reason: None,
        }
    }

    #[test]
    fn ac_p3_6_grace_runs_from_opened_at_not_latest_evaluation() {
        let now = Utc::now();
        let old = interval(EvalOutcome::Fail, Some(2), now - Duration::hours(5));
        let t = triage_interval(&old, &[], now);
        assert_eq!(t.state, TriageState::Actionable);
        assert_eq!(t.grace_deadline, Some(old.opened_at + Duration::hours(2)));

        let fresh = interval(EvalOutcome::Fail, Some(2), now - Duration::hours(1));
        assert_eq!(triage_interval(&fresh, &[], now).state, TriageState::AwaitingGrace);
    }

    #[test]
    fn ac_p3_2_pass_after_state_changed_fail_is_verified_corrected() {
        let now = Utc::now();
        let mut f = interval(EvalOutcome::Pass, Some(1), now - Duration::minutes(5));
        f.predecessor_outcome = Some(EvalOutcome::Fail);
        f.predecessor_close_reason = Some(CloseReason::StateChanged);
        assert_eq!(triage_interval(&f, &[], now).state, TriageState::VerifiedCorrected);

        // A fail closed by a pack revision change is not a correction.
        f.predecessor_close_reason = Some(CloseReason::PackRevision);
        assert_eq!(triage_interval(&f, &[], now).state, TriageState::Pass);

        // Nor is a pass after an unknown.
        f.predecessor_outcome = Some(EvalOutcome::Unknown);
        f.predecessor_close_reason = Some(CloseReason::StateChanged);
        assert_eq!(triage_interval(&f, &[], now).state, TriageState::Pass);
    }

    #[test]
    fn fail_without_grace_is_actionable_and_unknown_stays_unknown() {
        let now = Utc::now();
        let f = interval(EvalOutcome::Fail, None, now);
        assert_eq!(triage_interval(&f, &[], now).state, TriageState::Actionable);
        let u = interval(EvalOutcome::Unknown, None, now);
        assert_eq!(triage_interval(&u, &[], now).state, TriageState::Unknown);
        let i = interval(EvalOutcome::Inapplicable, Some(4), now);
        let t = triage_interval(&i, &[], now);
        assert_eq!(t.state, TriageState::Inapplicable);
        assert_eq!(t.grace_period_hours, None);
    }

    #[test]
    fn exception_overlay_applies_after_grace() {
        let now = Utc::now();
        let ex = ExceptionRecord {
            id: "EX-1".into(),
            control_id: "fin-014".into(),
            resource_id: None,
            subscription_id: Some("s".into()),
            resource_group: Some("RG".into()),
            reason: None,
            approved_by: None,
            ticket_ref: None,
            expires_at: None,
            created_at: now,
        };
        let f = interval(EvalOutcome::Fail, Some(2), now - Duration::hours(5));
        let t = triage_interval(&f, std::slice::from_ref(&ex), now);
        assert_eq!(t.state, TriageState::Excepted);
        assert_eq!(t.exception_id.as_deref(), Some("EX-1"));
        // Pass is untouched by the overlay.
        let p = interval(EvalOutcome::Pass, None, now);
        assert_eq!(triage_interval(&p, &[ex], now).state, TriageState::Pass);
    }

    #[test]
    fn close_reason_round_trips() {
        for r in CloseReason::ALL {
            assert_eq!(CloseReason::parse(r.as_str()), Some(r));
            assert_eq!(serde_json::to_value(r).unwrap(), json!(r.as_str()));
        }
        assert_eq!(CloseReason::parse("nope"), None);
    }

    #[test]
    fn triage_rank_puts_actionable_first() {
        assert!(triage_rank(&TriageState::Actionable) < triage_rank(&TriageState::Pass));
        assert!(triage_rank(&TriageState::AwaitingGrace) < triage_rank(&TriageState::VerifiedCorrected));
    }
}
