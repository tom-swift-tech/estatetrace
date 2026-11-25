//! Finding triage: grace → actionable → verified corrected (UI-02 / AC-07).

use crate::{EvalOutcome, Evaluation};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

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

/// Compute operator-facing triage from a single evaluation at `now`.
pub fn triage_evaluation(ev: &Evaluation, now: DateTime<Utc>) -> TriageInfo {
    match ev.outcome {
        EvalOutcome::Inapplicable => TriageInfo {
            state: TriageState::Inapplicable,
            grace_deadline: None,
            grace_period_hours: None,
            reason: "control not applicable".into(),
            exception_id: None,
            exception_expired: false,
        },
        EvalOutcome::Pass => TriageInfo {
            state: TriageState::Pass,
            grace_deadline: None,
            grace_period_hours: grace_hours(ev),
            reason: "passing evidence".into(),
            exception_id: None,
            exception_expired: false,
        },
        EvalOutcome::Fail | EvalOutcome::Unknown => {
            let hours = grace_hours(ev);
            if let Some(h) = hours {
                let deadline = ev.evaluated_at + Duration::hours(h as i64);
                if now < deadline {
                    return TriageInfo {
                        state: TriageState::AwaitingGrace,
                        grace_deadline: Some(deadline),
                        grace_period_hours: hours,
                        reason: format!("grace until {}", deadline.to_rfc3339()),
                        exception_id: None,
                        exception_expired: false,
                    };
                }
                return TriageInfo {
                    state: TriageState::Actionable,
                    grace_deadline: Some(deadline),
                    grace_period_hours: hours,
                    reason: "grace period elapsed".into(),
                    exception_id: None,
                    exception_expired: false,
                };
            }
            TriageInfo {
                state: if ev.outcome == EvalOutcome::Fail {
                    TriageState::Actionable
                } else {
                    TriageState::Unknown
                },
                grace_deadline: None,
                grace_period_hours: None,
                reason: if ev.outcome == EvalOutcome::Fail {
                    "failing without grace".into()
                } else {
                    "unknown evidence".into()
                },
                exception_id: None,
                exception_expired: false,
            }
        }
    }
}

/// Latest eval wins; a fresh Pass after an earlier Fail for the same control
/// becomes verified_corrected.
pub fn triage_with_history(evals: &[Evaluation], now: DateTime<Utc>) -> Option<TriageInfo> {
    if evals.is_empty() {
        return None;
    }
    let mut sorted = evals.to_vec();
    sorted.sort_by(|a, b| a.evaluated_at.cmp(&b.evaluated_at));
    let latest = sorted.last()?;
    let mut info = triage_evaluation(latest, now);
    if latest.outcome == EvalOutcome::Pass {
        let had_fail = sorted.iter().any(|e| {
            e.control_id == latest.control_id && e.outcome == EvalOutcome::Fail
        });
        if had_fail {
            info.state = TriageState::VerifiedCorrected;
            info.reason = "fresh passing evidence after prior fail".into();
        }
    }
    Some(info)
}

/// `triage_with_history` plus the exception overlay, keyed on the latest evaluation's
/// outcome and control. Interim helper until P3's `triage_interval` replaces both.
pub fn triage_with_exceptions(
    evals: &[Evaluation],
    exceptions: &[ExceptionRecord],
    now: DateTime<Utc>,
) -> Option<TriageInfo> {
    let info = triage_with_history(evals, now)?;
    // Same pick as triage_with_history: the last of the latest evaluations.
    let latest = evals.iter().max_by(|a, b| a.evaluated_at.cmp(&b.evaluated_at))?;
    Some(apply_exception(
        info,
        &latest.outcome,
        &latest.control_id,
        latest.resource_id.as_str(),
        exceptions,
        now,
    ))
}

fn grace_hours(ev: &Evaluation) -> Option<u64> {
    ev.evidence
        .get("grace_period_hours")
        .and_then(|v| v.as_u64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ResourceId, Severity};
    use serde_json::json;
    use uuid::Uuid;

    fn ev(outcome: EvalOutcome, hours: Option<u64>, at: DateTime<Utc>) -> Evaluation {
        Evaluation {
            id: Uuid::new_v4().to_string(),
            observation_id: "o1".into(),
            resource_id: ResourceId::new("/subscriptions/s/resourceGroups/rg/providers/x/y"),
            control_id: "FIN-014".into(),
            control_revision: "1".into(),
            outcome,
            severity: Severity::Medium,
            evidence: json!({ "grace_period_hours": hours }),
            evaluated_at: at,
            environment: crate::EnvironmentClass::Unknown,
            detail: String::new(),
        }
    }

    #[test]
    fn ac07_grace_becomes_actionable_after_deadline() {
        let start = Utc::now() - Duration::hours(5);
        let failing = ev(EvalOutcome::Fail, Some(2), start);
        let info = triage_evaluation(&failing, Utc::now());
        assert_eq!(info.state, TriageState::Actionable);
    }

    #[test]
    fn ac07_within_grace_awaits() {
        let start = Utc::now() - Duration::hours(1);
        let failing = ev(EvalOutcome::Fail, Some(24), start);
        let info = triage_evaluation(&failing, Utc::now());
        assert_eq!(info.state, TriageState::AwaitingGrace);
    }

    #[test]
    fn ac07_verified_corrected_after_fresh_pass() {
        let t0 = Utc::now() - Duration::hours(3);
        let t1 = Utc::now() - Duration::minutes(5);
        let history = vec![
            ev(EvalOutcome::Fail, Some(1), t0),
            ev(EvalOutcome::Pass, Some(1), t1),
        ];
        let info = triage_with_history(&history, Utc::now()).unwrap();
        assert_eq!(info.state, TriageState::VerifiedCorrected);
    }
}
