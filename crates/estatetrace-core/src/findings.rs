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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageInfo {
    pub state: TriageState,
    pub grace_deadline: Option<DateTime<Utc>>,
    pub grace_period_hours: Option<u64>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionRecord {
    pub id: String,
    pub resource_id: String,
    pub control_id: String,
    pub reason: Option<String>,
    pub approved_by: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
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
        },
        EvalOutcome::Pass => TriageInfo {
            state: TriageState::Pass,
            grace_deadline: None,
            grace_period_hours: grace_hours(ev),
            reason: "passing evidence".into(),
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
                    };
                }
                return TriageInfo {
                    state: TriageState::Actionable,
                    grace_deadline: Some(deadline),
                    grace_period_hours: hours,
                    reason: "grace period elapsed".into(),
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
