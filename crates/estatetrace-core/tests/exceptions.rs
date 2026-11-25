//! P2: scoped exception overlay (spec §4.5, invariants 10–11, AC-P2-1..3).

use chrono::{DateTime, Duration, Utc};
use estatetrace_core::*;

const SUB: &str = "11111111-2222-3333-4444-555555555555";
const OTHER_SUB: &str = "99999999-2222-3333-4444-555555555555";

fn rid(sub: &str, rg: &str, name: &str) -> String {
    format!("/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}")
}

fn ex(id: &str, control: &str) -> ExceptionRecord {
    ExceptionRecord {
        id: id.into(),
        control_id: control.into(),
        resource_id: None,
        subscription_id: None,
        resource_group: None,
        reason: Some("approved".into()),
        approved_by: Some("approver".into()),
        ticket_ref: Some("CHG0001".into()),
        expires_at: None,
        created_at: Utc::now() - Duration::days(30),
    }
}

fn scoped(id: &str, control: &str, sub: &str, rg: Option<&str>) -> ExceptionRecord {
    ExceptionRecord {
        subscription_id: Some(sub.into()),
        resource_group: rg.map(Into::into),
        ..ex(id, control)
    }
}

fn base(state: TriageState) -> TriageInfo {
    TriageInfo {
        state,
        grace_deadline: None,
        grace_period_hours: None,
        reason: "base".into(),
        exception_id: None,
        exception_expired: false,
    }
}

fn overlay(outcome: EvalOutcome, control: &str, resource: &str, exs: &[ExceptionRecord], now: DateTime<Utc>) -> TriageInfo {
    let state = match outcome {
        EvalOutcome::Fail => TriageState::Actionable,
        EvalOutcome::Pass => TriageState::Pass,
        EvalOutcome::Unknown => TriageState::Unknown,
        EvalOutcome::Inapplicable => TriageState::Inapplicable,
    };
    apply_exception(base(state), &outcome, control, resource, exs, now)
}

#[test]
fn ac_p2_1_subscription_and_rg_scope_excepts_only_that_group() {
    let now = Utc::now();
    let exs = vec![scoped("EXC-1", "STG-001", SUB, Some("rg-app"))];

    let inside = overlay(EvalOutcome::Fail, "STG-001", &rid(SUB, "rg-app", "st1"), &exs, now);
    assert_eq!(inside.state, TriageState::Excepted);
    assert_eq!(inside.exception_id.as_deref(), Some("EXC-1"));
    assert!(!inside.exception_expired);

    let other_rg = overlay(EvalOutcome::Fail, "STG-001", &rid(SUB, "rg-other", "st2"), &exs, now);
    assert_eq!(other_rg.state, TriageState::Actionable);
    assert_eq!(other_rg.exception_id, None);

    // Invariant 10: a different control on the same resource is not excepted.
    let other_control = overlay(EvalOutcome::Fail, "STG-002", &rid(SUB, "rg-app", "st1"), &exs, now);
    assert_eq!(other_control.state, TriageState::Actionable);
}

#[test]
fn ac_p2_1_matching_is_case_insensitive() {
    let now = Utc::now();
    let exs = vec![scoped("EXC-1", "STG-001", &SUB.to_uppercase(), Some("RG-APP"))];
    let id = rid(SUB, "rg-app", "st1").replace("resourceGroups", "RESOURCEGROUPS");
    assert_eq!(overlay(EvalOutcome::Fail, "STG-001", &id, &exs, now).state, TriageState::Excepted);
}

#[test]
fn ac_p2_1_subscription_only_scope_covers_every_group() {
    let now = Utc::now();
    let exs = vec![scoped("EXC-2", "STG-001", SUB, None)];
    assert_eq!(overlay(EvalOutcome::Fail, "STG-001", &rid(SUB, "a", "x"), &exs, now).state, TriageState::Excepted);
    assert_eq!(overlay(EvalOutcome::Fail, "STG-001", &rid(SUB, "b", "y"), &exs, now).state, TriageState::Excepted);
    assert_eq!(
        overlay(EvalOutcome::Fail, "STG-001", &rid(OTHER_SUB, "a", "x"), &exs, now).state,
        TriageState::Actionable
    );
}

#[test]
fn resource_scope_is_exact_case_insensitive_match() {
    let now = Utc::now();
    let target = rid(SUB, "rg-app", "st1");
    let exs = vec![ExceptionRecord {
        resource_id: Some(target.to_uppercase()),
        // Ignored when resource_id is set.
        subscription_id: Some(OTHER_SUB.into()),
        ..ex("EXC-3", "STG-001")
    }];
    assert_eq!(overlay(EvalOutcome::Fail, "STG-001", &target, &exs, now).state, TriageState::Excepted);
    assert_eq!(
        overlay(EvalOutcome::Fail, "STG-001", &rid(SUB, "rg-app", "st2"), &exs, now).state,
        TriageState::Actionable
    );
    // A resource-scoped exception never widens to the subscription.
    assert!(find_exception(&exs, "STG-001", &rid(OTHER_SUB, "rg-app", "st1")).is_none());
}

#[test]
fn ac_p2_2_expired_exception_stays_actionable_and_is_flagged() {
    let now = Utc::now();
    let exs = vec![ExceptionRecord {
        expires_at: Some(now - Duration::days(1)),
        ..scoped("EXC-OLD", "STG-001", SUB, Some("rg-app"))
    }];
    let t = overlay(EvalOutcome::Fail, "STG-001", &rid(SUB, "rg-app", "st1"), &exs, now);
    assert_eq!(t.state, TriageState::Actionable);
    assert!(t.exception_expired);
    assert_eq!(t.exception_id.as_deref(), Some("EXC-OLD"));
    assert!(t.reason.contains("EXC-OLD"), "reason names the exception: {}", t.reason);
}

#[test]
fn expiry_boundary_and_active_wins_over_expired() {
    let now = Utc::now();
    let at_now = ExceptionRecord { expires_at: Some(now), ..scoped("EXC-EDGE", "C", SUB, None) };
    assert!(at_now.is_active(now), "expiry == now is still active");

    let exs = vec![
        ExceptionRecord { expires_at: Some(now - Duration::hours(1)), ..scoped("EXC-OLD", "C", SUB, None) },
        ExceptionRecord { expires_at: Some(now + Duration::days(10)), ..scoped("EXC-NEW", "C", SUB, Some("rg")) },
    ];
    let t = overlay(EvalOutcome::Fail, "C", &rid(SUB, "rg", "x"), &exs, now);
    assert_eq!(t.state, TriageState::Excepted);
    assert_eq!(t.exception_id.as_deref(), Some("EXC-NEW"));
    // find_exception is the plain port: first match regardless of expiry.
    assert_eq!(find_exception(&exs, "C", &rid(SUB, "rg", "x")).unwrap().id, "EXC-OLD");
}

#[test]
fn ac_p2_3_overlay_applies_to_fail_only() {
    let now = Utc::now();
    let exs = vec![scoped("EXC-1", "STG-001", SUB, None)];
    let id = rid(SUB, "rg-app", "st1");
    let pass = overlay(EvalOutcome::Pass, "STG-001", &id, &exs, now);
    assert_eq!(pass.state, TriageState::Pass);
    assert_eq!(pass.exception_id, None);
    assert_eq!(overlay(EvalOutcome::Unknown, "STG-001", &id, &exs, now).state, TriageState::Unknown);
    assert_eq!(
        overlay(EvalOutcome::Inapplicable, "STG-001", &id, &exs, now).state,
        TriageState::Inapplicable
    );
}

#[test]
fn overlay_keeps_grace_fields() {
    let now = Utc::now();
    let exs = vec![scoped("EXC-1", "C", SUB, None)];
    let info = TriageInfo {
        state: TriageState::AwaitingGrace,
        grace_deadline: Some(now + Duration::hours(2)),
        grace_period_hours: Some(4),
        reason: "grace".into(),
        exception_id: None,
        exception_expired: false,
    };
    let t = apply_exception(info, &EvalOutcome::Fail, "C", &rid(SUB, "rg", "x"), &exs, now);
    assert_eq!(t.state, TriageState::Excepted);
    assert_eq!(t.grace_period_hours, Some(4));
}

#[test]
fn arm_scope_parses_subscription_and_group() {
    assert_eq!(arm_scope(&rid(SUB, "rg-app", "st1")), (Some(SUB), Some("rg-app")));
    assert_eq!(
        arm_scope("/SUBSCRIPTIONS/abc/RESOURCEGROUPS/Rg/providers/x/y/z"),
        (Some("abc"), Some("Rg"))
    );
    assert_eq!(arm_scope("/subscriptions/abc/providers/Microsoft.Foo/bar/b"), (Some("abc"), None));
    assert_eq!(arm_scope("not-an-arm-id"), (None, None));
    assert_eq!(arm_scope(""), (None, None));
}

#[test]
fn empty_scope_detection() {
    assert!(ex("E", "C").scope_is_empty());
    assert!(ExceptionRecord { resource_id: Some("  ".into()), ..ex("E", "C") }.scope_is_empty());
    assert!(!scoped("E", "C", SUB, None).scope_is_empty());
    // An empty-scope record never matches anything.
    assert!(find_exception(&[ex("E", "C")], "C", &rid(SUB, "rg", "x")).is_none());
}

#[test]
fn triage_state_serializes_as_excepted() {
    assert_eq!(TriageState::Excepted.as_str(), "excepted");
    assert_eq!(serde_json::to_value(TriageState::Excepted).unwrap(), "excepted");
}
