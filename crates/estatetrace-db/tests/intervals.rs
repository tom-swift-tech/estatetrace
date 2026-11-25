//! P3: finding intervals (spec §4.4, invariants 7-14, AC-P3-1..5, AC-P3-9).

use chrono::{DateTime, Duration, Utc};
use estatetrace_core::*;
use estatetrace_db as db;
use estatetrace_policy::PackEvaluation;
use serde_json::json;
use sqlx::SqlitePool;
use std::collections::HashSet;

const SUB_A: &str = "aaaaaaaa-0000-0000-0000-000000000001";
const SUB_B: &str = "bbbbbbbb-0000-0000-0000-000000000002";

fn rid(sub: &str, name: &str) -> String {
    format!("/subscriptions/{sub}/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/{name}")
}

fn ev(resource: &str, control: &str, outcome: EvalOutcome, at: DateTime<Utc>, scan: &str) -> Evaluation {
    Evaluation {
        id: format!("{scan}:{resource}:{control}"),
        observation_id: format!("obs-{scan}-{resource}"),
        resource_id: ResourceId::new(resource),
        control_id: control.into(),
        control_revision: "1".into(),
        outcome: outcome.clone(),
        severity: Severity::High,
        evidence: json!({
            "grace_period_hours": 2,
            "clause_revision": "c1",
            "lane": "security",
            "detail": format!("{} detail", outcome.as_str()),
        }),
        evaluated_at: at,
        environment: EnvironmentClass::Prod,
        detail: format!("{} detail", outcome.as_str()),
    }
}

fn result(evals: Vec<Evaluation>) -> PackEvaluation {
    PackEvaluation {
        evaluations: evals,
        coverage_gaps: Vec::new(),
    }
}

fn subs(ids: &[&str]) -> HashSet<SubscriptionId> {
    ids.iter().map(|s| SubscriptionId::new(*s)).collect()
}

async fn pool() -> (tempfile::TempDir, SqlitePool) {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("f.db")).await.unwrap();
    (dir, pool)
}

async fn count(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>(sql).fetch_one(pool).await.unwrap().0
}

/// Insert an observation row so the resource counts as "observed in `scan`".
async fn observe(pool: &SqlitePool, resource: &str, scan: &str) {
    let (sub, _) = arm_scope(resource);
    db::insert_observation(
        pool,
        &ResourceObservation {
            id: format!("obs-{scan}-{resource}"),
            provider: Provider::Azure,
            resource_id: ResourceId::new(resource),
            tenant_id: TenantId::new("t"),
            subscription_id: SubscriptionId::new(sub.unwrap()),
            resource_type: "Microsoft.Storage/storageAccounts".into(),
            name: "st".into(),
            location: None,
            resource_group: Some("rg-app".into()),
            tags: json!({}),
            properties: json!({}),
            scan_id: scan.into(),
            observation_time: Utc::now(),
            evidence_available: true,
            lifecycle_epoch: 1,
            arm_meta: json!({}),
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn migration_006_creates_findings_and_allows_pack_revisions() {
    let (_d, pool) = pool().await;
    assert!(db::schema_version(&pool).await.unwrap() >= 6);
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM finding_intervals").await, 0);
    // policy_packs is keyed by (id, revision): a second revision can be stored.
    db::save_policy_pack(&pool, "P", "Pack", "1", None, None, true, &json!({})).await.unwrap();
    db::save_policy_pack(&pool, "P", "Pack", "2", None, None, false, &json!({})).await.unwrap();
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM policy_packs WHERE id = 'P'").await, 2);
    let before = db::set_pack_active_revision(&pool, "P", Some("2")).await.unwrap();
    assert_eq!(before, vec!["1".to_string()]);
    let active = db::active_policy_packs(&pool).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0]["revision"], "2");
}

#[tokio::test]
async fn ac_p3_1_identical_scans_continue_one_interval() {
    let (_d, pool) = pool().await;
    let r = rid(SUB_A, "st1");
    let t0 = Utc::now() - Duration::hours(3);
    let complete = subs(&[SUB_A]);
    for (i, scan) in ["s1", "s2", "s3"].iter().enumerate() {
        let at = t0 + Duration::hours(i as i64);
        let stats = db::record_pack_evaluation(
            &pool,
            scan,
            "P",
            "1",
            &complete,
            &result(vec![ev(&r, "C-1", EvalOutcome::Fail, at, scan)]),
        )
        .await
        .unwrap();
        if i == 0 {
            assert_eq!(stats, IntervalStats { opened: 1, continued: 0, closed: 0 });
        } else {
            assert_eq!(stats, IntervalStats { opened: 0, continued: 1, closed: 0 });
        }
    }
    let rows = db::findings_for_resource(&pool, &r).await.unwrap();
    assert_eq!(rows.len(), 1);
    let f = &rows[0];
    assert_eq!(f.last_scan_id, "s3");
    assert_eq!(f.opened_scan_id, "s1");
    assert_eq!(f.opened_at, t0);
    assert_eq!(f.last_evaluated_at, t0 + Duration::hours(2));
    assert_eq!(f.pack_revision, "1");
    assert_eq!(f.clause_revision, "c1");
    assert_eq!(f.subscription_id.as_str(), SUB_A);
    assert_eq!(f.grace_period_hours, Some(2));
    assert!(f.is_open());

    // Invariant 7 / retry: recording the same scan again duplicates nothing.
    db::record_pack_evaluation(
        &pool,
        "s3",
        "P",
        "1",
        &complete,
        &result(vec![ev(&r, "C-1", EvalOutcome::Fail, t0 + Duration::hours(2), "s3")]),
    )
    .await
    .unwrap();
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM finding_intervals").await, 1);
}

#[tokio::test]
async fn ac_p3_2_fail_to_pass_closes_state_changed_and_triages_verified_corrected() {
    let (_d, pool) = pool().await;
    let r = rid(SUB_A, "st1");
    let t0 = Utc::now() - Duration::hours(3);
    let complete = subs(&[SUB_A]);
    db::record_pack_evaluation(&pool, "s1", "P", "1", &complete, &result(vec![ev(&r, "C-1", EvalOutcome::Fail, t0, "s1")]))
        .await
        .unwrap();
    let t1 = t0 + Duration::hours(1);
    let stats = db::record_pack_evaluation(&pool, "s2", "P", "1", &complete, &result(vec![ev(&r, "C-1", EvalOutcome::Pass, t1, "s2")]))
        .await
        .unwrap();
    assert_eq!(stats, IntervalStats { opened: 1, continued: 0, closed: 1 });

    let rows = db::findings_for_resource(&pool, &r).await.unwrap();
    assert_eq!(rows.len(), 2);
    let open = rows.iter().find(|f| f.is_open()).unwrap();
    let closed = rows.iter().find(|f| !f.is_open()).unwrap();
    assert_eq!(closed.outcome, EvalOutcome::Fail);
    assert_eq!(closed.close_reason, Some(CloseReason::StateChanged));
    assert_eq!(closed.closed_at, Some(t1), "old interval ends where the new one starts");
    assert_eq!(open.outcome, EvalOutcome::Pass);
    assert_eq!(open.opened_at, t1);
    assert_eq!(open.predecessor_outcome, Some(EvalOutcome::Fail));
    assert_eq!(open.predecessor_close_reason, Some(CloseReason::StateChanged));
    assert_eq!(triage_interval(open, &[], Utc::now()).state, TriageState::VerifiedCorrected);

    // The same through list_open_findings (inbox / summary reader).
    let open_rows = db::list_open_findings(&pool, &FindingQuery::default()).await.unwrap();
    assert_eq!(open_rows.len(), 1);
    assert_eq!(triage_interval(&open_rows[0], &[], Utc::now()).state, TriageState::VerifiedCorrected);
}

#[tokio::test]
async fn ac_p3_3_pack_revision_change_closes_with_pack_revision() {
    let (_d, pool) = pool().await;
    let r = rid(SUB_A, "st1");
    let t0 = Utc::now() - Duration::hours(3);
    let complete = subs(&[SUB_A]);
    db::record_pack_evaluation(&pool, "s1", "P", "1", &complete, &result(vec![ev(&r, "C-1", EvalOutcome::Fail, t0, "s1")]))
        .await
        .unwrap();
    // A second resource in a subscription that this scan does not visit: its old-revision
    // interval still closes, because the policy that produced it is gone.
    let other = rid(SUB_B, "st9");
    db::record_pack_evaluation(&pool, "s1b", "P", "1", &HashSet::new(), &result(vec![ev(&other, "C-1", EvalOutcome::Pass, t0, "s1b")]))
        .await
        .unwrap();

    let t1 = t0 + Duration::hours(1);
    let stats = db::record_pack_evaluation(&pool, "s2", "P", "2", &complete, &result(vec![ev(&r, "C-1", EvalOutcome::Fail, t1, "s2")]))
        .await
        .unwrap();
    assert_eq!(stats.closed, 2);
    assert_eq!(stats.opened, 1);

    let rows = db::findings_for_resource(&pool, &r).await.unwrap();
    let old = rows.iter().find(|f| f.pack_revision == "1").unwrap();
    let new = rows.iter().find(|f| f.pack_revision == "2").unwrap();
    assert_eq!(old.close_reason, Some(CloseReason::PackRevision));
    assert!(new.is_open());
    assert_eq!(new.outcome, EvalOutcome::Fail);
    assert_eq!(new.opened_scan_id, "s2");
    // A fail restarts its grace under the new revision; a pass after a revision close is
    // not a correction.
    let other_rows = db::findings_for_resource(&pool, &other).await.unwrap();
    assert_eq!(other_rows[0].close_reason, Some(CloseReason::PackRevision));
}

#[tokio::test]
async fn ac_p3_4_partial_scan_never_closes_unvisited_resources() {
    let (_d, pool) = pool().await;
    let visited = rid(SUB_A, "st1");
    let unvisited = rid(SUB_A, "st2");
    let t0 = Utc::now() - Duration::hours(3);
    let complete = subs(&[SUB_A]);
    db::record_pack_evaluation(
        &pool,
        "s1",
        "P",
        "1",
        &complete,
        &result(vec![
            ev(&visited, "C-1", EvalOutcome::Fail, t0, "s1"),
            ev(&unvisited, "C-1", EvalOutcome::Fail, t0, "s1"),
        ]),
    )
    .await
    .unwrap();
    // Scan 2 fails on page 2 of SUB_A: only page 1 (st1) was observed, and SUB_A is not in
    // the complete set.
    observe(&pool, &visited, "s2").await;
    let stats = db::record_pack_evaluation(
        &pool,
        "s2",
        "P",
        "1",
        &HashSet::new(),
        &result(vec![ev(&visited, "C-1", EvalOutcome::Fail, t0 + Duration::hours(1), "s2")]),
    )
    .await
    .unwrap();
    assert_eq!(stats.closed, 0);
    let still = db::findings_for_resource(&pool, &unvisited).await.unwrap();
    assert_eq!(still.len(), 1);
    assert!(still[0].is_open(), "unvisited resource keeps its open interval");
    assert_eq!(still[0].last_scan_id, "s1", "and shows a stale last_scan_id");
}

#[tokio::test]
async fn ac_p3_5_complete_scan_closes_missing_and_untargeted() {
    let (_d, pool) = pool().await;
    let gone = rid(SUB_A, "st-gone");
    let kept = rid(SUB_A, "st-kept");
    let untargeted = rid(SUB_A, "st-untargeted");
    let other_sub = rid(SUB_B, "st-other");
    let t0 = Utc::now() - Duration::hours(3);
    db::record_pack_evaluation(
        &pool,
        "s1",
        "P",
        "1",
        &subs(&[SUB_A, SUB_B]),
        &result(vec![
            ev(&gone, "C-1", EvalOutcome::Fail, t0, "s1"),
            ev(&kept, "C-1", EvalOutcome::Pass, t0, "s1"),
            ev(&untargeted, "C-1", EvalOutcome::Fail, t0, "s1"),
            ev(&other_sub, "C-1", EvalOutcome::Fail, t0, "s1"),
        ]),
    )
    .await
    .unwrap();

    // Scan 2: SUB_A completes from the beginning; `gone` is not observed, `untargeted` is
    // observed but no longer selected by C-1. SUB_B failed, so `other_sub` stays open.
    observe(&pool, &kept, "s2").await;
    observe(&pool, &untargeted, "s2").await;
    // Subscription IDs compare case-insensitively.
    let complete = subs(&[&SUB_A.to_uppercase()]);
    let stats = db::record_pack_evaluation(
        &pool,
        "s2",
        "P",
        "1",
        &complete,
        &result(vec![ev(&kept, "C-1", EvalOutcome::Pass, t0 + Duration::hours(1), "s2")]),
    )
    .await
    .unwrap();
    assert_eq!(stats, IntervalStats { opened: 0, continued: 1, closed: 2 });

    let reason = |rows: Vec<FindingInterval>| rows[0].close_reason;
    assert_eq!(
        reason(db::findings_for_resource(&pool, &gone).await.unwrap()),
        Some(CloseReason::ResourceMissing)
    );
    assert_eq!(
        reason(db::findings_for_resource(&pool, &untargeted).await.unwrap()),
        Some(CloseReason::NoLongerTargeted)
    );
    assert!(db::findings_for_resource(&pool, &other_sub).await.unwrap()[0].is_open());
    assert!(db::findings_for_resource(&pool, &kept).await.unwrap()[0].is_open());
}

#[tokio::test]
async fn ac_p3_9_close_findings_for_pack_deactivated() {
    let (_d, pool) = pool().await;
    let t0 = Utc::now();
    let r = rid(SUB_A, "st1");
    db::record_pack_evaluation(
        &pool,
        "s1",
        "P",
        "1",
        &subs(&[SUB_A]),
        &result(vec![
            ev(&r, "C-1", EvalOutcome::Fail, t0, "s1"),
            ev(&r, "C-2", EvalOutcome::Pass, t0, "s1"),
        ]),
    )
    .await
    .unwrap();
    db::record_pack_evaluation(&pool, "s1", "Q", "1", &subs(&[SUB_A]), &result(vec![ev(&r, "C-1", EvalOutcome::Fail, t0, "s1")]))
        .await
        .unwrap();
    let n = db::close_findings_for_pack(&pool, "P", CloseReason::PackDeactivated).await.unwrap();
    assert_eq!(n, 2);
    let rows = db::findings_for_resource(&pool, &r).await.unwrap();
    for f in rows.iter().filter(|f| f.pack_id == "P") {
        assert_eq!(f.close_reason, Some(CloseReason::PackDeactivated));
    }
    assert!(rows.iter().find(|f| f.pack_id == "Q").unwrap().is_open(), "other packs untouched");
    assert_eq!(db::close_findings_for_pack(&pool, "P", CloseReason::PackDeactivated).await.unwrap(), 0);
}

#[tokio::test]
async fn list_open_findings_filters_and_scopes() {
    let (_d, pool) = pool().await;
    let t0 = Utc::now();
    let a = rid(SUB_A, "st1");
    let b = rid(SUB_B, "st2");
    let mut hygiene = ev(&a, "TAG-1", EvalOutcome::Fail, t0, "s1");
    hygiene.evidence["lane"] = json!("hygiene");
    db::record_pack_evaluation(
        &pool,
        "s1",
        "P",
        "1",
        &HashSet::new(),
        &result(vec![
            ev(&a, "C-1", EvalOutcome::Fail, t0, "s1"),
            ev(&a, "C-2", EvalOutcome::Pass, t0, "s1"),
            hygiene,
            ev(&b, "C-1", EvalOutcome::Fail, t0, "s1"),
        ]),
    )
    .await
    .unwrap();
    let q = |f: fn(&mut FindingQuery)| {
        let mut q = FindingQuery::default();
        f(&mut q);
        q
    };
    let all = db::list_open_findings(&pool, &FindingQuery::default()).await.unwrap();
    assert_eq!(all.len(), 4);
    let scoped = db::list_open_findings(
        &pool,
        &FindingQuery { subscriptions: Some(vec![SUB_A.to_uppercase()]), ..Default::default() },
    )
    .await
    .unwrap();
    assert_eq!(scoped.len(), 3, "scope filter is case-insensitive and drops SUB_B");
    let empty_scope = db::list_open_findings(
        &pool,
        &FindingQuery { subscriptions: Some(vec![]), ..Default::default() },
    )
    .await
    .unwrap();
    assert!(empty_scope.is_empty(), "an empty tracked scope shows nothing");
    let fails = db::list_open_findings(&pool, &q(|q| q.outcome = Some(EvalOutcome::Fail))).await.unwrap();
    assert_eq!(fails.len(), 3);
    let security = db::list_open_findings(&pool, &q(|q| q.lane = Some("security".into()))).await.unwrap();
    assert_eq!(security.len(), 3);
    let c1 = db::list_open_findings(&pool, &q(|q| q.control_id = Some("C-1".into()))).await.unwrap();
    assert_eq!(c1.len(), 2);
    let limited = db::list_open_findings(&pool, &q(|q| q.limit = Some(1))).await.unwrap();
    assert_eq!(limited.len(), 1);
    let batch = db::list_open_findings(
        &pool,
        &FindingQuery { resource_ids: Some(vec![b.clone()]), ..Default::default() },
    )
    .await
    .unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].resource_id.as_str(), b);
}

#[tokio::test]
async fn failed_write_rolls_back_the_whole_pack_and_retry_duplicates_nothing() {
    let (_d, pool) = pool().await;
    let t0 = Utc::now() - Duration::hours(2);
    let a = rid(SUB_A, "st1");
    let boom = rid(SUB_A, "boom");
    let complete = subs(&[SUB_A]);
    db::record_pack_evaluation(&pool, "s1", "P", "1", &complete, &result(vec![ev(&a, "C-1", EvalOutcome::Fail, t0, "s1")]))
        .await
        .unwrap();
    // Fail the insert step, after the close and continue steps already ran in the transaction.
    sqlx::query(
        "CREATE TRIGGER boom BEFORE INSERT ON finding_intervals
         WHEN NEW.resource_id LIKE '%/boom' BEGIN SELECT RAISE(ABORT, 'boom'); END",
    )
    .execute(&pool)
    .await
    .unwrap();
    let scan2 = result(vec![
        ev(&a, "C-1", EvalOutcome::Pass, t0 + Duration::hours(1), "s2"),
        ev(&boom, "C-1", EvalOutcome::Fail, t0 + Duration::hours(1), "s2"),
    ]);
    assert!(db::record_pack_evaluation(&pool, "s2", "P", "1", &complete, &scan2).await.is_err());
    let rows = db::findings_for_resource(&pool, &a).await.unwrap();
    assert_eq!(rows.len(), 1, "state_changed close rolled back");
    assert!(rows[0].is_open());
    assert_eq!(rows[0].last_scan_id, "s1");

    // The next attempt succeeds, and a retry of it writes each interval once.
    sqlx::query("DROP TRIGGER boom").execute(&pool).await.unwrap();
    db::record_pack_evaluation(&pool, "s2", "P", "1", &complete, &scan2).await.unwrap();
    db::record_pack_evaluation(&pool, "s2", "P", "1", &complete, &scan2).await.unwrap();
    assert_eq!(count(&pool, "SELECT COUNT(*) FROM finding_intervals").await, 3);
    assert_eq!(
        count(&pool, "SELECT COUNT(*) FROM finding_intervals WHERE closed_at IS NULL").await,
        2
    );
}

#[tokio::test]
async fn coverage_gaps_are_written_with_the_intervals() {
    let (_d, pool) = pool().await;
    let gap = CoverageGap {
        pack_id: "P".into(),
        control_id: "C-9".into(),
        category: GapCategory::OutsideAzure,
        note: "records".into(),
        resource_type: None,
        resource_count: 0,
    };
    let res = PackEvaluation { evaluations: vec![], coverage_gaps: vec![gap.clone()] };
    db::record_pack_evaluation(&pool, "s1", "P", "1", &HashSet::new(), &res).await.unwrap();
    assert_eq!(db::list_coverage_gaps(&pool, Some("P")).await.unwrap(), vec![gap]);
}
