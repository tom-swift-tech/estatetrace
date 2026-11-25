//! P6: reporting reads over finding intervals (spec §4.7, AC-P6-1..4, AC-P6-6).

use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use estatetrace_core::*;
use estatetrace_db as db;
use estatetrace_policy::{Lane, PackEvaluation};
use serde_json::json;
use sqlx::SqlitePool;
use std::collections::HashSet;

const SUB_A: &str = "aaaaaaaa-0000-0000-0000-000000000001";
const SUB_B: &str = "bbbbbbbb-0000-0000-0000-000000000002";

fn rid(sub: &str, name: &str) -> String {
    format!("/subscriptions/{sub}/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/{name}")
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 10, 12, 0, 0).unwrap()
}

fn ev(resource: &str, control: &str, outcome: EvalOutcome, at: DateTime<Utc>, lane: &str) -> Evaluation {
    Evaluation {
        id: format!("{resource}:{control}"),
        observation_id: format!("obs-{resource}"),
        resource_id: ResourceId::new(resource),
        control_id: control.into(),
        control_revision: "1".into(),
        outcome,
        severity: Severity::High,
        evidence: json!({ "clause_revision": "c1", "lane": lane }),
        evaluated_at: at,
        environment: EnvironmentClass::Prod,
        detail: String::new(),
    }
}

async fn pool() -> (tempfile::TempDir, SqlitePool) {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("r.db")).await.unwrap();
    (dir, pool)
}

async fn record(pool: &SqlitePool, scan: &str, evals: Vec<Evaluation>) {
    db::record_pack_evaluation(
        pool,
        scan,
        "PACK",
        "1",
        &HashSet::new(),
        &PackEvaluation {
            evaluations: evals,
            coverage_gaps: Vec::new(),
        },
    )
    .await
    .unwrap();
}

fn scope(subs: &[&str], lane: Option<&str>) -> db::ReportScope {
    db::ReportScope::new(subs.iter().map(|s| s.to_string()).collect(), lane)
}

async fn insert_scan(pool: &SqlitePool, id: &str, started: DateTime<Utc>, finished: DateTime<Utc>) {
    sqlx::query(
        "INSERT INTO scan_runs(id, source, started_at, finished_at, completeness, error)
         VALUES(?, 'test', ?, ?, 'complete', NULL)",
    )
    .bind(id)
    .bind(started.to_rfc3339())
    .bind(finished.to_rfc3339())
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn ac_p6_1_queue_lane_security_excludes_hygiene() {
    let (_d, pool) = pool().await;
    record(
        &pool,
        "s1",
        vec![
            ev(&rid(SUB_A, "a"), "SEC-1", EvalOutcome::Fail, t0(), "security"),
            ev(&rid(SUB_A, "b"), "SEC-1", EvalOutcome::Fail, t0(), "security"),
            ev(&rid(SUB_A, "a"), "TAG-1", EvalOutcome::Fail, t0(), "hygiene"),
            ev(&rid(SUB_A, "c"), "SEC-2", EvalOutcome::Pass, t0(), "security"),
        ],
    )
    .await;
    let sec = db::compliance_queue(&pool, &scope(&[SUB_A], Some("security")), false, None)
        .await
        .unwrap();
    assert_eq!(sec.len(), 1, "{sec:?}");
    assert_eq!(sec[0].control_id, "SEC-1");
    assert_eq!(sec[0].lane, Lane::Security);
    assert_eq!(sec[0].count, 2);
    assert_eq!(sec[0].subscriptions, 1);
    assert_eq!(sec[0].group_key, "");
    assert_eq!(sec[0].environment, "prod");
    assert_eq!(sec[0].oldest_opened_at, t0());

    let hyg = db::compliance_queue(&pool, &scope(&[SUB_A], Some("hygiene")), false, None)
        .await
        .unwrap();
    assert_eq!(hyg.len(), 1);
    assert_eq!(hyg[0].control_id, "TAG-1");
    assert_eq!(hyg[0].lane, Lane::Hygiene);

    let both = db::compliance_queue(&pool, &scope(&[SUB_A], None), false, None)
        .await
        .unwrap();
    assert_eq!(both.len(), 2);

    // The Rust aggregation path (ownership grouping) applies the same lane filter.
    let rows = db::open_fail_resources(&pool, &scope(&[SUB_A], Some("security")))
        .await
        .unwrap();
    assert!(rows.iter().all(|r| r.lane == Lane::Security));
    let agg = db::aggregate_queue(&rows, None, |_| String::new());
    assert_eq!(agg, sec);
}

#[tokio::test]
async fn ac_p6_1_missing_lane_counts_as_security() {
    let (_d, pool) = pool().await;
    let mut e = ev(&rid(SUB_A, "a"), "OLD-1", EvalOutcome::Fail, t0(), "security");
    e.evidence = json!({ "clause_revision": "c1" });
    record(&pool, "s1", vec![e]).await;
    let sec = db::compliance_queue(&pool, &scope(&[SUB_A], Some("security")), false, None)
        .await
        .unwrap();
    assert_eq!(sec.len(), 1);
}

#[tokio::test]
async fn ac_p6_2_new_since_last_visit_counts_opened_after_visit() {
    let (_d, pool) = pool().await;
    let visit = t0();
    record(
        &pool,
        "s1",
        vec![
            ev(&rid(SUB_A, "old"), "SEC-1", EvalOutcome::Fail, visit - Duration::hours(2), "security"),
            ev(&rid(SUB_A, "at"), "SEC-1", EvalOutcome::Fail, visit, "security"),
            ev(&rid(SUB_A, "new1"), "SEC-1", EvalOutcome::Fail, visit + Duration::seconds(1), "security"),
            ev(&rid(SUB_B, "new2"), "SEC-1", EvalOutcome::Fail, visit + Duration::hours(3), "security"),
        ],
    )
    .await;
    let q = db::compliance_queue(&pool, &scope(&[SUB_A, SUB_B], None), false, Some(visit))
        .await
        .unwrap();
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].count, 4);
    assert_eq!(q[0].subscriptions, 2);
    assert_eq!(q[0].new_since_last_visit, 2, "strictly after the visit");
    assert_eq!(q[0].oldest_opened_at, visit - Duration::hours(2));

    // Same rule in the Rust aggregation used for ownership grouping.
    let rows = db::open_fail_resources(&pool, &scope(&[SUB_A, SUB_B], None)).await.unwrap();
    let agg = db::aggregate_queue(&rows, Some(visit), |_| String::new());
    assert_eq!(agg[0].new_since_last_visit, 2);
    assert_eq!(agg[0].subscriptions, 2);

    // No recorded visit: every open fail is new (inbox convention).
    let q = db::compliance_queue(&pool, &scope(&[SUB_A, SUB_B], None), false, None)
        .await
        .unwrap();
    assert_eq!(q[0].new_since_last_visit, 4);

    // Grouping by subscription in SQL.
    let by_sub = db::compliance_queue(&pool, &scope(&[SUB_A, SUB_B], None), true, Some(visit))
        .await
        .unwrap();
    assert_eq!(by_sub.len(), 2);
    let a = by_sub.iter().find(|r| r.group_key == SUB_A).unwrap();
    assert_eq!((a.count, a.new_since_last_visit, a.subscriptions), (3, 1, 1));
}

#[tokio::test]
async fn ac_p6_3_aging_buckets_are_inclusive_on_the_upper_bound() {
    let (_d, pool) = pool().await;
    let now = t0();
    let ages = [0i64, 7, 8, 30, 31, 90, 91];
    let evals = ages
        .iter()
        .map(|d| {
            ev(
                &rid(SUB_A, &format!("r{d}")),
                "SEC-1",
                EvalOutcome::Fail,
                now - Duration::days(*d),
                "security",
            )
        })
        .collect();
    record(&pool, "s1", evals).await;
    let rows = db::compliance_aging(&pool, &scope(&[SUB_A], None), now).await.unwrap();
    let got: Vec<(&str, u64)> = rows.iter().map(|r| (r.bucket.as_str(), r.count)).collect();
    assert_eq!(got, vec![("0-7", 2), ("8-30", 2), ("31-90", 2), ("90+", 1)]);

    // Exactly 7 days -> 0-7 and exactly 8 days -> 8-30, on their own.
    let (_d2, pool2) = pool_with(&[(7, "r7")]).await;
    let r = db::compliance_aging(&pool2, &scope(&[SUB_A], None), now).await.unwrap();
    assert_eq!(r[0].bucket, "0-7");
    let (_d3, pool3) = pool_with(&[(8, "r8")]).await;
    let r = db::compliance_aging(&pool3, &scope(&[SUB_A], None), now).await.unwrap();
    assert_eq!(r[0].bucket, "8-30");
}

async fn pool_with(ages: &[(i64, &str)]) -> (tempfile::TempDir, SqlitePool) {
    let (d, p) = pool().await;
    let evals = ages
        .iter()
        .map(|(days, name)| {
            ev(&rid(SUB_A, name), "SEC-1", EvalOutcome::Fail, t0() - Duration::days(*days), "security")
        })
        .collect();
    record(&p, "s1", evals).await;
    (d, p)
}

#[tokio::test]
async fn ac_p6_4_flow_counts_opened_and_closed_fail_intervals_per_day() {
    let (_d, pool) = pool().await;
    let day = t0();
    // Three fails open on the day; one passing interval also opens (not counted).
    record(
        &pool,
        "s1",
        vec![
            ev(&rid(SUB_A, "a"), "SEC-1", EvalOutcome::Fail, day, "security"),
            ev(&rid(SUB_A, "b"), "SEC-1", EvalOutcome::Fail, day, "security"),
            ev(&rid(SUB_A, "c"), "SEC-1", EvalOutcome::Fail, day, "security"),
            ev(&rid(SUB_A, "d"), "SEC-1", EvalOutcome::Pass, day, "security"),
        ],
    )
    .await;
    // Later the same day `a` passes: its fail interval closes. `d` fails: its pass interval
    // closes (not a fail close) and a fail opens the next day.
    record(
        &pool,
        "s2",
        vec![
            ev(&rid(SUB_A, "a"), "SEC-1", EvalOutcome::Pass, day + Duration::hours(2), "security"),
            ev(&rid(SUB_A, "b"), "SEC-1", EvalOutcome::Fail, day + Duration::hours(2), "security"),
            ev(&rid(SUB_A, "c"), "SEC-1", EvalOutcome::Fail, day + Duration::hours(2), "security"),
        ],
    )
    .await;
    record(
        &pool,
        "s3",
        vec![ev(&rid(SUB_A, "d"), "SEC-1", EvalOutcome::Fail, day + Duration::days(1), "security")],
    )
    .await;
    let now = day + Duration::days(1);
    let rows = db::compliance_flow(&pool, &scope(&[SUB_A], None), 90, now).await.unwrap();
    let d0 = day.date_naive();
    let first = rows.iter().find(|r| r.day == d0).unwrap();
    assert_eq!((first.opened, first.closed), (3, 1), "{rows:?}");
    let next = rows.iter().find(|r| r.day == d0.succ_opt().unwrap()).unwrap();
    assert_eq!((next.opened, next.closed), (1, 0));

    // The window ends `days` back, inclusive of today.
    let rows = db::compliance_flow(&pool, &scope(&[SUB_A], None), 1, now).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].day, NaiveDate::from_ymd_opt(2026, 3, 11).unwrap());
}

#[tokio::test]
async fn trend_counts_open_fails_at_each_finished_scan() {
    let (_d, pool) = pool().await;
    let s1 = t0();
    record(
        &pool,
        "s1",
        vec![
            ev(&rid(SUB_A, "a"), "SEC-1", EvalOutcome::Fail, s1 + Duration::minutes(1), "security"),
            ev(&rid(SUB_A, "b"), "SEC-1", EvalOutcome::Fail, s1 + Duration::minutes(1), "security"),
            ev(&rid(SUB_A, "b"), "TAG-1", EvalOutcome::Fail, s1 + Duration::minutes(1), "hygiene"),
        ],
    )
    .await;
    insert_scan(&pool, "s1", s1, s1 + Duration::minutes(5)).await;
    let s2 = s1 + Duration::hours(1);
    record(
        &pool,
        "s2",
        vec![
            ev(&rid(SUB_A, "a"), "SEC-1", EvalOutcome::Pass, s2 + Duration::minutes(1), "security"),
            ev(&rid(SUB_A, "b"), "SEC-1", EvalOutcome::Fail, s2 + Duration::minutes(1), "security"),
        ],
    )
    .await;
    insert_scan(&pool, "s2", s2, s2 + Duration::minutes(5)).await;

    let rows = db::compliance_trend(&pool, &scope(&[SUB_A], Some("security")), db::TREND_SCANS)
        .await
        .unwrap();
    let got: Vec<(&str, &str, u64)> = rows
        .iter()
        .map(|r| (r.scan_id.as_str(), r.control_id.as_str(), r.open))
        .collect();
    assert_eq!(got, vec![("s1", "SEC-1", 2), ("s2", "SEC-1", 1)]);

    let all = db::compliance_trend(&pool, &scope(&[SUB_A], None), db::TREND_SCANS)
        .await
        .unwrap();
    assert!(all.iter().any(|r| r.control_id == "TAG-1" && r.lane == Lane::Hygiene));

    let scans = db::trend_scans(&pool, 1).await.unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].scan_id, "s2", "newest scans are kept");
}

#[tokio::test]
async fn ac_p6_6_every_reporting_query_is_scoped_and_empty_scope_is_empty() {
    let (_d, pool) = pool().await;
    let at = t0();
    record(
        &pool,
        "s1",
        vec![
            ev(&rid(SUB_A, "a"), "SEC-1", EvalOutcome::Fail, at, "security"),
            ev(&rid(SUB_B, "b"), "SEC-OUT", EvalOutcome::Fail, at, "security"),
        ],
    )
    .await;
    insert_scan(&pool, "s1", at - Duration::minutes(1), at + Duration::minutes(5)).await;
    let now = at + Duration::days(1);
    // Scope matches case-insensitively.
    let only_a = scope(&[&SUB_A.to_uppercase()], None);

    let q = db::compliance_queue(&pool, &only_a, true, None).await.unwrap();
    assert!(q.iter().all(|r| r.control_id == "SEC-1") && q.len() == 1);
    let r = db::open_fail_resources(&pool, &only_a).await.unwrap();
    assert!(r.iter().all(|r| r.control_id == "SEC-1") && r.len() == 1);
    let a = db::compliance_aging(&pool, &only_a, now).await.unwrap();
    assert!(a.iter().all(|r| r.control_id == "SEC-1") && a.len() == 1);
    let f = db::compliance_flow(&pool, &only_a, 90, now).await.unwrap();
    assert!(f.iter().all(|r| r.control_id == "SEC-1") && f.len() == 1);
    let t = db::compliance_trend(&pool, &only_a, db::TREND_SCANS).await.unwrap();
    assert!(t.iter().all(|r| r.control_id == "SEC-1") && t.len() == 1);

    // Empty scope means no rows, never "all".
    let empty = scope(&[], None);
    assert!(db::compliance_queue(&pool, &empty, false, None).await.unwrap().is_empty());
    assert!(db::open_fail_resources(&pool, &empty).await.unwrap().is_empty());
    assert!(db::compliance_aging(&pool, &empty, now).await.unwrap().is_empty());
    assert!(db::compliance_flow(&pool, &empty, 90, now).await.unwrap().is_empty());
    assert!(db::compliance_trend(&pool, &empty, db::TREND_SCANS).await.unwrap().is_empty());
}

#[tokio::test]
async fn open_fail_resources_joins_the_latest_observation() {
    let (_d, pool) = pool().await;
    let r = rid(SUB_A, "a");
    db::insert_observation(
        &pool,
        &ResourceObservation {
            id: "obs-1".into(),
            provider: Provider::Azure,
            resource_id: ResourceId::new(r.clone()),
            tenant_id: TenantId::new("t"),
            subscription_id: SubscriptionId::new(SUB_A),
            resource_type: "Microsoft.Storage/storageAccounts".into(),
            name: "a".into(),
            location: None,
            resource_group: Some("rg-app".into()),
            tags: json!({ "app": "payments" }),
            properties: json!({ "big": true }),
            scan_id: "s1".into(),
            observation_time: t0(),
            evidence_available: true,
            lifecycle_epoch: 1,
            arm_meta: json!({}),
        },
    )
    .await
    .unwrap();
    record(
        &pool,
        "s1",
        vec![
            ev(&r, "SEC-1", EvalOutcome::Fail, t0(), "security"),
            ev(&rid(SUB_A, "no-obs"), "SEC-1", EvalOutcome::Fail, t0(), "security"),
        ],
    )
    .await;
    let rows = db::open_fail_resources(&pool, &scope(&[SUB_A], None)).await.unwrap();
    assert_eq!(rows.len(), 2);
    let with = rows.iter().find(|x| x.resource_id == r).unwrap();
    let obs = with.observation.as_ref().unwrap();
    assert_eq!(obs.tags["app"], "payments");
    assert_eq!(obs.resource_group.as_deref(), Some("rg-app"));
    assert!(rows.iter().any(|x| x.observation.is_none()));

    let agg = db::aggregate_queue(&rows, None, |x| {
        x.observation
            .as_ref()
            .and_then(|o| o.tags.get("app").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string()
    });
    let keys: Vec<(&str, u64)> = agg.iter().map(|q| (q.group_key.as_str(), q.count)).collect();
    assert_eq!(keys, vec![("", 1), ("payments", 1)]);
}
