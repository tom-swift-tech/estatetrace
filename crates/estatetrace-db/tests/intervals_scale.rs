//! P3 scale (AC-P3-8): unchanged scans continue intervals instead of adding rows, and one
//! resource's full history is a cheap indexed read. Temp-file SQLite, as in production.

use chrono::{Duration, Utc};
use estatetrace_core::*;
use estatetrace_db as db;
use estatetrace_policy::PackEvaluation;
use serde_json::json;
use std::collections::HashSet;
use std::time::{Duration as StdDuration, Instant};

const SUB: &str = "cccccccc-0000-0000-0000-000000000003";
const CONTROLS: usize = 5;

fn resource_id(r: usize) -> String {
    format!(
        "/subscriptions/{SUB}/resourceGroups/rg-{}/providers/Microsoft.Storage/storageAccounts/st{r:05}",
        r % 50
    )
}

fn scan_result(resources: usize, scan: usize) -> PackEvaluation {
    let at = Utc::now() - Duration::hours(24) + Duration::hours(scan as i64);
    let mut evaluations = Vec::with_capacity(resources * CONTROLS);
    for r in 0..resources {
        let resource = resource_id(r);
        for c in 0..CONTROLS {
            let outcome = if (r + c) % 3 == 0 { EvalOutcome::Fail } else { EvalOutcome::Pass };
            evaluations.push(Evaluation {
                id: format!("{scan}-{r}-{c}"),
                observation_id: format!("obs-{scan}-{r}"),
                resource_id: ResourceId::new(resource.clone()),
                control_id: format!("CTL-{c}"),
                control_revision: "1".into(),
                outcome,
                severity: Severity::Medium,
                evidence: json!({
                    "field": "properties.minimumTlsVersion",
                    "operator": "ordinal_gte",
                    "observed": "TLS1_2",
                    "grace_period_hours": 24,
                    "clause_revision": "1",
                    "lane": "security",
                }),
                evaluated_at: at,
                environment: EnvironmentClass::Prod,
                detail: String::new(),
            });
        }
    }
    PackEvaluation { evaluations, coverage_gaps: Vec::new() }
}

async fn run(resources: usize, scans: usize, budget: StdDuration) {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("scale.db")).await.unwrap();
    let complete: HashSet<SubscriptionId> = [SubscriptionId::new(SUB)].into_iter().collect();
    let expected = (resources * CONTROLS) as u64;
    // The budget covers the store only, not building the synthetic evaluations.
    let mut write_time = StdDuration::ZERO;
    for s in 0..scans {
        let res = scan_result(resources, s);
        let started = Instant::now();
        let stats = db::record_pack_evaluation(&pool, &format!("scan-{s}"), "PACK", "1", &complete, &res)
            .await
            .unwrap();
        write_time += started.elapsed();
        if s == 0 {
            assert_eq!(stats, IntervalStats { opened: expected, continued: 0, closed: 0 });
        } else {
            assert_eq!(stats, IntervalStats { opened: 0, continued: expected, closed: 0 });
        }
    }

    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM finding_intervals")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(rows.0 as u64 <= expected, "row count {} grew with scans", rows.0);
    assert_eq!(rows.0 as u64, expected);

    // Full history of one resource: every control, re-evaluated by the last scan.
    let target = resource_id(resources / 2);
    let q = Instant::now();
    let history = db::findings_for_resource(&pool, &target).await.unwrap();
    let read_time = q.elapsed();
    assert_eq!(history.len(), CONTROLS);
    let last = format!("scan-{}", scans - 1);
    assert!(history.iter().all(|f| f.last_scan_id == last && f.opened_scan_id == "scan-0"));
    assert!(read_time < StdDuration::from_millis(500), "resource history took {read_time:?}");

    let q = Instant::now();
    let open = db::list_open_findings(&pool, &FindingQuery::default()).await.unwrap();
    let list_time = q.elapsed();
    assert_eq!(open.len() as u64, expected);

    eprintln!(
        "intervals scale: {resources} resources x {CONTROLS} controls x {scans} scans: \
         writes {write_time:?}, resource history {read_time:?}, open list {list_time:?}"
    );
    let total = write_time + read_time + list_time;
    assert!(total < budget, "took {total:?}, budget {budget:?}");
}

/// AC-P3-8 at full size: 10,000 resources x 5 controls x 10 unchanged scans (budget 60 s,
/// debug build).
#[tokio::test]
async fn ac_p3_8_ten_thousand_resources_ten_scans() {
    run(10_000, 10, StdDuration::from_secs(60)).await;
}

/// Smaller variant of the same checks.
#[tokio::test]
async fn ac_p3_8_one_thousand_resources_ten_scans() {
    run(1_000, 10, StdDuration::from_secs(20)).await;
}
