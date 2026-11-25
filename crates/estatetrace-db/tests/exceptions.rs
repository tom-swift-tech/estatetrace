//! P2: scoped exceptions store (spec §4.5, AC-P2-4).

use chrono::{Duration, Utc};
use estatetrace_core::ExceptionRecord;
use estatetrace_db as db;

const SUB: &str = "11111111-2222-3333-4444-555555555555";

fn rid(rg: &str, name: &str) -> String {
    format!("/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}")
}

fn migration_003() -> (i64, &'static str) {
    *db::MIGRATIONS
        .iter()
        .find(|(v, _)| *v == 3)
        .expect("migration 003 is registered")
}

fn record(id: &str, control: &str) -> ExceptionRecord {
    ExceptionRecord {
        id: id.into(),
        control_id: control.into(),
        resource_id: None,
        subscription_id: None,
        resource_group: None,
        reason: None,
        approved_by: None,
        ticket_ref: None,
        expires_at: None,
        created_at: Utc::now(),
    }
}

#[tokio::test]
async fn ac_p2_4_v1_rows_survive_migration_003() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("x.db")).await.unwrap();

    // Put the DB back into its pre-003 shape: the v1 exceptions table with one v1 row.
    sqlx::query("DROP TABLE exceptions").execute(&pool).await.unwrap();
    sqlx::query(
        "CREATE TABLE exceptions (
            id TEXT PRIMARY KEY NOT NULL,
            resource_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            reason TEXT,
            approved_by TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    let v1_rid = rid("rg-app", "st1");
    sqlx::query(
        "INSERT INTO exceptions(id, resource_id, control_id, reason, approved_by, expires_at, created_at)
         VALUES('ex-v1', ?, 'GEO-001', 'legacy reason', 'alice', '2030-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
    )
    .bind(&v1_rid)
    .execute(&pool)
    .await
    .unwrap();
    let (v3, sql3) = migration_003();
    // Forget that 003 was applied when the DB was opened.
    sqlx::query("DELETE FROM schema_migrations WHERE version = ?")
        .bind(v3)
        .execute(&pool)
        .await
        .unwrap();

    db::apply_migrations(&pool, &[(v3, sql3)]).await.unwrap();
    let recorded: Option<(i64,)> = sqlx::query_as("SELECT version FROM schema_migrations WHERE version = ?")
        .bind(v3)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(recorded.is_some(), "003 recorded as applied");

    let raw: (String, Option<String>, Option<String>, Option<String>, Option<String>, String) =
        sqlx::query_as(
            "SELECT control_id, resource_id, subscription_id, resource_group, ticket_ref, reason
             FROM exceptions WHERE id = 'ex-v1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(raw.0, "GEO-001");
    assert_eq!(raw.1.as_deref(), Some(v1_rid.as_str()));
    assert_eq!(raw.2, None);
    assert_eq!(raw.3, None);
    assert_eq!(raw.4, None);
    assert_eq!(raw.5, "legacy reason");

    let listed = db::list_exceptions(&pool, Some("GEO-001"), None).await.unwrap();
    assert_eq!(listed.len(), 1);
    let ex = &listed[0];
    assert_eq!(ex.resource_id.as_deref(), Some(v1_rid.as_str()));
    assert_eq!(ex.approved_by.as_deref(), Some("alice"));
    assert!(ex.expires_at.is_some());

    // The rebuilt table now accepts scoped rows (resource_id nullable).
    let scoped = ExceptionRecord {
        subscription_id: Some(SUB.into()),
        ..record("ex-sub", "GEO-001")
    };
    db::insert_exception(&pool, &scoped).await.unwrap();

    // Reopening runs 001 (IF NOT EXISTS) again; the rebuilt table and rows stay.
    drop(pool);
    let pool = db::open_db(&dir.path().join("x.db")).await.unwrap();
    assert_eq!(db::list_exceptions(&pool, None, None).await.unwrap().len(), 2);
}

#[tokio::test]
async fn fresh_db_has_scoped_table_and_rejects_empty_scope() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("f.db")).await.unwrap();
    let err = db::insert_exception(&pool, &record("ex-empty", "C")).await;
    assert!(err.is_err(), "CHECK rejects a row with no resource and no subscription");
}

#[tokio::test]
async fn list_filters_by_control_and_covering_scope() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("l.db")).await.unwrap();
    let now = Utc::now();
    let rows = [
        ExceptionRecord { resource_id: Some(rid("rg-app", "st1")), ..record("r1", "STG-001") },
        ExceptionRecord {
            subscription_id: Some(SUB.to_uppercase()),
            resource_group: Some("RG-APP".into()),
            ticket_ref: Some("CHG0042".into()),
            ..record("g1", "STG-001")
        },
        ExceptionRecord {
            subscription_id: Some(SUB.into()),
            resource_group: Some("rg-other".into()),
            ..record("g2", "STG-001")
        },
        ExceptionRecord {
            subscription_id: Some(SUB.into()),
            expires_at: Some(now - Duration::days(1)),
            ..record("s1", "STG-002")
        },
    ];
    for r in &rows {
        db::insert_exception(&pool, r).await.unwrap();
    }

    let by_control = db::list_exceptions(&pool, Some("stg-001"), None).await.unwrap();
    assert_eq!(by_control.len(), 3, "control filter is case-insensitive");

    let mut for_st1: Vec<String> = db::list_exceptions(&pool, None, Some(&rid("rg-app", "st1")))
        .await
        .unwrap()
        .into_iter()
        .map(|x| x.id)
        .collect();
    for_st1.sort();
    assert_eq!(for_st1, vec!["g1", "r1", "s1"]);

    let both: Vec<String> = db::list_exceptions(&pool, Some("STG-001"), Some(&rid("rg-other", "st9")))
        .await
        .unwrap()
        .into_iter()
        .map(|x| x.id)
        .collect();
    assert_eq!(both, vec!["g2"]);

    let g1 = db::list_exceptions(&pool, None, None)
        .await
        .unwrap()
        .into_iter()
        .find(|x| x.id == "g1")
        .unwrap();
    assert_eq!(g1.ticket_ref.as_deref(), Some("CHG0042"));
    assert_eq!(g1.resource_group.as_deref(), Some("RG-APP"));

    // s1 has expired, so three of the four are active.
    assert_eq!(db::count_active_exceptions(&pool).await.unwrap(), 3);
}
