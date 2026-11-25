//! P0: versioned migrations (spec AC-P0-1, AC-P0-2).

use estatetrace_db as db;

const TEST_MIGRATIONS: &[(i64, &str)] = &[
    (2, "-- leading comment must not drop the statement\nCREATE TABLE t_two (id INTEGER PRIMARY KEY)"),
    (3, "CREATE TABLE t_three (id INTEGER PRIMARY KEY); INSERT INTO t_three(id) VALUES (1)"),
];

#[tokio::test]
async fn ac_p0_1_migrations_apply_once_and_record_version() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("m.db")).await.unwrap();
    assert_eq!(db::schema_version(&pool).await.unwrap(), db::MIGRATIONS.last().map(|m| m.0).unwrap_or(1));

    let pool_versioned_from = db::schema_version(&pool).await.unwrap();
    // Re-base test migrations above whatever the shipped list reached.
    let rebased: Vec<(i64, String)> = TEST_MIGRATIONS
        .iter()
        .map(|(v, s)| (pool_versioned_from + v - 1, s.to_string()))
        .collect();
    let list: Vec<(i64, &str)> = rebased.iter().map(|(v, s)| (*v, s.as_str())).collect();

    db::apply_migrations(&pool, &list).await.unwrap();
    db::apply_migrations(&pool, &list).await.unwrap(); // second run is a no-op

    let n: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM t_three")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n.0, 1, "migration 3 ran exactly once");
    assert_eq!(db::schema_version(&pool).await.unwrap(), list.last().unwrap().0);

    // Reopening (which runs 001 + shipped list) keeps the higher version.
    drop(pool);
    let pool = db::open_db(&dir.path().join("m.db")).await.unwrap();
    assert_eq!(db::schema_version(&pool).await.unwrap(), list.last().unwrap().0);
}

#[tokio::test]
async fn ac_p0_2_failed_migration_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("f.db")).await.unwrap();
    let before = db::schema_version(&pool).await.unwrap();

    let broken = [(
        before + 1,
        "CREATE TABLE t_partial (id INTEGER); THIS IS NOT SQL",
    )];
    assert!(db::apply_migrations(&pool, &broken).await.is_err());
    assert_eq!(db::schema_version(&pool).await.unwrap(), before);

    let exists: Option<(String,)> =
        sqlx::query_as("SELECT name FROM sqlite_master WHERE type='table' AND name='t_partial'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(exists.is_none(), "partial DDL must roll back");
}
