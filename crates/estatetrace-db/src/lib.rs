//! SQLite persistence for EstateTrace.

mod repo;

pub use repo::*;

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::Path;
use std::str::FromStr;

pub async fn open_db(path: &Path) -> Result<SqlitePool> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let options = SqliteConnectOptions::from_str(&url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .with_context(|| format!("open sqlite {}", path.display()))?;

    migrate(&pool).await?;
    Ok(pool)
}

/// Versioned migrations applied after `001_init.sql`, in ascending order.
/// Each runs once, inside a transaction, when `meta.schema_version` is below its number.
/// Add new entries at the end; never edit or renumber an entry that has shipped.
pub const MIGRATIONS: &[(i64, &str)] = &[
    (3, include_str!("../migrations/003_exception_scope.sql")),
];

pub async fn migrate(pool: &SqlitePool) -> Result<()> {
    // 001 is idempotent (CREATE ... IF NOT EXISTS) and runs on every open.
    let sql = include_str!("../migrations/001_init.sql");
    for stmt in split_sql(sql) {
        sqlx::query(&stmt).execute(pool).await.with_context(|| {
            format!("migration statement failed: {}", &stmt[..stmt.len().min(80)])
        })?;
    }
    apply_migrations(pool, MIGRATIONS).await
}

/// Highest applied migration version (1 when only `001_init.sql` has been applied).
pub async fn schema_version(pool: &SqlitePool) -> Result<i64> {
    ensure_migration_table(pool).await?;
    let row: (Option<i64>,) = sqlx::query_as("SELECT MAX(version) FROM schema_migrations")
        .fetch_one(pool)
        .await?;
    Ok(row.0.unwrap_or(1))
}

async fn ensure_migration_table(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY NOT NULL, applied_at TEXT NOT NULL)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Apply each `(version, sql)` not yet recorded in `schema_migrations`, in ascending order.
/// Tracking each version (not just the maximum) means a migration merged later with a lower
/// number still runs on a DB that already has higher ones. A failing migration rolls back
/// entirely and is not recorded.
pub async fn apply_migrations(pool: &SqlitePool, migrations: &[(i64, &str)]) -> Result<()> {
    ensure_migration_table(pool).await?;
    let applied: Vec<(i64,)> = sqlx::query_as("SELECT version FROM schema_migrations")
        .fetch_all(pool)
        .await?;
    let applied: std::collections::HashSet<i64> = applied.into_iter().map(|r| r.0).collect();
    let mut ordered: Vec<&(i64, &str)> = migrations.iter().collect();
    ordered.sort_by_key(|m| m.0);
    for (version, sql) in ordered {
        if applied.contains(version) {
            continue;
        }
        let mut tx = pool.begin().await?;
        for stmt in split_sql(sql) {
            sqlx::query(&stmt).execute(&mut *tx).await.with_context(|| {
                format!(
                    "migration {version:03} failed at: {}",
                    &stmt[..stmt.len().min(80)]
                )
            })?;
        }
        sqlx::query("INSERT INTO schema_migrations(version, applied_at) VALUES(?, datetime('now'))")
            .bind(version)
            .execute(&mut *tx)
            .await?;
        tx.commit()
            .await
            .with_context(|| format!("migration {version:03} commit failed"))?;
    }
    Ok(())
}

/// Split a SQL script into statements. Full-line `--` comments are removed first so a
/// statement preceded by a comment is not dropped. Statements must not contain `;` in literals.
fn split_sql(sql: &str) -> Vec<String> {
    let without_comments: String = sql
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    without_comments
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

pub async fn meta_get(pool: &SqlitePool, key: &str) -> Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM meta WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.0))
}

pub async fn meta_set(pool: &SqlitePool, key: &str, value: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}