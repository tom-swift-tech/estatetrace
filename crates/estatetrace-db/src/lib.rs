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
    (4, include_str!("../migrations/004_classification.sql")),
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

/// Current schema version (1 when only `001_init.sql` has been applied).
pub async fn schema_version(pool: &SqlitePool) -> Result<i64> {
    Ok(meta_get(pool, "schema_version")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(1))
}

/// Apply each `(version, sql)` whose version exceeds the stored schema version.
/// A failing migration rolls back entirely and leaves the version unchanged.
pub async fn apply_migrations(pool: &SqlitePool, migrations: &[(i64, &str)]) -> Result<()> {
    let mut current = schema_version(pool).await?;
    for (version, sql) in migrations {
        if *version <= current {
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
        sqlx::query(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(version.to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit()
            .await
            .with_context(|| format!("migration {version:03} commit failed"))?;
        current = *version;
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