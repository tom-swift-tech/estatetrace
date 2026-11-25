//! Findings store: one row per interval of a (pack, resource, control) outcome (spec §3.3,
//! §4.4). Port of azcompliance `Save-ComplianceRun`'s interval SQL.

use anyhow::Result;
use chrono::{DateTime, Utc};
use estatetrace_core::*;
use estatetrace_policy::PackEvaluation;
use serde_json::{json, Value};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqliteConnection, SqlitePool};
use std::collections::HashSet;

/// Rows staged per INSERT: 11 parameters each, under SQLite's 32,766-parameter limit.
const STAGE_CHUNK: usize = 1_000;

/// Record one pack's evaluation for one scan as finding intervals, in one transaction
/// (invariant 14). Steps, all scoped to `pack_id`:
///
/// 1. Stage this scan's evaluations in a temp table.
/// 2. Close open intervals whose pack revision differs (`pack_revision`).
/// 3. Close open intervals whose outcome changed (`state_changed`).
/// 4. Continue the remaining open intervals that have a staged row (detail, evidence, `last_*`).
/// 5. For subscriptions in `complete_subscriptions` only (a complete pass that started from the
///    beginning), close open intervals with no staged row: `no_longer_targeted` when the
///    resource was observed in this scan, else `resource_missing` (invariant 8).
/// 6. Open an interval for every staged row without an open one.
/// 7. Replace the pack's coverage gaps.
///
/// A retry of the same scan writes nothing new: same outcomes continue, and the open-interval
/// unique index rules out duplicates. A failure rolls everything back.
pub async fn record_pack_evaluation(
    pool: &SqlitePool,
    scan_id: &str,
    pack_id: &str,
    pack_revision: &str,
    complete_subscriptions: &HashSet<SubscriptionId>,
    result: &PackEvaluation,
) -> Result<IntervalStats> {
    let now = Utc::now().to_rfc3339();
    let mut tx = pool.begin().await?;
    let conn: &mut SqliteConnection = &mut tx;

    sqlx::query(
        "CREATE TEMP TABLE IF NOT EXISTS stage_finding (
            resource_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            subscription_id TEXT NOT NULL,
            outcome TEXT NOT NULL,
            severity TEXT NOT NULL,
            environment TEXT NOT NULL,
            detail TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            clause_revision TEXT NOT NULL,
            evaluated_at TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            PRIMARY KEY (resource_id, control_id)
        )",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM temp.stage_finding")
        .execute(&mut *conn)
        .await?;

    // Multi-row VALUES with bound parameters. Full chunks share one SQL text, so the prepared
    // statement is cached across chunks and scans.
    for chunk in result.evaluations.chunks(STAGE_CHUNK) {
        let mut sql = String::with_capacity(64 + chunk.len() * 26);
        sql.push_str(
            "INSERT OR REPLACE INTO temp.stage_finding (resource_id, control_id,
                subscription_id, outcome, severity, environment, detail, evidence_json,
                clause_revision, evaluated_at, observation_id) VALUES ",
        );
        for i in 0..chunk.len() {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str("(?,?,?,?,?,?,?,?,?,?,?)");
        }
        // A duplicate (resource, control) in one result keeps the last row.
        let mut q = sqlx::query(&sql);
        for ev in chunk {
            let clause = ev
                .evidence
                .get("clause_revision")
                .and_then(|v| v.as_str())
                .unwrap_or(&ev.control_revision);
            q = q
                .bind(ev.resource_id.as_str())
                .bind(ev.control_id.as_str())
                .bind(arm_scope(ev.resource_id.as_str()).0.unwrap_or_default())
                .bind(ev.outcome.as_str())
                .bind(ev.severity.as_str())
                .bind(ev.environment.as_str())
                .bind(ev.detail.as_str())
                .bind(ev.evidence.to_string())
                .bind(clause)
                .bind(ev.evaluated_at.to_rfc3339())
                .bind(ev.observation_id.as_str());
        }
        q.execute(&mut *conn).await?;
    }

    let mut stats = IntervalStats::default();

    // 2. Revision boundary (AC-P3-3): every open interval of an older revision closes, visited
    // or not, because its policy no longer applies.
    stats.closed += sqlx::query(
        "UPDATE finding_intervals
         SET closed_at = COALESCE((SELECT s.evaluated_at FROM temp.stage_finding s
                                   WHERE s.resource_id = finding_intervals.resource_id
                                     AND s.control_id = finding_intervals.control_id), ?1),
             closed_scan_id = ?2,
             close_reason = 'pack_revision'
         WHERE pack_id = ?3 AND closed_at IS NULL AND pack_revision <> ?4",
    )
    .bind(&now)
    .bind(scan_id)
    .bind(pack_id)
    .bind(pack_revision)
    .execute(&mut *conn)
    .await?
    .rows_affected();

    // 3. Outcome changed (AC-P3-2). The old interval ends where the new one starts.
    stats.closed += sqlx::query(
        "UPDATE finding_intervals AS f
         SET closed_at = s.evaluated_at, closed_scan_id = ?1, close_reason = 'state_changed'
         FROM temp.stage_finding AS s
         WHERE f.pack_id = ?2 AND f.closed_at IS NULL
           AND s.resource_id = f.resource_id AND s.control_id = f.control_id
           AND s.outcome <> f.outcome",
    )
    .bind(scan_id)
    .bind(pack_id)
    .execute(&mut *conn)
    .await?
    .rows_affected();

    // 4. Continue (AC-P3-1): same outcome and revision; take this scan's detail and evidence.
    stats.continued = sqlx::query(
        "UPDATE finding_intervals AS f
         SET severity = s.severity, environment = s.environment, detail = s.detail,
             evidence_json = s.evidence_json, clause_revision = s.clause_revision,
             last_evaluated_at = s.evaluated_at, last_scan_id = ?1,
             last_observation_id = s.observation_id
         FROM temp.stage_finding AS s
         WHERE f.pack_id = ?2 AND f.closed_at IS NULL
           AND s.resource_id = f.resource_id AND s.control_id = f.control_id",
    )
    .bind(scan_id)
    .bind(pack_id)
    .execute(&mut *conn)
    .await?
    .rows_affected();

    // 5. Absence closes only inside a complete from-the-beginning pass (AC-P3-4, AC-P3-5).
    if !complete_subscriptions.is_empty() {
        let subs: Vec<&str> = complete_subscriptions.iter().map(|s| s.as_str()).collect();
        stats.closed += sqlx::query(
            "UPDATE finding_intervals
             SET closed_at = ?1, closed_scan_id = ?2,
                 close_reason = CASE WHEN EXISTS (
                         SELECT 1 FROM resource_observations o
                         WHERE o.scan_id = ?2 AND o.resource_id = finding_intervals.resource_id)
                     THEN 'no_longer_targeted' ELSE 'resource_missing' END
             WHERE pack_id = ?3 AND closed_at IS NULL
               AND lower(subscription_id) IN (SELECT lower(value) FROM json_each(?4))
               AND NOT EXISTS (
                     SELECT 1 FROM temp.stage_finding s
                     WHERE s.resource_id = finding_intervals.resource_id
                       AND s.control_id = finding_intervals.control_id)",
        )
        .bind(&now)
        .bind(scan_id)
        .bind(pack_id)
        .bind(serde_json::to_string(&subs)?)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    }

    // 6. Open new intervals.
    stats.opened = sqlx::query(
        "INSERT INTO finding_intervals (id, pack_id, pack_revision, clause_revision, resource_id,
            subscription_id, control_id, outcome, severity, environment, detail, evidence_json,
            opened_at, opened_scan_id, first_observation_id, last_evaluated_at, last_scan_id,
            last_observation_id)
         SELECT lower(hex(randomblob(16))), ?1, ?2, s.clause_revision, s.resource_id, s.subscription_id,
                s.control_id, s.outcome, s.severity, s.environment, s.detail, s.evidence_json,
                s.evaluated_at, ?3, s.observation_id, s.evaluated_at, ?3, s.observation_id
         FROM temp.stage_finding s
         WHERE NOT EXISTS (
             SELECT 1 FROM finding_intervals f
             WHERE f.pack_id = ?1 AND f.resource_id = s.resource_id
               AND f.control_id = s.control_id AND f.closed_at IS NULL)",
    )
    .bind(pack_id)
    .bind(pack_revision)
    .bind(scan_id)
    .execute(&mut *conn)
    .await?
    .rows_affected();

    sqlx::query("DELETE FROM temp.stage_finding")
        .execute(&mut *conn)
        .await?;

    // 7. Coverage gaps for the same pack and scan, in the same transaction.
    crate::repo::replace_coverage_gaps_in(
        &mut *conn,
        pack_id,
        pack_revision,
        scan_id,
        &result.coverage_gaps,
    )
    .await?;

    tx.commit().await?;
    Ok(stats)
}

/// Close every open interval of a pack (deactivation, or activation of another revision).
/// Returns the number closed.
pub async fn close_findings_for_pack(
    pool: &SqlitePool,
    pack_id: &str,
    reason: CloseReason,
) -> Result<u64> {
    let res = sqlx::query(
        "UPDATE finding_intervals SET closed_at = ?, close_reason = ?
         WHERE pack_id = ? AND closed_at IS NULL",
    )
    .bind(Utc::now().to_rfc3339())
    .bind(reason.as_str())
    .bind(pack_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Columns of `FindingInterval` plus the predecessor of a pass interval (`pred`, as
/// `outcome:close_reason`). The predecessor is the previous row for the same key by insertion
/// order, found through the per-resource index; it is only looked up for passes, the only
/// outcome that needs it (`VerifiedCorrected`).
const FINDING_SELECT: &str = "SELECT f.id, f.pack_id, f.pack_revision, f.clause_revision,
        f.resource_id, f.subscription_id, f.control_id, f.outcome, f.severity, f.environment,
        f.detail, f.evidence_json, f.opened_at, f.opened_scan_id, f.last_evaluated_at,
        f.last_scan_id, f.closed_at, f.close_reason,
        CASE WHEN f.outcome = 'pass' THEN (
            SELECT p.outcome || ':' || IFNULL(p.close_reason, '')
            FROM finding_intervals p
            WHERE p.resource_id = f.resource_id AND p.pack_id = f.pack_id
              AND p.control_id = f.control_id AND p.rowid < f.rowid
            ORDER BY p.rowid DESC LIMIT 1) END AS pred
    FROM finding_intervals f";

fn parse_time(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or(DateTime::<Utc>::MIN_UTC)
}

fn map_finding(row: &SqliteRow) -> FindingInterval {
    let evidence: Value = serde_json::from_str(row.get::<&str, _>("evidence_json"))
        .unwrap_or(Value::Null);
    let pred: Option<String> = row.get("pred");
    let (predecessor_outcome, predecessor_close_reason) = match pred.as_deref() {
        Some(p) => {
            let (o, r) = p.split_once(':').unwrap_or((p, ""));
            (EvalOutcome::parse(o), CloseReason::parse(r))
        }
        None => (None, None),
    };
    FindingInterval {
        id: row.get("id"),
        pack_id: row.get("pack_id"),
        pack_revision: row.get("pack_revision"),
        clause_revision: row.get("clause_revision"),
        resource_id: ResourceId::new(row.get::<String, _>("resource_id")),
        subscription_id: SubscriptionId::new(row.get::<String, _>("subscription_id")),
        control_id: row.get("control_id"),
        outcome: EvalOutcome::parse(row.get("outcome")).unwrap_or(EvalOutcome::Unknown),
        severity: Severity::parse(row.get("severity")).unwrap_or(Severity::Medium),
        environment: EnvironmentClass::parse(row.get("environment"))
            .unwrap_or(EnvironmentClass::Unknown),
        detail: row.get("detail"),
        grace_period_hours: evidence.get("grace_period_hours").and_then(|v| v.as_u64()),
        evidence,
        opened_at: parse_time(row.get("opened_at")),
        opened_scan_id: row.get("opened_scan_id"),
        last_evaluated_at: parse_time(row.get("last_evaluated_at")),
        last_scan_id: row.get("last_scan_id"),
        closed_at: row.get::<Option<&str>, _>("closed_at").map(parse_time),
        close_reason: row
            .get::<Option<&str>, _>("close_reason")
            .and_then(CloseReason::parse),
        predecessor_outcome,
        predecessor_close_reason,
    }
}

/// Open intervals matching `q`, ordered by resource then control. `q.subscriptions` applies
/// the tracked-scope filter (invariant 13); `None` means no scope filter.
pub async fn list_open_findings(pool: &SqlitePool, q: &FindingQuery) -> Result<Vec<FindingInterval>> {
    let sql = format!(
        "{FINDING_SELECT}
         WHERE f.closed_at IS NULL
           AND (?1 IS NULL OR f.subscription_id = ?1 COLLATE NOCASE)
           AND (?2 IS NULL OR f.control_id = ?2)
           AND (?3 IS NULL OR f.outcome = ?3)
           AND (?4 IS NULL OR f.environment = ?4)
           AND (?5 IS NULL OR IFNULL(json_extract(f.evidence_json, '$.lane'), 'security') = ?5)
           AND (?6 IS NULL OR f.resource_id = ?6)
           AND (?7 IS NULL OR lower(f.subscription_id) IN (SELECT lower(value) FROM json_each(?7)))
           AND (?8 IS NULL OR f.resource_id IN (SELECT value FROM json_each(?8)))
         ORDER BY f.resource_id, f.control_id, f.pack_id
         LIMIT ?9"
    );
    let rows = sqlx::query(&sql)
        .bind(q.subscription_id.as_deref())
        .bind(q.control_id.as_deref())
        .bind(q.outcome.as_ref().map(|o| o.as_str()))
        .bind(q.environment.as_deref())
        .bind(q.lane.as_deref())
        .bind(q.resource_id.as_deref())
        .bind(q.subscriptions.as_ref().map(|s| json!(s).to_string()))
        .bind(q.resource_ids.as_ref().map(|s| json!(s).to_string()))
        .bind(q.limit.unwrap_or(-1))
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(map_finding).collect())
}

/// Full history of one resource, open and closed, newest interval first within each control.
/// No LIMIT: history is never truncated (AC-P3-8).
pub async fn findings_for_resource(pool: &SqlitePool, resource_id: &str) -> Result<Vec<FindingInterval>> {
    let sql = format!(
        "{FINDING_SELECT}
         WHERE f.resource_id = ?1
         ORDER BY f.control_id, f.pack_id, f.rowid DESC"
    );
    let rows = sqlx::query(&sql).bind(resource_id).fetch_all(pool).await?;
    Ok(rows.iter().map(map_finding).collect())
}

/// Start time of the newest finished scan (`complete` or `partial`), used to flag findings
/// whose `last_evaluated_at` is older (stale: not re-evaluated by the last scan).
pub async fn last_finished_scan_started_at(pool: &SqlitePool) -> Result<Option<DateTime<Utc>>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT started_at FROM scan_runs
         WHERE finished_at IS NOT NULL AND completeness IN ('complete', 'partial')
         ORDER BY started_at DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| parse_time(&r.0)))
}
