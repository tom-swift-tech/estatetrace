//! Reporting reads over `finding_intervals` (spec §3.3, §4.7; plan P6). Adapted from the
//! azcompliance `queue`, `aging`, `flow` and `trend` render queries.
//!
//! Every function takes the scope as a list of subscription IDs (invariant 13). An empty scope
//! returns no rows; it never means "all subscriptions".
//!
//! Lane is read from the interval evidence (`$.lane`); a missing lane is `security`, the pack
//! default. The filter runs after the open/fail predicates, so it only touches candidate rows.

use anyhow::Result;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use estatetrace_core::{ResourceId, ResourceObservation, SubscriptionId, TenantId, Provider};
use estatetrace_policy::Lane;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Row, SqlitePool};
use std::collections::BTreeMap;

/// SQL for an interval's lane (`security` when the evidence has none).
const LANE_SQL: &str = "IFNULL(json_extract(f.evidence_json, '$.lane'), 'security')";

/// Scope and lane filter shared by every reporting query.
#[derive(Debug, Clone, Default)]
pub struct ReportScope {
    /// Tracked subscription IDs, matched case-insensitively. Empty means no rows.
    pub subscriptions: Vec<String>,
    /// `security` or `hygiene`; `None` means both lanes.
    pub lane: Option<String>,
}

impl ReportScope {
    pub fn new(subscriptions: Vec<String>, lane: Option<&str>) -> Self {
        Self {
            subscriptions,
            lane: lane.map(str::to_string),
        }
    }

    fn subs_json(&self) -> String {
        json!(self.subscriptions).to_string()
    }
}

/// `?1` = scope JSON array, `?2` = lane or NULL. Appended to a WHERE clause over alias `f`.
fn scope_predicate() -> String {
    format!(
        "lower(f.subscription_id) IN (SELECT lower(value) FROM json_each(?1))
         AND (?2 IS NULL OR {LANE_SQL} = ?2)"
    )
}

/// How queue rows are grouped beyond control, lane and environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueGroupBy {
    Application,
    Owner,
    Subscription,
    LineOfBusiness,
}

impl QueueGroupBy {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "application" => Some(Self::Application),
            "owner" => Some(Self::Owner),
            "subscription" => Some(Self::Subscription),
            "line_of_business" => Some(Self::LineOfBusiness),
            _ => None,
        }
    }

    /// Grouping that needs `derive_ownership` over the latest observation (done in Rust).
    pub fn needs_ownership(self) -> bool {
        !matches!(self, Self::Subscription)
    }
}

/// One remediation-queue row (spec §4.7): open `fail` intervals for one control, lane,
/// environment and group. `group_key` is `""` without grouping or when the group is unknown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueueRow {
    pub control_id: String,
    pub lane: Lane,
    pub group_key: String,
    pub environment: String,
    pub count: u64,
    pub subscriptions: u64,
    pub oldest_opened_at: DateTime<Utc>,
    pub new_since_last_visit: u64,
}

/// Open `fail` intervals per control in one age bucket (spec §4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgingRow {
    pub control_id: String,
    /// `0-7` | `8-30` | `31-90` | `90+`
    pub bucket: String,
    pub count: u64,
}

/// Fail intervals opened and closed on one UTC day for one control (spec §4.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRow {
    pub day: NaiveDate,
    pub control_id: String,
    pub opened: u64,
    pub closed: u64,
}

/// Open `fail` intervals per control and lane at the end of one finished scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrendRow {
    pub scan_id: String,
    pub scan_started_at: DateTime<Utc>,
    pub control_id: String,
    pub lane: Lane,
    pub open: u64,
}

/// A finished scan used as a trend point.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrendScan {
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

/// One open `fail` interval with the latest observation of its resource, for grouping by
/// derived ownership (application, owner, line of business) in the caller.
#[derive(Debug, Clone)]
pub struct OpenFailResource {
    pub control_id: String,
    pub lane: Lane,
    pub environment: String,
    pub subscription_id: String,
    pub resource_id: String,
    pub opened_at: DateTime<Utc>,
    /// `None` when the resource has no stored observation.
    pub observation: Option<ResourceObservation>,
}

/// Number of trend points (finished scans) by default, as in azcompliance.
pub const TREND_SCANS: i64 = 26;

fn parse_time(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or(DateTime::<Utc>::MIN_UTC)
}

fn parse_lane(s: &str) -> Lane {
    if s.eq_ignore_ascii_case("hygiene") {
        Lane::Hygiene
    } else {
        Lane::Security
    }
}

/// Age bucket for whole days elapsed, inclusive on the upper bound: 7 days is `0-7`,
/// 8 days is `8-30`, 90 days is `31-90`, 91 days is `90+`.
pub fn aging_bucket(age_days: i64) -> &'static str {
    match age_days {
        i64::MIN..=7 => "0-7",
        8..=30 => "8-30",
        31..=90 => "31-90",
        _ => "90+",
    }
}

pub const AGING_BUCKETS: [&str; 4] = ["0-7", "8-30", "31-90", "90+"];

/// Remediation queue grouped in SQL: by control, lane and environment, plus subscription when
/// `by_subscription`. `new_since_last_visit` counts `opened_at > last_visit`; with no recorded
/// visit every open fail is new (the inbox convention). Largest groups first.
pub async fn compliance_queue(
    pool: &SqlitePool,
    scope: &ReportScope,
    by_subscription: bool,
    last_visit: Option<DateTime<Utc>>,
) -> Result<Vec<QueueRow>> {
    if scope.subscriptions.is_empty() {
        return Ok(Vec::new());
    }
    let group = if by_subscription {
        "f.subscription_id"
    } else {
        "''"
    };
    let sql = format!(
        "SELECT f.control_id, {LANE_SQL} AS lane, {group} AS group_key, f.environment,
                COUNT(*) AS n, COUNT(DISTINCT lower(f.subscription_id)) AS subs,
                MIN(f.opened_at) AS oldest,
                SUM(CASE WHEN ?3 IS NULL OR julianday(f.opened_at) > julianday(?3)
                         THEN 1 ELSE 0 END) AS new_n
         FROM finding_intervals f
         WHERE f.closed_at IS NULL AND f.outcome = 'fail' AND {}
         GROUP BY f.control_id, lane, group_key, f.environment
         ORDER BY n DESC, f.control_id, group_key, f.environment",
        scope_predicate()
    );
    let rows = sqlx::query(&sql)
        .bind(scope.subs_json())
        .bind(scope.lane.as_deref())
        .bind(last_visit.map(|t| t.to_rfc3339()))
        .fetch_all(pool)
        .await?;
    Ok(rows
        .iter()
        .map(|r| QueueRow {
            control_id: r.get("control_id"),
            lane: parse_lane(r.get("lane")),
            group_key: r.get("group_key"),
            environment: r.get("environment"),
            count: r.get::<i64, _>("n") as u64,
            subscriptions: r.get::<i64, _>("subs") as u64,
            oldest_opened_at: parse_time(r.get("oldest")),
            new_since_last_visit: r.get::<i64, _>("new_n") as u64,
        })
        .collect())
}

/// Every open `fail` interval in scope joined to its resource's latest observation, in one
/// query. The caller derives ownership per resource and aggregates with [`aggregate_queue`].
pub async fn open_fail_resources(
    pool: &SqlitePool,
    scope: &ReportScope,
) -> Result<Vec<OpenFailResource>> {
    if scope.subscriptions.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT f.control_id, {LANE_SQL} AS lane, f.environment, f.subscription_id,
                f.resource_id, f.opened_at,
                o.id AS o_id, o.tenant_id AS o_tenant, o.subscription_id AS o_sub,
                o.resource_type AS o_type, o.name AS o_name, o.location AS o_location,
                o.resource_group AS o_rg, o.tags_json AS o_tags, o.scan_id AS o_scan,
                o.observation_time AS o_time, o.evidence_available AS o_evidence,
                o.lifecycle_epoch AS o_epoch, o.arm_meta_json AS o_meta
         FROM finding_intervals f
         LEFT JOIN latest_resources l ON l.resource_id = f.resource_id
         LEFT JOIN resource_observations o ON o.id = l.observation_id
         WHERE f.closed_at IS NULL AND f.outcome = 'fail' AND {}
         ORDER BY f.resource_id, f.control_id",
        scope_predicate()
    );
    let rows = sqlx::query(&sql)
        .bind(scope.subs_json())
        .bind(scope.lane.as_deref())
        .fetch_all(pool)
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let resource_id: String = r.get("resource_id");
            let observation = r.get::<Option<String>, _>("o_id").map(|id| {
                let json_or_empty = |col: &str| -> Value {
                    r.get::<Option<String>, _>(col)
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_else(|| Value::Object(Default::default()))
                };
                ResourceObservation {
                    id,
                    provider: Provider::Azure,
                    resource_id: ResourceId::new(resource_id.clone()),
                    tenant_id: TenantId::new(r.get::<Option<String>, _>("o_tenant").unwrap_or_default()),
                    subscription_id: SubscriptionId::new(
                        r.get::<Option<String>, _>("o_sub").unwrap_or_default(),
                    ),
                    resource_type: r.get::<Option<String>, _>("o_type").unwrap_or_default(),
                    name: r.get::<Option<String>, _>("o_name").unwrap_or_default(),
                    location: r.get("o_location"),
                    resource_group: r.get("o_rg"),
                    tags: json_or_empty("o_tags"),
                    // Ownership reads tags only; properties are not loaded for reporting.
                    properties: Value::Object(Default::default()),
                    scan_id: r.get::<Option<String>, _>("o_scan").unwrap_or_default(),
                    observation_time: r
                        .get::<Option<String>, _>("o_time")
                        .map(|s| parse_time(&s))
                        .unwrap_or(DateTime::<Utc>::MIN_UTC),
                    evidence_available: r.get::<Option<i64>, _>("o_evidence").unwrap_or(1) != 0,
                    lifecycle_epoch: r.get::<Option<i64>, _>("o_epoch").unwrap_or(1),
                    arm_meta: json_or_empty("o_meta"),
                }
            });
            OpenFailResource {
                control_id: r.get("control_id"),
                lane: parse_lane(r.get("lane")),
                environment: r.get("environment"),
                subscription_id: r.get("subscription_id"),
                resource_id,
                opened_at: parse_time(r.get("opened_at")),
                observation,
            }
        })
        .collect())
}

/// Aggregate open fails into queue rows by control, lane, environment and `group_key(row)`,
/// with the same counting rules as [`compliance_queue`]. Largest groups first.
pub fn aggregate_queue(
    rows: &[OpenFailResource],
    last_visit: Option<DateTime<Utc>>,
    mut group_key: impl FnMut(&OpenFailResource) -> String,
) -> Vec<QueueRow> {
    struct Acc {
        row: QueueRow,
        subs: std::collections::HashSet<String>,
    }
    let mut groups: BTreeMap<(String, &'static str, String, String), Acc> = BTreeMap::new();
    for r in rows {
        let lane_key = match r.lane {
            Lane::Security => "security",
            Lane::Hygiene => "hygiene",
        };
        let key = group_key(r);
        let is_new = last_visit.map_or(true, |lv| r.opened_at > lv);
        let acc = groups
            .entry((r.control_id.clone(), lane_key, key.clone(), r.environment.clone()))
            .or_insert_with(|| Acc {
                row: QueueRow {
                    control_id: r.control_id.clone(),
                    lane: r.lane,
                    group_key: key,
                    environment: r.environment.clone(),
                    count: 0,
                    subscriptions: 0,
                    oldest_opened_at: r.opened_at,
                    new_since_last_visit: 0,
                },
                subs: Default::default(),
            });
        acc.row.count += 1;
        acc.row.new_since_last_visit += is_new as u64;
        if r.opened_at < acc.row.oldest_opened_at {
            acc.row.oldest_opened_at = r.opened_at;
        }
        acc.subs.insert(r.subscription_id.to_lowercase());
    }
    let mut out: Vec<QueueRow> = groups
        .into_values()
        .map(|mut a| {
            a.row.subscriptions = a.subs.len() as u64;
            a.row
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count));
    out
}

/// Open `fail` intervals per control by whole days from `opened_at` to `now`
/// ([`aging_bucket`]). Only non-empty buckets are returned, ordered by control then bucket.
pub async fn compliance_aging(
    pool: &SqlitePool,
    scope: &ReportScope,
    now: DateTime<Utc>,
) -> Result<Vec<AgingRow>> {
    if scope.subscriptions.is_empty() {
        return Ok(Vec::new());
    }
    // Ages are computed in Rust: SQLite's julianday arithmetic can put exactly 8 days at
    // 7.999…, which would land in the wrong bucket.
    let sql = format!(
        "SELECT f.control_id, f.opened_at, COUNT(*) AS n
         FROM finding_intervals f
         WHERE f.closed_at IS NULL AND f.outcome = 'fail' AND {}
         GROUP BY f.control_id, f.opened_at",
        scope_predicate()
    );
    let rows = sqlx::query(&sql)
        .bind(scope.subs_json())
        .bind(scope.lane.as_deref())
        .fetch_all(pool)
        .await?;
    let mut counts: BTreeMap<(String, usize), u64> = BTreeMap::new();
    for r in &rows {
        let opened = parse_time(r.get("opened_at"));
        let bucket = aging_bucket((now - opened).num_days());
        let idx = AGING_BUCKETS.iter().position(|b| *b == bucket).unwrap_or(0);
        *counts.entry((r.get("control_id"), idx)).or_default() += r.get::<i64, _>("n") as u64;
    }
    Ok(counts
        .into_iter()
        .map(|((control_id, idx), count)| AgingRow {
            control_id,
            bucket: AGING_BUCKETS[idx].to_string(),
            count,
        })
        .collect())
}

/// Daily flow of `fail` intervals over the last `days` UTC days up to `now` (inclusive of
/// today): `opened` counts intervals whose `opened_at` falls on the day, `closed` counts fail
/// intervals whose `closed_at` falls on the day, whatever the close reason.
pub async fn compliance_flow(
    pool: &SqlitePool,
    scope: &ReportScope,
    days: u32,
    now: DateTime<Utc>,
) -> Result<Vec<FlowRow>> {
    if scope.subscriptions.is_empty() || days == 0 {
        return Ok(Vec::new());
    }
    let since = (now - Duration::days(i64::from(days) - 1)).date_naive();
    let pred = scope_predicate();
    let sql = format!(
        "SELECT day, control_id, SUM(opened) AS opened, SUM(closed) AS closed FROM (
             SELECT date(f.opened_at) AS day, f.control_id, 1 AS opened, 0 AS closed
             FROM finding_intervals f
             WHERE f.outcome = 'fail' AND date(f.opened_at) >= ?3 AND {pred}
             UNION ALL
             SELECT date(f.closed_at) AS day, f.control_id, 0 AS opened, 1 AS closed
             FROM finding_intervals f
             WHERE f.outcome = 'fail' AND f.closed_at IS NOT NULL
               AND date(f.closed_at) >= ?3 AND {pred}
         )
         GROUP BY day, control_id
         ORDER BY day, control_id"
    );
    let rows = sqlx::query(&sql)
        .bind(scope.subs_json())
        .bind(scope.lane.as_deref())
        .bind(since.format("%Y-%m-%d").to_string())
        .fetch_all(pool)
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            let day: Option<String> = r.get("day");
            Some(FlowRow {
                day: NaiveDate::parse_from_str(&day?, "%Y-%m-%d").ok()?,
                control_id: r.get("control_id"),
                opened: r.get::<i64, _>("opened") as u64,
                closed: r.get::<i64, _>("closed") as u64,
            })
        })
        .collect())
}

/// The newest `limit` finished scans (`complete` or `partial`), oldest first.
pub async fn trend_scans(pool: &SqlitePool, limit: i64) -> Result<Vec<TrendScan>> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, started_at, finished_at FROM (
             SELECT id, started_at, finished_at FROM scan_runs
             WHERE finished_at IS NOT NULL AND completeness IN ('complete', 'partial')
             ORDER BY started_at DESC LIMIT ?1)
         ORDER BY started_at",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, s, f)| TrendScan {
            scan_id: id,
            started_at: parse_time(&s),
            finished_at: parse_time(&f),
        })
        .collect())
}

/// Open `fail` count per control and lane at each of the newest `limit` finished scans, from
/// interval overlap. The point in time is the scan's `finished_at`: intervals open in a scan
/// carry the observation time, which is after `started_at`, so overlap at the start would
/// show the previous scan's state. Scans with no open fails have no rows (see
/// [`trend_scans`]). Ordered by scan start, then control.
pub async fn compliance_trend(
    pool: &SqlitePool,
    scope: &ReportScope,
    limit: i64,
) -> Result<Vec<TrendRow>> {
    if scope.subscriptions.is_empty() {
        return Ok(Vec::new());
    }
    let sql = format!(
        "WITH s AS (
             SELECT id, started_at, finished_at FROM scan_runs
             WHERE finished_at IS NOT NULL AND completeness IN ('complete', 'partial')
             ORDER BY started_at DESC LIMIT ?3)
         SELECT s.id AS scan_id, s.started_at, f.control_id, {LANE_SQL} AS lane, COUNT(*) AS n
         FROM s JOIN finding_intervals f
           ON f.outcome = 'fail'
          AND julianday(f.opened_at) <= julianday(s.finished_at)
          AND (f.closed_at IS NULL OR julianday(f.closed_at) > julianday(s.finished_at))
         WHERE {}
         GROUP BY s.id, f.control_id, lane
         ORDER BY s.started_at, f.control_id, lane",
        scope_predicate()
    );
    let rows = sqlx::query(&sql)
        .bind(scope.subs_json())
        .bind(scope.lane.as_deref())
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .iter()
        .map(|r| TrendRow {
            scan_id: r.get("scan_id"),
            scan_started_at: parse_time(r.get("started_at")),
            control_id: r.get("control_id"),
            lane: parse_lane(r.get("lane")),
            open: r.get::<i64, _>("n") as u64,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aging_bucket_upper_bounds_are_inclusive() {
        assert_eq!(aging_bucket(0), "0-7");
        assert_eq!(aging_bucket(7), "0-7");
        assert_eq!(aging_bucket(8), "8-30");
        assert_eq!(aging_bucket(30), "8-30");
        assert_eq!(aging_bucket(31), "31-90");
        assert_eq!(aging_bucket(90), "31-90");
        assert_eq!(aging_bucket(91), "90+");
        assert_eq!(aging_bucket(-1), "0-7", "clock skew stays in the newest bucket");
    }
}
