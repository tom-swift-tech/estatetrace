use anyhow::Result;
use chrono::{DateTime, Utc};
use estatetrace_core::*;
use serde_json::Value;
use sqlx::SqlitePool;
use uuid::Uuid;

pub async fn upsert_tenant(pool: &SqlitePool, t: &TenantInfo) -> Result<()> {
    sqlx::query(
        "INSERT INTO tenants(id, name, needs_sign_in, last_refresh, access_issue)
         VALUES(?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
           name=excluded.name,
           needs_sign_in=excluded.needs_sign_in,
           last_refresh=excluded.last_refresh,
           access_issue=excluded.access_issue",
    )
    .bind(t.id.as_str())
    .bind(&t.name)
    .bind(t.needs_sign_in as i64)
    .bind(t.last_refresh.map(|d| d.to_rfc3339()))
    .bind(&t.access_issue)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn upsert_subscription(pool: &SqlitePool, s: &SubscriptionInfo) -> Result<()> {
    sqlx::query(
        "INSERT INTO subscriptions(id, tenant_id, name, state, quota_id, tags_json, access_issue, last_refresh)
         VALUES(?,?,?,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
           tenant_id=excluded.tenant_id,
           name=excluded.name,
           state=excluded.state,
           quota_id=excluded.quota_id,
           tags_json=excluded.tags_json,
           access_issue=excluded.access_issue,
           last_refresh=excluded.last_refresh",
    )
    .bind(s.id.as_str())
    .bind(s.tenant_id.as_str())
    .bind(&s.name)
    .bind(&s.state)
    .bind(&s.quota_id)
    .bind(s.tags.to_string())
    .bind(&s.access_issue)
    .bind(s.last_refresh.map(|d| d.to_rfc3339()))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_tenants(pool: &SqlitePool) -> Result<Vec<TenantInfo>> {
    let rows = sqlx::query_as::<_, (String, String, i64, Option<String>, Option<String>)>(
        "SELECT id, name, needs_sign_in, last_refresh, access_issue FROM tenants ORDER BY name",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, needs, lr, ai)| TenantInfo {
            id: TenantId::new(id),
            name,
            needs_sign_in: needs != 0,
            last_refresh: lr.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
            access_issue: ai,
        })
        .collect())
}

pub async fn list_subscriptions(pool: &SqlitePool) -> Result<Vec<SubscriptionInfo>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT id, tenant_id, name, state, quota_id, tags_json, access_issue, last_refresh
         FROM subscriptions ORDER BY name",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, tid, name, state, quota, tags, ai, lr)| SubscriptionInfo {
            id: SubscriptionId::new(id),
            tenant_id: TenantId::new(tid),
            name,
            state,
            quota_id: quota,
            tags: serde_json::from_str(&tags).unwrap_or(Value::Object(Default::default())),
            access_issue: ai,
            last_refresh: lr.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
        })
        .collect())
}

pub async fn insert_scope_decision(pool: &SqlitePool, d: &ScopeDecision) -> Result<()> {
    sqlx::query(
        "INSERT INTO scope_decisions(id, provider, tenant_id, subscription_id, decision, source, matching_rule_id, reason, effective_from, effective_to)
         VALUES(?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&d.id)
    .bind(d.provider.as_str())
    .bind(d.tenant_id.as_str())
    .bind(d.subscription_id.as_ref().map(|s| s.as_str().to_string()))
    .bind(d.decision.as_str())
    .bind(d.source.as_str())
    .bind(&d.matching_rule_id)
    .bind(&d.reason)
    .bind(d.effective_from.to_rfc3339())
    .bind(d.effective_to.map(|t| t.to_rfc3339()))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn end_scope_decision(pool: &SqlitePool, id: &str, at: DateTime<Utc>) -> Result<()> {
    sqlx::query("UPDATE scope_decisions SET effective_to = ? WHERE id = ? AND effective_to IS NULL")
        .bind(at.to_rfc3339())
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn active_explicit_decisions(pool: &SqlitePool) -> Result<Vec<ScopeDecision>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
        ),
    >(
        "SELECT id, provider, tenant_id, subscription_id, decision, source, matching_rule_id, reason, effective_from, effective_to
         FROM scope_decisions WHERE effective_to IS NULL AND subscription_id IS NOT NULL AND source = 'explicit'",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, _prov, tid, sid, decision, source, rule, reason, from, to)| ScopeDecision {
                id,
                provider: Provider::Azure,
                tenant_id: TenantId::new(tid),
                subscription_id: sid.map(SubscriptionId::new),
                decision: DecisionKind::parse(&decision).unwrap_or(DecisionKind::AwaitReview),
                source: DecisionSource::parse(&source).unwrap_or(DecisionSource::Explicit),
                matching_rule_id: rule,
                reason,
                effective_from: DateTime::parse_from_rfc3339(&from)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                effective_to: to.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                }),
            },
        )
        .collect())
}

pub async fn list_exclusion_rules(pool: &SqlitePool) -> Result<Vec<ExclusionRule>> {
    let rows = sqlx::query_as::<_, (String, String, Option<String>, String, i64, String)>(
        "SELECT id, name, tenant_id, filter_json, enabled, created_at FROM exclusion_rules",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, tid, filter, en, created)| ExclusionRule {
            id,
            name,
            tenant_id: tid.map(TenantId::new),
            filter: serde_json::from_str(&filter).unwrap_or(ExclusionFilter {
                name_contains: None,
                tag_key: None,
                tag_value: None,
                quota_id: None,
                offer_mapping: None,
            }),
            enabled: en != 0,
            created_at: DateTime::parse_from_rfc3339(&created)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
        .collect())
}

pub async fn upsert_exclusion_rule(pool: &SqlitePool, rule: &ExclusionRule) -> Result<()> {
    sqlx::query(
        "INSERT INTO exclusion_rules(id, name, tenant_id, filter_json, enabled, created_at)
         VALUES(?,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
           name=excluded.name,
           tenant_id=excluded.tenant_id,
           filter_json=excluded.filter_json,
           enabled=excluded.enabled",
    )
    .bind(&rule.id)
    .bind(&rule.name)
    .bind(rule.tenant_id.as_ref().map(|t| t.as_str().to_string()))
    .bind(serde_json::to_string(&rule.filter)?)
    .bind(rule.enabled as i64)
    .bind(rule.created_at.to_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_tenant_default(pool: &SqlitePool, tenant_id: &str) -> Result<Option<TenantDefault>> {
    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT tenant_id, auto_track_new FROM tenant_defaults WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(tid, auto)| TenantDefault {
        tenant_id: TenantId::new(tid),
        auto_track_new: auto != 0,
    }))
}

pub async fn set_tenant_default(pool: &SqlitePool, d: &TenantDefault) -> Result<()> {
    sqlx::query(
        "INSERT INTO tenant_defaults(tenant_id, auto_track_new) VALUES(?,?)
         ON CONFLICT(tenant_id) DO UPDATE SET auto_track_new=excluded.auto_track_new",
    )
    .bind(d.tenant_id.as_str())
    .bind(d.auto_track_new as i64)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn resolve_effective_scope(pool: &SqlitePool) -> Result<Vec<EffectiveScopeRow>> {
    let subs = list_subscriptions(pool).await?;
    let explicit = active_explicit_decisions(pool).await?;
    let rules = list_exclusion_rules(pool).await?;
    let mut out = Vec::with_capacity(subs.len());
    for sub in subs {
        let ex = explicit
            .iter()
            .find(|d| d.subscription_id.as_ref() == Some(&sub.id));
        let td = get_tenant_default(pool, sub.tenant_id.as_str()).await?;
        let (decision, source, reason, rule_id) =
            resolve_subscription_decision(&sub, ex, &rules, td.as_ref());
        out.push(EffectiveScopeRow {
            subscription: sub,
            decision,
            source,
            reason,
            matching_rule_id: rule_id,
        });
    }
    Ok(out)
}

pub async fn tracked_subscription_ids(pool: &SqlitePool) -> Result<Vec<String>> {
    let rows = resolve_effective_scope(pool).await?;
    Ok(rows
        .into_iter()
        .filter(|r| r.decision == DecisionKind::Track)
        .map(|r| r.subscription.id.0)
        .collect())
}

pub async fn create_scan_run(pool: &SqlitePool, source: &str) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO scan_runs(id, source, started_at, finished_at, completeness, error)
         VALUES(?,?,?,?,?,?)",
    )
    .bind(&id)
    .bind(source)
    .bind(Utc::now().to_rfc3339())
    .bind(Option::<String>::None)
    .bind("running")
    .bind(Option::<String>::None)
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn finish_scan_run(
    pool: &SqlitePool,
    id: &str,
    completeness: &str,
    error: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE scan_runs SET finished_at = ?, completeness = ?, error = ? WHERE id = ?",
    )
    .bind(Utc::now().to_rfc3339())
    .bind(completeness)
    .bind(error)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn upsert_coverage(
    pool: &SqlitePool,
    source: &str,
    subscription_id: &str,
    checkpoint: Option<&str>,
    success: bool,
    gap_note: Option<&str>,
) -> Result<()> {
    let id = format!("{source}:{subscription_id}");
    let now = Utc::now().to_rfc3339();
    if success {
        sqlx::query(
            "INSERT INTO source_coverage(id, source, subscription_id, last_success, last_checkpoint, gap_start, gap_end, notes)
             VALUES(?,?,?,?,?,NULL,NULL,?)
             ON CONFLICT(source, subscription_id) DO UPDATE SET
               last_success=excluded.last_success,
               last_checkpoint=excluded.last_checkpoint,
               gap_start=NULL,
               gap_end=NULL,
               notes=excluded.notes",
        )
        .bind(&id)
        .bind(source)
        .bind(subscription_id)
        .bind(&now)
        .bind(checkpoint)
        .bind(gap_note)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO source_coverage(id, source, subscription_id, last_success, last_checkpoint, gap_start, gap_end, notes)
             VALUES(?,?,?,?,NULL,?,?,?)
             ON CONFLICT(source, subscription_id) DO UPDATE SET
               gap_start=COALESCE(source_coverage.gap_start, excluded.gap_start),
               gap_end=excluded.gap_end,
               notes=excluded.notes",
        )
        .bind(&id)
        .bind(source)
        .bind(subscription_id)
        .bind(Option::<String>::None)
        .bind(&now)
        .bind(&now)
        .bind(gap_note)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn get_checkpoint(
    pool: &SqlitePool,
    source: &str,
    subscription_id: &str,
) -> Result<Option<String>> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT last_checkpoint FROM source_coverage WHERE source = ? AND subscription_id = ?",
    )
    .bind(source)
    .bind(subscription_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.0))
}

pub async fn insert_observation(pool: &SqlitePool, obs: &ResourceObservation) -> Result<()> {
    sqlx::query(
        "INSERT INTO resource_observations(
            id, provider, resource_id, tenant_id, subscription_id, resource_type, name,
            location, resource_group, tags_json, properties_json, scan_id, observation_time,
            evidence_available, lifecycle_epoch)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&obs.id)
    .bind(obs.provider.as_str())
    .bind(obs.resource_id.as_str())
    .bind(obs.tenant_id.as_str())
    .bind(obs.subscription_id.as_str())
    .bind(&obs.resource_type)
    .bind(&obs.name)
    .bind(&obs.location)
    .bind(&obs.resource_group)
    .bind(obs.tags.to_string())
    .bind(obs.properties.to_string())
    .bind(&obs.scan_id)
    .bind(obs.observation_time.to_rfc3339())
    .bind(obs.evidence_available as i64)
    .bind(obs.lifecycle_epoch)
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO latest_resources(resource_id, observation_id, subscription_id, last_seen, missing)
         VALUES(?,?,?,?,0)
         ON CONFLICT(resource_id) DO UPDATE SET
           observation_id=excluded.observation_id,
           subscription_id=excluded.subscription_id,
           last_seen=excluded.last_seen,
           missing=0",
    )
    .bind(obs.resource_id.as_str())
    .bind(&obs.id)
    .bind(obs.subscription_id.as_str())
    .bind(obs.observation_time.to_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_missing(
    pool: &SqlitePool,
    resource_id: &str,
    last_seen: DateTime<Utc>,
) -> Result<()> {
    sqlx::query("UPDATE latest_resources SET missing = 1, last_seen = ? WHERE resource_id = ?")
        .bind(last_seen.to_rfc3339())
        .bind(resource_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn latest_observation(
    pool: &SqlitePool,
    resource_id: &str,
) -> Result<Option<ResourceObservation>> {
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            String,
            String,
            String,
            i64,
            i64,
        ),
    >(
        "SELECT o.id, o.provider, o.resource_id, o.tenant_id, o.subscription_id, o.resource_type, o.name,
                o.location, o.resource_group, o.tags_json, o.properties_json, o.scan_id, o.observation_time,
                o.evidence_available, o.lifecycle_epoch
         FROM latest_resources l
         JOIN resource_observations o ON o.id = l.observation_id
         WHERE l.resource_id = ?",
    )
    .bind(resource_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(map_obs))
}

pub async fn list_latest_resources(pool: &SqlitePool) -> Result<Vec<ResourceObservation>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            String,
            String,
            String,
            i64,
            i64,
        ),
    >(
        "SELECT o.id, o.provider, o.resource_id, o.tenant_id, o.subscription_id, o.resource_type, o.name,
                o.location, o.resource_group, o.tags_json, o.properties_json, o.scan_id, o.observation_time,
                o.evidence_available, o.lifecycle_epoch
         FROM latest_resources l
         JOIN resource_observations o ON o.id = l.observation_id
         ORDER BY o.name",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(map_obs).collect())
}

fn map_obs(
    row: (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        String,
        i64,
        i64,
    ),
) -> ResourceObservation {
    let (
        id,
        _prov,
        rid,
        tid,
        sid,
        rtype,
        name,
        loc,
        rg,
        tags,
        props,
        scan,
        ot,
        evidence,
        epoch,
    ) = row;
    ResourceObservation {
        id,
        provider: Provider::Azure,
        resource_id: ResourceId::new(rid),
        tenant_id: TenantId::new(tid),
        subscription_id: SubscriptionId::new(sid),
        resource_type: rtype,
        name,
        location: loc,
        resource_group: rg,
        tags: serde_json::from_str(&tags).unwrap_or(Value::Object(Default::default())),
        properties: serde_json::from_str(&props).unwrap_or(Value::Object(Default::default())),
        scan_id: scan,
        observation_time: DateTime::parse_from_rfc3339(&ot)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        evidence_available: evidence != 0,
        lifecycle_epoch: epoch,
    }
}

pub async fn insert_change_event(pool: &SqlitePool, ev: &ChangeEvent) -> Result<bool> {
    let res = sqlx::query(
        "INSERT OR IGNORE INTO change_events(
            id, resource_id, subscription_id, source_event_id, label, event_time, observation_time,
            before_json, after_json, property_diffs_json)
         VALUES(?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&ev.id)
    .bind(ev.resource_id.as_str())
    .bind(ev.subscription_id.as_str())
    .bind(&ev.source_event_id)
    .bind(ev.label.as_str())
    .bind(ev.times.event_time.map(|t| t.to_rfc3339()))
    .bind(ev.times.observation_time.to_rfc3339())
    .bind(ev.before.as_ref().map(|v| v.to_string()))
    .bind(ev.after.as_ref().map(|v| v.to_string()))
    .bind(ev.property_diffs.to_string())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn list_changes_for_resource(pool: &SqlitePool, resource_id: &str) -> Result<Vec<ChangeEvent>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            String,
        ),
    >(
        "SELECT id, resource_id, subscription_id, source_event_id, label, event_time, observation_time,
                before_json, after_json, property_diffs_json
         FROM change_events WHERE resource_id = ? ORDER BY observation_time DESC",
    )
    .bind(resource_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, rid, sid, seid, label, et, ot, before, after, diffs)| ChangeEvent {
                id,
                resource_id: ResourceId::new(rid),
                subscription_id: SubscriptionId::new(sid),
                source_event_id: seid,
                label: match label.as_str() {
                    "created" => ChangeLabel::Created,
                    "updated" => ChangeLabel::Updated,
                    "missing_from_scan" => ChangeLabel::MissingFromScan,
                    "confirmed_deleted" => ChangeLabel::ConfirmedDeleted,
                    _ => ChangeLabel::NewToInventory,
                },
                times: DualTime {
                    event_time: et.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|d| d.with_timezone(&Utc))
                    }),
                    observation_time: DateTime::parse_from_rfc3339(&ot)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                },
                before: before.and_then(|s| serde_json::from_str(&s).ok()),
                after: after.and_then(|s| serde_json::from_str(&s).ok()),
                property_diffs: serde_json::from_str(&diffs).unwrap_or(Value::Object(Default::default())),
            },
        )
        .collect())
}

pub async fn list_recent_changes(pool: &SqlitePool, limit: i64) -> Result<Vec<ChangeEvent>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            String,
        ),
    >(
        "SELECT id, resource_id, subscription_id, source_event_id, label, event_time, observation_time,
                before_json, after_json, property_diffs_json
         FROM change_events ORDER BY observation_time DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, rid, sid, seid, label, et, ot, before, after, diffs)| ChangeEvent {
                id,
                resource_id: ResourceId::new(rid),
                subscription_id: SubscriptionId::new(sid),
                source_event_id: seid,
                label: match label.as_str() {
                    "created" => ChangeLabel::Created,
                    "updated" => ChangeLabel::Updated,
                    "missing_from_scan" => ChangeLabel::MissingFromScan,
                    "confirmed_deleted" => ChangeLabel::ConfirmedDeleted,
                    _ => ChangeLabel::NewToInventory,
                },
                times: DualTime {
                    event_time: et.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|d| d.with_timezone(&Utc))
                    }),
                    observation_time: DateTime::parse_from_rfc3339(&ot)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                },
                before: before.and_then(|s| serde_json::from_str(&s).ok()),
                after: after.and_then(|s| serde_json::from_str(&s).ok()),
                property_diffs: serde_json::from_str(&diffs).unwrap_or(Value::Object(Default::default())),
            },
        )
        .collect())
}

pub async fn list_coverage(pool: &SqlitePool) -> Result<Vec<SourceCoverage>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT id, source, subscription_id, last_success, last_checkpoint, gap_start, gap_end, notes FROM source_coverage",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, source, sid, ls, cp, gs, ge, notes)| SourceCoverage {
            id,
            source,
            subscription_id: SubscriptionId::new(sid),
            last_success: ls.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }),
            last_checkpoint: cp,
            gap_start: gs.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }),
            gap_end: ge.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }),
            notes,
        })
        .collect())
}

pub async fn upsert_classification_rule(pool: &SqlitePool, rule: &ClassificationRule) -> Result<()> {
    sqlx::query(
        "INSERT INTO classification_rules(id, kind, subscription_id, resource_group, tag_key, tag_value, environment, priority)
         VALUES(?,?,?,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
           kind=excluded.kind,
           subscription_id=excluded.subscription_id,
           resource_group=excluded.resource_group,
           tag_key=excluded.tag_key,
           tag_value=excluded.tag_value,
           environment=excluded.environment,
           priority=excluded.priority",
    )
    .bind(&rule.id)
    .bind(match rule.kind {
        ClassificationRuleKind::Subscription => "subscription",
        ClassificationRuleKind::ResourceGroup => "resource_group",
        ClassificationRuleKind::Tag => "tag",
    })
    .bind(rule.subscription_id.as_ref().map(|s| s.as_str().to_string()))
    .bind(&rule.resource_group)
    .bind(&rule.tag_key)
    .bind(&rule.tag_value)
    .bind(rule.environment.as_str())
    .bind(rule.priority)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_classification_rules(pool: &SqlitePool) -> Result<Vec<ClassificationRule>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            i64,
        ),
    >(
        "SELECT id, kind, subscription_id, resource_group, tag_key, tag_value, environment, priority FROM classification_rules",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, kind, sid, rg, tk, tv, env, pri)| ClassificationRule {
            id,
            kind: match kind.as_str() {
                "resource_group" => ClassificationRuleKind::ResourceGroup,
                "tag" => ClassificationRuleKind::Tag,
                _ => ClassificationRuleKind::Subscription,
            },
            subscription_id: sid.map(SubscriptionId::new),
            resource_group: rg,
            tag_key: tk,
            tag_value: tv,
            environment: EnvironmentClass::parse(&env).unwrap_or(EnvironmentClass::Unknown),
            priority: pri as i32,
        })
        .collect())
}

pub async fn save_policy_pack(
    pool: &SqlitePool,
    id: &str,
    name: &str,
    revision: &str,
    owner: Option<&str>,
    reviewed_by: Option<&str>,
    activated: bool,
    content: &Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO policy_packs(id, name, revision, owner, activated, reviewed_by, content_json, created_at)
         VALUES(?,?,?,?,?,?,?,?)
         ON CONFLICT(id, revision) DO UPDATE SET
           name=excluded.name,
           owner=excluded.owner,
           activated=excluded.activated,
           reviewed_by=excluded.reviewed_by,
           content_json=excluded.content_json",
    )
    .bind(id)
    .bind(name)
    .bind(revision)
    .bind(owner)
    .bind(activated as i64)
    .bind(reviewed_by)
    .bind(content.to_string())
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_policy_packs(pool: &SqlitePool) -> Result<Vec<Value>> {
    let rows = sqlx::query_as::<
        _,
        (String, String, String, Option<String>, i64, Option<String>, String, String),
    >(
        "SELECT id, name, revision, owner, activated, reviewed_by, content_json, created_at FROM policy_packs ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, rev, owner, act, rev_by, content, created)| {
            serde_json::json!({
                "id": id,
                "name": name,
                "revision": rev,
                "owner": owner,
                "activated": act != 0,
                "reviewed_by": rev_by,
                "content": serde_json::from_str::<Value>(&content).unwrap_or(Value::Null),
                "created_at": created,
            })
        })
        .collect())
}

pub async fn active_policy_packs(pool: &SqlitePool) -> Result<Vec<Value>> {
    let rows = sqlx::query_as::<_, (String, String, String)>(
        "SELECT id, revision, content_json FROM policy_packs WHERE activated = 1",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, rev, content)| {
            serde_json::json!({
                "id": id,
                "revision": rev,
                "content": serde_json::from_str::<Value>(&content).unwrap_or(Value::Null),
            })
        })
        .collect())
}

pub async fn insert_evaluation(pool: &SqlitePool, ev: &Evaluation) -> Result<()> {
    sqlx::query(
        "INSERT INTO evaluations(id, observation_id, resource_id, control_id, control_revision, outcome, severity, evidence_json, evaluated_at)
         VALUES(?,?,?,?,?,?,?,?,?)",
    )
    .bind(&ev.id)
    .bind(&ev.observation_id)
    .bind(ev.resource_id.as_str())
    .bind(&ev.control_id)
    .bind(&ev.control_revision)
    .bind(ev.outcome.as_str())
    .bind(ev.severity.as_str())
    .bind(ev.evidence.to_string())
    .bind(ev.evaluated_at.to_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_evaluations(pool: &SqlitePool, limit: i64) -> Result<Vec<Evaluation>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        ),
    >(
        "SELECT id, observation_id, resource_id, control_id, control_revision, outcome, severity, evidence_json, evaluated_at
         FROM evaluations ORDER BY evaluated_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, oid, rid, cid, crev, outcome, sev, evidence, at)| {
            let evidence: Value = serde_json::from_str(&evidence).unwrap_or(Value::Null);
            // `detail` and `environment` live in evidence_json until the findings store replaces
            // this table (spec §4.4); older rows have neither.
            let detail = evidence
                .get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let environment = evidence
                .get("environment")
                .and_then(|v| v.as_str())
                .and_then(EnvironmentClass::parse)
                .unwrap_or(EnvironmentClass::Unknown);
            Evaluation {
                id,
                observation_id: oid,
                resource_id: ResourceId::new(rid),
                control_id: cid,
                control_revision: crev,
                outcome: EvalOutcome::parse(&outcome).unwrap_or(EvalOutcome::Unknown),
                severity: Severity::parse(&sev).unwrap_or(Severity::Medium),
                evidence,
                evaluated_at: DateTime::parse_from_rfc3339(&at)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                environment,
                detail,
            }
        })
        .collect())
}

pub async fn insert_export_artifact(
    pool: &SqlitePool,
    id: &str,
    pack_id: &str,
    pack_revision: &str,
    control_id: &str,
    state: &str,
    target_scope: &Value,
    parameters: &Value,
    bicep: Option<&str>,
    mapping: &Value,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO export_artifacts(id, pack_id, pack_revision, control_id, state, target_scope_json, parameters_json, bicep_text, mapping_json, created_at, updated_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(id)
    .bind(pack_id)
    .bind(pack_revision)
    .bind(control_id)
    .bind(state)
    .bind(target_scope.to_string())
    .bind(parameters.to_string())
    .bind(bicep)
    .bind(mapping.to_string())
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_export_state(
    pool: &SqlitePool,
    id: &str,
    state: &str,
    evidence: &Value,
) -> Result<()> {
    sqlx::query(
        "UPDATE export_artifacts SET state = ?, evidence_json = ?, updated_at = ? WHERE id = ?",
    )
    .bind(state)
    .bind(evidence.to_string())
    .bind(Utc::now().to_rfc3339())
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_exports(pool: &SqlitePool) -> Result<Vec<Value>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
            String,
            String,
            String,
        ),
    >(
        "SELECT id, pack_id, pack_revision, control_id, state, target_scope_json, parameters_json, bicep_text, mapping_json, created_at, updated_at, evidence_json
         FROM export_artifacts ORDER BY updated_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, pack, prev, cid, state, scope, params, bicep, mapping, created, updated, evidence)| {
                serde_json::json!({
                    "id": id,
                    "pack_id": pack,
                    "pack_revision": prev,
                    "control_id": cid,
                    "state": state,
                    "target_scope": serde_json::from_str::<Value>(&scope).unwrap_or(Value::Null),
                    "parameters": serde_json::from_str::<Value>(&params).unwrap_or(Value::Null),
                    "bicep": bicep,
                    "mapping": serde_json::from_str::<Value>(&mapping).unwrap_or(Value::Null),
                    "created_at": created,
                    "updated_at": updated,
                    "evidence": serde_json::from_str::<Value>(&evidence).unwrap_or(Value::Null),
                })
            },
        )
        .collect())
}

pub async fn save_view(pool: &SqlitePool, view: &SavedView) -> Result<()> {
    sqlx::query(
        "INSERT INTO saved_views(id, name, filter_json, group_by, sort_by, updated_at)
         VALUES(?,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET
           name=excluded.name,
           filter_json=excluded.filter_json,
           group_by=excluded.group_by,
           sort_by=excluded.sort_by,
           updated_at=excluded.updated_at",
    )
    .bind(&view.id)
    .bind(&view.name)
    .bind(serde_json::to_string(&view.filter)?)
    .bind(&view.group_by)
    .bind(&view.sort_by)
    .bind(view.updated_at.to_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_views(pool: &SqlitePool) -> Result<Vec<SavedView>> {
    let rows = sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>, String)>(
        "SELECT id, name, filter_json, group_by, sort_by, updated_at FROM saved_views",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, filter, group, sort, updated)| SavedView {
            id,
            name,
            filter: serde_json::from_str(&filter).unwrap_or_default(),
            group_by: group,
            sort_by: sort,
            updated_at: DateTime::parse_from_rfc3339(&updated)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
        .collect())
}

pub async fn set_connector_status(
    pool: &SqlitePool,
    name: &str,
    configured: bool,
    last_test_ok: Option<bool>,
    detail: &Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO connector_status(name, configured, last_test_ok, last_test_at, detail_json)
         VALUES(?,?,?,?,?)
         ON CONFLICT(name) DO UPDATE SET
           configured=excluded.configured,
           last_test_ok=excluded.last_test_ok,
           last_test_at=excluded.last_test_at,
           detail_json=excluded.detail_json",
    )
    .bind(name)
    .bind(configured as i64)
    .bind(last_test_ok.map(|b| b as i64))
    .bind(Utc::now().to_rfc3339())
    .bind(detail.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_connector_status(pool: &SqlitePool, name: &str) -> Result<Option<Value>> {
    let row: Option<(i64, Option<i64>, Option<String>, String)> = sqlx::query_as(
        "SELECT configured, last_test_ok, last_test_at, detail_json FROM connector_status WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(cfg, ok, at, detail)| {
        serde_json::json!({
            "configured": cfg != 0,
            "last_test_ok": ok.map(|v| v != 0),
            "last_test_at": at,
            "detail": serde_json::from_str::<Value>(&detail).unwrap_or(Value::Null),
        })
    }))
}

pub async fn insert_ticket_relationship(
    pool: &SqlitePool,
    resource_id: Option<&str>,
    change_id: Option<&str>,
    owning_service: Option<&str>,
    instance_url: &str,
    record_id: &str,
    record_number: Option<&str>,
    relationship_type: &str,
    evidence: &Value,
    lookup_status: &str,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO ticket_relationships(id, resource_id, change_id, owning_service, instance_url, record_id, record_number, relationship_type, evidence_json, lookup_status, created_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&id)
    .bind(resource_id)
    .bind(change_id)
    .bind(owning_service)
    .bind(instance_url)
    .bind(record_id)
    .bind(record_number)
    .bind(relationship_type)
    .bind(evidence.to_string())
    .bind(lookup_status)
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn list_ticket_relationships(pool: &SqlitePool, resource_id: &str) -> Result<Vec<Value>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            String,
            Option<String>,
            String,
            String,
            String,
            String,
        ),
    >(
        "SELECT id, resource_id, change_id, owning_service, instance_url, record_id, record_number, relationship_type, evidence_json, lookup_status, created_at
         FROM ticket_relationships WHERE resource_id = ?",
    )
    .bind(resource_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, rid, cid, svc, url, record, number, rtype, evidence, status, created)| {
                serde_json::json!({
                    "id": id,
                    "resource_id": rid,
                    "change_id": cid,
                    "owning_service": svc,
                    "instance_url": url,
                    "record_id": record,
                    "record_number": number,
                    "relationship_type": rtype,
                    "evidence": serde_json::from_str::<Value>(&evidence).unwrap_or(Value::Null),
                    "lookup_status": status,
                    "created_at": created,
                })
            },
        )
        .collect())
}

pub async fn replace_queue_cache(
    pool: &SqlitePool,
    queue_name: &str,
    instance_url: &str,
    refresh_instant: &str,
    records: &[(String, Value)],
) -> Result<()> {
    sqlx::query("DELETE FROM sn_queue_cache WHERE queue_name = ? AND instance_url = ?")
        .bind(queue_name)
        .bind(instance_url)
        .execute(pool)
        .await?;
    for (record_id, payload) in records {
        sqlx::query(
            "INSERT INTO sn_queue_cache(queue_name, record_id, instance_url, payload_json, refresh_instant)
             VALUES(?,?,?,?,?)",
        )
        .bind(queue_name)
        .bind(record_id)
        .bind(instance_url)
        .bind(payload.to_string())
        .bind(refresh_instant)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn get_queue_cache(pool: &SqlitePool, queue_name: &str) -> Result<Vec<Value>> {
    let rows = sqlx::query_as::<_, (String,)>(
        "SELECT payload_json FROM sn_queue_cache WHERE queue_name = ? ORDER BY record_id",
    )
    .bind(queue_name)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(p,)| serde_json::from_str(&p).ok())
        .collect())
}

pub async fn set_queue_meta(
    pool: &SqlitePool,
    queue_name: &str,
    last_success: Option<&str>,
    stale: bool,
    unavailable: bool,
    error: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO sn_queue_meta(queue_name, last_success, last_refresh, stale, unavailable, error)
         VALUES(?,?,?,?,?,?)
         ON CONFLICT(queue_name) DO UPDATE SET
           last_success=COALESCE(excluded.last_success, sn_queue_meta.last_success),
           last_refresh=excluded.last_refresh,
           stale=excluded.stale,
           unavailable=excluded.unavailable,
           error=excluded.error",
    )
    .bind(queue_name)
    .bind(last_success)
    .bind(Utc::now().to_rfc3339())
    .bind(stale as i64)
    .bind(unavailable as i64)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_queue_meta(pool: &SqlitePool) -> Result<Vec<Value>> {
    let rows = sqlx::query_as::<
        _,
        (String, Option<String>, Option<String>, i64, i64, Option<String>),
    >(
        "SELECT queue_name, last_success, last_refresh, stale, unavailable, error FROM sn_queue_meta",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(name, ls, lr, stale, unavail, err)| {
            serde_json::json!({
                "queue_name": name,
                "last_success": ls,
                "last_refresh": lr,
                "stale": stale != 0,
                "unavailable": unavail != 0,
                "error": err,
            })
        })
        .collect())
}

pub async fn save_incident_lookup(
    pool: &SqlitePool,
    incident_id: &str,
    anchor_time: Option<&str>,
    anchor_source: Option<&str>,
    lookback_hours: i64,
    matched: &Value,
    coverage: &Value,
    query_scope: &Value,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO incident_change_lookups(id, incident_id, anchor_time, anchor_source, lookback_hours, matched_json, coverage_json, query_scope_json, created_at)
         VALUES(?,?,?,?,?,?,?,?,?)",
    )
    .bind(&id)
    .bind(incident_id)
    .bind(anchor_time)
    .bind(anchor_source)
    .bind(lookback_hours)
    .bind(matched.to_string())
    .bind(coverage.to_string())
    .bind(query_scope.to_string())
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn insert_exception(pool: &SqlitePool, ex: &ExceptionRecord) -> Result<()> {
    sqlx::query(
        "INSERT INTO exceptions(id, resource_id, control_id, reason, approved_by, expires_at, created_at)
         VALUES(?,?,?,?,?,?,?)",
    )
    .bind(&ex.id)
    .bind(&ex.resource_id)
    .bind(&ex.control_id)
    .bind(&ex.reason)
    .bind(&ex.approved_by)
    .bind(ex.expires_at.map(|d| d.to_rfc3339()))
    .bind(ex.created_at.to_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_exceptions(
    pool: &SqlitePool,
    resource_id: Option<&str>,
) -> Result<Vec<ExceptionRecord>> {
    let rows = if let Some(rid) = resource_id {
        sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>, Option<String>, String)>(
            "SELECT id, resource_id, control_id, reason, approved_by, expires_at, created_at
             FROM exceptions WHERE resource_id = ? ORDER BY created_at DESC",
        )
        .bind(rid)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>, Option<String>, String)>(
            "SELECT id, resource_id, control_id, reason, approved_by, expires_at, created_at
             FROM exceptions ORDER BY created_at DESC LIMIT 500",
        )
        .fetch_all(pool)
        .await?
    };
    Ok(rows
        .into_iter()
        .map(|(id, rid, cid, reason, approved, exp, created)| ExceptionRecord {
            id,
            resource_id: rid,
            control_id: cid,
            reason,
            approved_by: approved,
            expires_at: exp.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|d| d.with_timezone(&Utc))
            }),
            created_at: DateTime::parse_from_rfc3339(&created)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
        .collect())
}

pub async fn count_active_exceptions(pool: &SqlitePool) -> Result<i64> {
    let now = Utc::now().to_rfc3339();
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM exceptions
         WHERE expires_at IS NULL OR expires_at > ?",
    )
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn insert_disposition(pool: &SqlitePool, d: &DispositionRecord) -> Result<()> {
    sqlx::query(
        "INSERT INTO dispositions(id, evaluation_id, owner, disposition, ticket_ref, created_at)
         VALUES(?,?,?,?,?,?)",
    )
    .bind(&d.id)
    .bind(&d.evaluation_id)
    .bind(&d.owner)
    .bind(&d.disposition)
    .bind(&d.ticket_ref)
    .bind(d.created_at.to_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_dispositions(
    pool: &SqlitePool,
    evaluation_id: Option<&str>,
) -> Result<Vec<DispositionRecord>> {
    let rows = if let Some(eid) = evaluation_id {
        sqlx::query_as::<_, (String, String, Option<String>, String, Option<String>, String)>(
            "SELECT id, evaluation_id, owner, disposition, ticket_ref, created_at
             FROM dispositions WHERE evaluation_id = ? ORDER BY created_at DESC",
        )
        .bind(eid)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, (String, String, Option<String>, String, Option<String>, String)>(
            "SELECT id, evaluation_id, owner, disposition, ticket_ref, created_at
             FROM dispositions ORDER BY created_at DESC LIMIT 500",
        )
        .fetch_all(pool)
        .await?
    };
    Ok(rows
        .into_iter()
        .map(|(id, eid, owner, disposition, ticket, created)| DispositionRecord {
            id,
            evaluation_id: eid,
            owner,
            disposition,
            ticket_ref: ticket,
            created_at: DateTime::parse_from_rfc3339(&created)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
        .collect())
}

pub async fn latest_disposition_for_evaluation(
    pool: &SqlitePool,
    evaluation_id: &str,
) -> Result<Option<DispositionRecord>> {
    let rows = list_dispositions(pool, Some(evaluation_id)).await?;
    Ok(rows.into_iter().next())
}

/// Replace the stored coverage gaps of one pack with this scan's gaps (spec §4.4, AC-P1-8).
/// Runs in one transaction, so readers never see a half-written set.
pub async fn replace_coverage_gaps(
    pool: &SqlitePool,
    pack_id: &str,
    pack_revision: &str,
    scan_id: &str,
    gaps: &[CoverageGap],
) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM coverage_gaps WHERE pack_id = ?")
        .bind(pack_id)
        .execute(&mut *tx)
        .await?;
    for g in gaps {
        sqlx::query(
            "INSERT INTO coverage_gaps(pack_id, pack_revision, control_id, resource_type, category, note, resource_count, recorded_scan_id)
             VALUES(?,?,?,?,?,?,?,?)
             ON CONFLICT(pack_id, control_id, resource_type) DO UPDATE SET
               pack_revision=excluded.pack_revision,
               category=excluded.category,
               note=excluded.note,
               resource_count=excluded.resource_count,
               recorded_scan_id=excluded.recorded_scan_id",
        )
        .bind(pack_id)
        .bind(pack_revision)
        .bind(&g.control_id)
        .bind(g.resource_type.as_deref().unwrap_or(""))
        .bind(g.category.as_str())
        .bind(&g.note)
        .bind(g.resource_count as i64)
        .bind(scan_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Stored coverage gaps, optionally for one pack, ordered by pack, control and type.
pub async fn list_coverage_gaps(
    pool: &SqlitePool,
    pack_id: Option<&str>,
) -> Result<Vec<CoverageGap>> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, i64)>(
        "SELECT pack_id, control_id, resource_type, category, note, resource_count
         FROM coverage_gaps
         WHERE (?1 IS NULL OR pack_id = ?1)
         ORDER BY pack_id, control_id, resource_type",
    )
    .bind(pack_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(pack_id, control_id, rtype, category, note, count)| CoverageGap {
                pack_id,
                control_id,
                category: GapCategory::parse(&category).unwrap_or(GapCategory::MoreCollection),
                note,
                resource_type: if rtype.is_empty() { None } else { Some(rtype) },
                resource_count: count.max(0) as u64,
            },
        )
        .collect())
}