use crate::scan;
use crate::state::{save_settings, AppState};
use crate::static_files::static_handler;
use crate::theme::{load_theme, neutral_theme, theme_preview_payload};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use estatetrace_azure::{discover_tenants_and_subscriptions, suggested_offer_searches};
use estatetrace_core::*;
use estatetrace_db as db;
use estatetrace_integrations::{
    ChatClient, ChatConfig, ServiceNowClient, ServiceNowConfig, ApprovedChatContext,
};
use estatetrace_policy::{
    builtin_resource_kinds, coverage_report, parse_pack_json, parse_pack_yaml, pilot_pack,
    run_example_cases, validate_pack as lint_and_validate_pack,
    suggest_and_preview, PolicyPack,
};
use serde::Deserialize;
use serde_json::{json, Value};
use http::HeaderValue;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use uuid::Uuid;

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/session", get(session))
        .route("/azure/refresh", post(azure_refresh))
        .route("/scope", get(get_scope))
        .route("/subscriptions", get(list_subscriptions))
        .route("/scope/decision", post(set_decision))
        .route("/scope/exclusion-rules", get(list_rules).post(save_rule))
        .route("/scope/exclusion-preview", post(preview_exclusion))
        .route("/scope/tenant-default", post(set_tenant_default))
        .route("/scope/suggestions", get(suggestions))
        .route("/scan", post(trigger_scan))
        .route("/resources", get(list_resources))
        .route("/resources/{id}/timeline", get(resource_timeline))
        .route("/changes", get(list_changes))
        .route("/coverage", get(coverage))
        .route("/inbox", get(inbox))
        .route("/findings", get(list_findings_api))
        .route("/compliance", get(compliance_summary))
        .route("/compliance/queue", get(compliance_queue_api))
        .route("/compliance/aging", get(compliance_aging_api))
        .route("/compliance/flow", get(compliance_flow_api))
        .route("/compliance/trend", get(compliance_trend_api))
        .route("/exceptions", get(list_exceptions_api).post(create_exception))
        .route("/dispositions", get(list_dispositions_api).post(create_disposition))
        .route("/classification/rules", get(list_class_rules).post(save_class_rule))
        .route("/classification/suggested-rules", get(suggested_class_rules))
        .route("/classification/quality", get(classification_quality))
        .route("/packs", get(list_packs).post(import_pack))
        .route("/packs/pilot", post(load_pilot))
        .route("/packs/{id}/activate", post(activate_pack))
        .route("/packs/{id}/deactivate", post(deactivate_pack))
        .route("/packs/validate", post(validate_pack))
        .route("/packs/compile", post(compile_pack))
        .route("/exports/preview", post(export_preview))
        .route("/exports", get(list_exports_api).post(create_export))
        .route("/exports/{id}/state", post(update_export))
        .route("/views", get(list_views_api).post(save_view_api))
        .route("/settings", get(get_settings).post(update_settings))
        .route("/theme", get(get_theme).post(set_theme))
        .route("/connectors/servicenow/test", post(snow_test))
        .route("/connectors/servicenow/disconnect", post(snow_disconnect))
        .route("/connectors/servicenow/queues", get(snow_queues).post(snow_refresh_queues))
        .route("/connectors/servicenow/lookup", post(snow_lookup))
        .route(
            "/connectors/servicenow/incidents/{id}/changes-before",
            get(snow_changes_before),
        )
        .route("/connectors/chat/test", post(chat_test))
        .route("/connectors/chat/disconnect", post(chat_disconnect))
        .route("/connectors/chat/ask", post(chat_ask))
        .route("/connectors/status", get(connectors_status))
        .route("/backup", post(do_backup))
        .route("/evidence/export", post(evidence_export))
        .with_state(state.clone());

    Router::new()
        .nest("/api", api)
        .fallback(static_handler)
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
                    origin
                        .to_str()
                        .map(is_loopback_origin)
                        .unwrap_or(false)
                }))
                .allow_methods(Any)
                .allow_headers(Any),
        )
}

fn require_session(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let token = headers
        .get("x-session-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if token == state.session_token {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Strict Origin check for CORS and mutations (issue #3).
/// Parses as a URL; requires http/https, no userinfo, and an exact loopback host.
fn is_loopback_origin(origin: &str) -> bool {
    if origin.eq_ignore_ascii_case("null") {
        return false;
    }
    let Ok(parsed) = url::Url::parse(origin) else {
        return false;
    };
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return false,
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        // [::1] is loopback; allowed when dual-stack clients send it.
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

fn origin_ok(headers: &HeaderMap) -> bool {
    match headers.get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok()) {
        None => true, // same-origin navigations / non-browser tools
        Some(o) => is_loopback_origin(o),
    }
}

fn require_mutation(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    require_session(state, headers)?;
    if !origin_ok(headers) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true, "service": "estatetrace" }))
}

async fn session(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "token": state.session_token }))
}

async fn azure_refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let (tenants, subs) = discover_tenants_and_subscriptions()
        .await
        .map_err(|e| {
            tracing::error!("Azure discovery failed: {e:#}");
            StatusCode::BAD_GATEWAY
        })?;
    for t in &tenants {
        db::upsert_tenant(&state.pool, t)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    for s in &subs {
        db::upsert_subscription(&state.pool, s)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(Json(json!({
        "tenants": tenants.len(),
        "subscriptions": subs.len(),
    })))
}

async fn get_scope(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let rows = db::resolve_effective_scope(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "rows": rows })))
}

async fn list_subscriptions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let subscriptions = db::list_subscriptions(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "subscriptions": subscriptions })))
}

#[derive(Deserialize)]
struct DecisionReq {
    tenant_id: String,
    subscription_id: String,
    decision: String,
    reason: Option<String>,
}

async fn set_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DecisionReq>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let decision = DecisionKind::parse(&req.decision).ok_or(StatusCode::BAD_REQUEST)?;
    // End prior explicit decision
    let existing = db::active_explicit_decisions(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for d in existing {
        if d.subscription_id.as_ref().map(|s| s.as_str()) == Some(req.subscription_id.as_str()) {
            db::end_scope_decision(&state.pool, &d.id, Utc::now())
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
    }
    let row = ScopeDecision {
        id: Uuid::new_v4().to_string(),
        provider: Provider::Azure,
        tenant_id: TenantId::new(req.tenant_id),
        subscription_id: Some(SubscriptionId::new(req.subscription_id)),
        decision,
        source: DecisionSource::Explicit,
        matching_rule_id: None,
        reason: req.reason,
        effective_from: Utc::now(),
        effective_to: None,
    };
    db::insert_scope_decision(&state.pool, &row)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "id": row.id })))
}

async fn list_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let rules = db::list_exclusion_rules(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "rules": rules })))
}

async fn save_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(rule): Json<ExclusionRule>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let mut rule = rule;
    if rule.id.is_empty() {
        rule.id = Uuid::new_v4().to_string();
    }
    if rule.created_at.timestamp() == 0 {
        rule.created_at = Utc::now();
    }
    db::upsert_exclusion_rule(&state.pool, &rule)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "id": rule.id })))
}

async fn preview_exclusion(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(filter): Json<ExclusionFilter>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let subs = db::list_subscriptions(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let matched: Vec<_> = subs.iter().filter(|s| filter.matches(s)).collect();
    Ok(Json(json!({
        "match_count": matched.len(),
        "sample_names": matched.iter().take(10).map(|s| s.name.clone()).collect::<Vec<_>>(),
        "reasons": matched.iter().take(10).map(|s| filter.match_reason(s)).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct TenantDefaultReq {
    tenant_id: String,
    auto_track_new: bool,
}

async fn set_tenant_default(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TenantDefaultReq>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    db::set_tenant_default(
        &state.pool,
        &TenantDefault {
            tenant_id: TenantId::new(req.tenant_id),
            auto_track_new: req.auto_track_new,
        },
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "ok": true })))
}

async fn suggestions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    Ok(Json(json!({ "offers": suggested_offer_searches() })))
}

#[derive(Deserialize, Default)]
struct ScanReq {
    subscription_ids: Option<Vec<String>>,
}

async fn trigger_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<ScanReq>>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let subscription_ids = body
        .and_then(|Json(req)| req.subscription_ids)
        .filter(|ids| !ids.is_empty());
    tokio::spawn({
        let state = state.clone();
        async move {
            let result = match subscription_ids.as_deref() {
                Some(ids) => scan::run_scan_for(&state, Some(ids)).await,
                None => scan::run_scan(&state).await,
            };
            if let Err(e) = result {
                tracing::error!("scan error: {e}");
            }
        }
    });
    Ok(Json(json!({ "started": true })))
}

async fn list_resources(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let tracked = db::tracked_subscription_ids(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut resources = db::list_latest_resources(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    resources.retain(|r| tracked.iter().any(|t| t == r.subscription_id.as_str()));
    let ctx = ClassCtx::load(&state).await;
    let rows: Vec<Value> = resources
        .iter()
        .map(|r| {
            json!({
                "resource": r,
                "classification": ctx.classify(r),
                "ownership": ctx.ownership(r),
            })
        })
        .collect();
    Ok(Json(json!({ "resources": rows })))
}

async fn resource_timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let decoded = urlencoding_decode(&id);
    let obs = db::latest_observation(&state.pool, &decoded)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let changes = db::list_changes_for_resource(&state.pool, &decoded)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let tracked = db::tracked_subscription_ids(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Full interval history (open + closed), scope-filtered (invariant 13). No LIMIT.
    let findings: Vec<FindingInterval> = db::findings_for_resource(&state.pool, &decoded)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .filter(|f| in_scope(&tracked, f.subscription_id.as_str()))
        .collect();
    let tickets = db::list_ticket_relationships(&state.pool, &decoded)
        .await
        .unwrap_or_default();
    let coverage = db::list_coverage(&state.pool)
        .await
        .unwrap_or_default();
    let now = Utc::now();
    let exceptions = db::list_exceptions(&state.pool, None, Some(&decoded))
        .await
        .unwrap_or_default();
    // Triage per (resource, control): one entry per open interval, null for closed ones.
    let findings_triage: Vec<Option<TriageInfo>> = findings
        .iter()
        .map(|f| f.is_open().then(|| triage_interval(f, &exceptions, now)))
        .collect();
    let triage = findings_triage
        .iter()
        .flatten()
        .min_by_key(|t| triage_rank(&t.state))
        .cloned();
    let mut dispositions = Vec::new();
    for f in findings.iter().filter(|f| f.is_open()) {
        if let Ok(Some(d)) = db::latest_disposition_for_evaluation(&state.pool, &f.id).await {
            dispositions.push(d);
        }
    }
    let last_scan_at = db::last_finished_scan_started_at(&state.pool).await.ok().flatten();
    Ok(Json(json!({
        "resource": obs,
        "changes": changes,
        "findings": findings,
        "findings_triage": findings_triage,
        "triage": triage,
        "last_scan_at": last_scan_at,
        "exceptions": exceptions,
        "dispositions": dispositions,
        "tickets": tickets,
        "coverage": coverage,
    })))
}

/// Case-insensitive membership in the tracked subscription list (invariant 13).
fn in_scope(tracked: &[String], subscription_id: &str) -> bool {
    tracked.iter().any(|t| t.eq_ignore_ascii_case(subscription_id))
}

/// Triage each open interval on its own (invariant 10), most urgent first.
fn triage_findings(
    findings: Vec<FindingInterval>,
    exceptions: &[ExceptionRecord],
    now: DateTime<Utc>,
) -> Vec<(FindingInterval, TriageInfo)> {
    let mut out: Vec<(FindingInterval, TriageInfo)> = findings
        .into_iter()
        .map(|f| {
            let t = triage_interval(&f, exceptions, now);
            (f, t)
        })
        .collect();
    out.sort_by(|a, b| {
        triage_rank(&a.1.state)
            .cmp(&triage_rank(&b.1.state))
            .then_with(|| a.0.control_id.cmp(&b.0.control_id))
            .then_with(|| a.0.pack_id.cmp(&b.0.pack_id))
    });
    out
}

/// `GET /api/findings` (spec §3.4): open intervals matching the query, or the full history
/// of `resource_id` when given (AC-P3-8). Always limited to tracked subscriptions.
/// Response: `{ findings, triage, last_scan_at }`, `triage[i]` belonging to `findings[i]`.
async fn list_findings_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(mut q): Query<FindingQuery>,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let tracked = db::tracked_subscription_ids(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let findings: Vec<FindingInterval> = match q.resource_id.as_deref() {
        Some(rid) => db::findings_for_resource(&state.pool, rid)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .into_iter()
            .filter(|f| in_scope(&tracked, f.subscription_id.as_str()))
            .collect(),
        None => {
            q.subscriptions = Some(tracked);
            db::list_open_findings(&state.pool, &q)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        }
    };
    let exceptions = db::list_exceptions(&state.pool, None, None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let now = Utc::now();
    let triage: Vec<TriageInfo> = findings
        .iter()
        .map(|f| triage_interval(f, &exceptions, now))
        .collect();
    let last_scan_at = db::last_finished_scan_started_at(&state.pool).await.ok().flatten();
    Ok(Json(json!({
        "findings": findings,
        "triage": triage,
        "last_scan_at": last_scan_at,
    })))
}

async fn list_changes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let changes = db::list_recent_changes(&state.pool, 200)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "changes": changes })))
}

async fn coverage(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let rows = db::list_coverage(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "coverage": rows })))
}

#[derive(Deserialize, serde::Serialize)]
struct InboxQuery {
    environment: Option<String>,
    severity: Option<String>,
    subscription_id: Option<String>,
    /// P4: matches derived application (or application ID), case-insensitive.
    application: Option<String>,
    /// P4: matches derived owner, case-insensitive.
    owner: Option<String>,
    /// P4: `owner` | `application` | `subscription`.
    group_by: Option<String>,
    /// P6 (AC-P6-1): findings lane, `security` (default) | `hygiene` | `all`. Hygiene
    /// findings never rank a row unless asked for.
    lane: Option<String>,
}

async fn inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(mut q): Query<InboxQuery>,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let lane = lane_filter(q.lane.as_deref())?;
    q.lane = Some(lane.unwrap_or("all").to_string());
    let tracked = db::tracked_subscription_ids(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let changes = db::list_recent_changes(&state.pool, 500)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let ctx = ClassCtx::load(&state).await;
    let changes: Vec<ChangeEvent> = changes
        .into_iter()
        .filter(|ch| tracked.iter().any(|t| t == ch.subscription_id.as_str()))
        .filter(|ch| {
            q.subscription_id
                .as_deref()
                .map(|sid| ch.subscription_id.as_str() == sid)
                .unwrap_or(true)
        })
        .collect();
    // One query for the open findings of every resource in view (no global LIMIT), grouped
    // by resource. Triage is per (resource, control): a pass on one control never masks a
    // fail on another (AC-P3-7).
    let resource_ids: Vec<String> = changes
        .iter()
        .map(|c| c.resource_id.as_str().to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let open = db::list_open_findings(
        &state.pool,
        &FindingQuery {
            subscriptions: Some(tracked.clone()),
            resource_ids: Some(resource_ids),
            lane: lane.map(str::to_string),
            ..Default::default()
        },
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut by_resource: std::collections::HashMap<String, Vec<FindingInterval>> =
        std::collections::HashMap::new();
    for f in open {
        by_resource
            .entry(f.resource_id.as_str().to_string())
            .or_default()
            .push(f);
    }
    let exceptions = db::list_exceptions(&state.pool, None, None)
        .await
        .unwrap_or_default();
    let last_scan_at = db::last_finished_scan_started_at(&state.pool).await.ok().flatten();

    let last_visit = db::meta_get(&state.pool, "last_visit")
        .await
        .ok()
        .flatten();
    let last_visit_dt = last_visit.as_ref().and_then(|s| {
        DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|d| d.with_timezone(&Utc))
    });
    let now = Utc::now();

    let mut rows = Vec::new();
    for ch in changes {
        let obs = db::latest_observation(&state.pool, ch.resource_id.as_str())
            .await
            .ok()
            .flatten();
        let class = obs
            .as_ref()
            .map(|o| ctx.classify(o))
            .unwrap_or_else(|| ClassificationResult::unclassified("no observation", true));
        if let Some(ref env) = q.environment {
            if class.environment.as_str() != env {
                continue;
            }
        }
        let ownership = obs.as_ref().map(|o| ctx.ownership(o)).unwrap_or_default();
        if !ownership_filter_ok(&ownership, q.application.as_deref(), q.owner.as_deref()) {
            continue;
        }
        let group_key =
            inbox_group_key(q.group_by.as_deref(), &ownership, &ctx, ch.subscription_id.as_str());
        let resource_findings = by_resource
            .get(ch.resource_id.as_str())
            .cloned()
            .unwrap_or_default();
        if let Some(ref sev) = q.severity {
            if !resource_findings.iter().any(|f| f.severity.as_str() == sev) {
                continue;
            }
        }
        let triaged = triage_findings(resource_findings, &exceptions, now);
        // Row-level summary is the most urgent control; every control is listed in `findings`.
        let (finding, triage) = match triaged.first() {
            Some((f, t)) => (Some(f.clone()), Some(t.clone())),
            None => (None, None),
        };
        let disposition = if let Some(ref f) = finding {
            db::latest_disposition_for_evaluation(&state.pool, &f.id)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let findings: Vec<Value> = triaged
            .iter()
            .map(|(f, t)| json!({ "finding": f, "triage": t }))
            .collect();
        let since_last_visit = last_visit_dt
            .map(|lv| ch.times.observation_time > lv)
            .unwrap_or(true);
        rows.push(json!({
            "change": ch,
            "classification": class,
            "finding": finding,
            "findings": findings,
            "triage": triage,
            "disposition": disposition,
            "resource": obs,
            "ownership": ownership,
            "group_key": group_key,
            "since_last_visit": since_last_visit,
        }));
    }

    // Elevate actionable / awaiting / unresolved; stable tie-break by observation time desc.
    rows.sort_by(|a, b| {
        let rank = |row: &Value| {
            let state = row
                .pointer("/triage/state")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match state {
                "actionable" => 0,
                "awaiting_grace" => 1,
                "fail" | "unknown" => 2,
                "excepted" => 3,
                "verified_corrected" => 4,
                _ => 5,
            }
        };
        let cmp = rank(a).cmp(&rank(b));
        if cmp != std::cmp::Ordering::Equal {
            return cmp;
        }
        let at = a
            .pointer("/change/times/observation_time")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let bt = b
            .pointer("/change/times/observation_time")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        bt.cmp(at)
    });

    let groups = group_inbox_rows(&mut rows, q.group_by.as_deref());

    let _ = db::meta_set(&state.pool, "last_visit", &now.to_rfc3339()).await;

    Ok(Json(json!({
        "rows": rows,
        "groups": groups,
        "last_visit": last_visit,
        "last_scan_at": last_scan_at,
        "filter": q,
    })))
}

async fn compliance_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let tracked = db::tracked_subscription_ids(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Every open interval in scope: the current state, never truncated by a LIMIT.
    let open = db::list_open_findings(
        &state.pool,
        &FindingQuery {
            subscriptions: Some(tracked.clone()),
            ..Default::default()
        },
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let last_scan_at = db::last_finished_scan_started_at(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut pass = 0;
    let mut fail = 0;
    let mut unknown = 0;
    let mut inapplicable = 0;
    let mut stale = 0;
    for f in &open {
        match f.outcome {
            EvalOutcome::Pass => pass += 1,
            EvalOutcome::Fail => fail += 1,
            EvalOutcome::Unknown => unknown += 1,
            EvalOutcome::Inapplicable => inapplicable += 1,
        }
        if last_scan_at.is_some_and(|t| f.last_evaluated_at < t) {
            stale += 1;
        }
    }
    let now = Utc::now();
    let exception_rows = db::list_exceptions(&state.pool, None, None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut actionable = 0;
    let mut awaiting_grace = 0;
    let mut verified = 0;
    let mut excepted = 0;
    // One triage per open interval, i.e. per (pack, resource, control).
    for f in &open {
        match triage_interval(f, &exception_rows, now).state {
            TriageState::Actionable => actionable += 1,
            TriageState::AwaitingGrace => awaiting_grace += 1,
            TriageState::VerifiedCorrected => verified += 1,
            TriageState::Excepted => excepted += 1,
            _ => {}
        }
    }
    let exceptions = exception_rows.iter().filter(|x| x.is_active(now)).count();

    // Coverage (AC-P1-8): controls of active packs that evaluate per resource, and the stored
    // gaps (from the latest scan) of those packs only.
    let active = db::active_policy_packs(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut controls_total = 0usize;
    let mut controls_evaluated = 0usize;
    let mut active_ids = std::collections::HashSet::new();
    for p in &active {
        if let Some(id) = p.get("id").and_then(|v| v.as_str()) {
            active_ids.insert(id.to_string());
        }
        let content = p.get("content").cloned().unwrap_or_default();
        if let Ok(pack) = serde_json::from_value::<PolicyPack>(content) {
            let cov = coverage_report(&pack);
            controls_total += cov.controls_total;
            controls_evaluated += cov.controls_evaluated;
        }
    }
    let coverage_gaps: Vec<CoverageGap> = db::list_coverage_gaps(&state.pool, None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .filter(|g| active_ids.contains(&g.pack_id))
        .collect();

    Ok(Json(json!({
        "passing": pass,
        "failing": fail,
        "unknown": unknown,
        "inapplicable": inapplicable,
        "exceptions": exceptions,
        "excepted": excepted,
        "pending_remediation": actionable,
        "awaiting_grace": awaiting_grace,
        "verified_corrected": verified,
        "freshness": now,
        "last_scan_at": last_scan_at,
        "stale": stale,
        "scope": tracked,
        "coverage_gaps": coverage_gaps,
        "controls_evaluated": controls_evaluated,
        "controls_total": controls_total,
    })))
}

// ---- P6: reporting (spec §3.4, §4.7) ----------------------------------------------------
// Every reporting read is limited to tracked subscriptions (invariant 13). Lane defaults to
// `security` (security-first, azcompliance backlog #4); `lane=all` includes hygiene.

#[derive(Deserialize, Default)]
struct ReportQuery {
    /// `security` (default) | `hygiene` | `all`.
    lane: Option<String>,
    /// Queue only: `application` | `owner` | `subscription` | `line_of_business`.
    group_by: Option<String>,
    /// Flow only: window in days, default 90.
    days: Option<u32>,
}

/// Lane filter for a reporting or inbox query: `None` means both lanes. 400 when unknown.
fn lane_filter(lane: Option<&str>) -> Result<Option<&'static str>, StatusCode> {
    match lane.map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("security") => Ok(Some("security")),
        Some("hygiene") => Ok(Some("hygiene")),
        Some("all") => Ok(None),
        Some(_) => Err(StatusCode::BAD_REQUEST),
    }
}

async fn report_scope(state: &AppState, lane: Option<&str>) -> Result<db::ReportScope, StatusCode> {
    let tracked = db::tracked_subscription_ids(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(db::ReportScope::new(tracked, lane))
}

async fn last_visit_at(state: &AppState) -> Option<DateTime<Utc>> {
    db::meta_get(&state.pool, "last_visit")
        .await
        .ok()
        .flatten()
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|d| d.with_timezone(&Utc))
}

/// Queue group for one open fail from its resource's derived ownership (AC-P4-6 rules).
fn ownership_group_key(group_by: db::QueueGroupBy, o: &Ownership) -> String {
    let v = match group_by {
        db::QueueGroupBy::Application => o.application.clone().or_else(|| o.application_id.clone()),
        db::QueueGroupBy::Owner => o.owner.clone(),
        db::QueueGroupBy::LineOfBusiness => o
            .line_of_business_name
            .clone()
            .or_else(|| o.line_of_business.clone()),
        db::QueueGroupBy::Subscription => None,
    };
    v.unwrap_or_default()
}

/// Derived ownership of each distinct resource in `rows`, computed once per resource.
fn ownership_by_resource(
    ctx: &ClassCtx,
    rows: &[db::OpenFailResource],
) -> std::collections::HashMap<String, Ownership> {
    let mut out = std::collections::HashMap::new();
    for r in rows {
        if out.contains_key(&r.resource_id) {
            continue;
        }
        let o = r
            .observation
            .as_ref()
            .map(|obs| ctx.ownership(obs))
            .unwrap_or_default();
        out.insert(r.resource_id.clone(), o);
    }
    out
}

/// `GET /api/compliance/queue?lane=&group_by=`: open fails by control, lane, environment and
/// group, with `new_since_last_visit` against `meta.last_visit` (read, not updated here).
/// Ownership groups derive ownership in Rust over one batched read of intervals + latest
/// observations; subscription grouping is done in SQL.
async fn compliance_queue_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReportQuery>,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let lane = lane_filter(q.lane.as_deref())?;
    let group_by = match q.group_by.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(g) => Some(db::QueueGroupBy::parse(g).ok_or(StatusCode::BAD_REQUEST)?),
    };
    let scope = report_scope(&state, lane).await?;
    let last_visit = last_visit_at(&state).await;
    let rows = match group_by {
        None | Some(db::QueueGroupBy::Subscription) => {
            let by_sub = group_by.is_some();
            let mut rows = db::compliance_queue(&state.pool, &scope, by_sub, last_visit)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            if by_sub {
                let ctx = ClassCtx::load(&state).await;
                for r in &mut rows {
                    if let Some(name) = ctx.sub_names.get(&r.group_key) {
                        r.group_key = name.clone();
                    }
                }
            }
            rows
        }
        Some(g) => {
            let ctx = ClassCtx::load(&state).await;
            let open = db::open_fail_resources(&state.pool, &scope)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let owners = ownership_by_resource(&ctx, &open);
            db::aggregate_queue(&open, last_visit, |r| {
                owners
                    .get(&r.resource_id)
                    .map(|o| ownership_group_key(g, o))
                    .unwrap_or_default()
            })
        }
    };
    Ok(Json(json!({
        "rows": rows,
        "lane": lane.unwrap_or("all"),
        "group_by": group_by,
        "last_visit": last_visit,
    })))
}

/// `GET /api/compliance/aging?lane=`: open fails per control by age bucket
/// (`0-7`, `8-30`, `31-90`, `90+` whole days since `opened_at`).
async fn compliance_aging_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReportQuery>,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let scope = report_scope(&state, lane_filter(q.lane.as_deref())?).await?;
    let rows = db::compliance_aging(&state.pool, &scope, Utc::now())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "rows": rows, "buckets": db::AGING_BUCKETS })))
}

/// `GET /api/compliance/flow?days=90&lane=`: fail intervals opened and closed per UTC day.
async fn compliance_flow_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReportQuery>,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let scope = report_scope(&state, lane_filter(q.lane.as_deref())?).await?;
    let days = q.days.unwrap_or(90).clamp(1, 3650);
    let rows = db::compliance_flow(&state.pool, &scope, days, Utc::now())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "rows": rows, "days": days })))
}

/// `GET /api/compliance/trend?lane=`: open fails per control at each of the last 26 finished
/// scans. `scans` lists every trend point, including scans with no open fails.
async fn compliance_trend_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReportQuery>,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let scope = report_scope(&state, lane_filter(q.lane.as_deref())?).await?;
    let rows = db::compliance_trend(&state.pool, &scope, db::TREND_SCANS)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let scans = db::trend_scans(&state.pool, db::TREND_SCANS)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "rows": rows, "scans": scans })))
}

/// Open fail counts split by lane, for the readout.
#[derive(Default)]
struct LaneCounts {
    security: u64,
    hygiene: u64,
}

impl LaneCounts {
    fn add(&mut self, lane: estatetrace_policy::Lane, n: u64) {
        match lane {
            estatetrace_policy::Lane::Security => self.security += n,
            estatetrace_policy::Lane::Hygiene => self.hygiene += n,
        }
    }

    fn json(&self) -> Value {
        json!({
            "open": self.security + self.hygiene,
            "security": self.security,
            "hygiene": self.hygiene,
        })
    }

    /// `[{<key>: k, open, security, hygiene}]`, largest first.
    fn rows(map: std::collections::BTreeMap<String, LaneCounts>, key: &str) -> Vec<Value> {
        let mut rows: Vec<Value> = map
            .into_iter()
            .map(|(k, c)| {
                let mut v = c.json();
                v[key] = json!(k);
                v
            })
            .collect();
        rows.sort_by(|a, b| b["open"].as_u64().cmp(&a["open"].as_u64()));
        rows
    }
}

/// Replace any string that looks like an ARM resource ID with a marker (AC-P6-5). The readout
/// is built from aggregates only; this guards free-text values such as tag-derived LOB names.
fn redact_resource_ids(v: &mut Value) {
    match v {
        Value::String(s) if s.to_ascii_lowercase().contains("/subscriptions/") => {
            *s = "[redacted]".into();
        }
        Value::Array(items) => items.iter_mut().for_each(redact_resource_ids),
        Value::Object(map) => map.values_mut().for_each(redact_resource_ids),
        _ => {}
    }
}

/// Leadership readout (`POST /api/evidence/export {format: "readout"}`, spec §3.4, AC-P6-5):
/// aggregates only, with no resource or subscription IDs. Open fail counts by control,
/// environment, line of business (name, else code) and lane; trend over the last 26 finished
/// scans; coverage-gap categories of active packs; active exceptions in scope; scope size; and
/// freshness. An empty scope gives zero counts and `scope_empty: true` (spec §7).
async fn readout_payload(state: &AppState) -> anyhow::Result<Value> {
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    let tracked = db::tracked_subscription_ids(&state.pool).await?;
    let scope_empty = tracked.is_empty();
    let scope = db::ReportScope::new(tracked.clone(), None);
    let open = db::open_fail_resources(&state.pool, &scope).await?;
    let ctx = ClassCtx::load(state).await;
    let owners = ownership_by_resource(&ctx, &open);

    // Keyed by (control, lane as serialized); `Lane` has no `Ord`.
    let mut by_control: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut by_env: BTreeMap<String, LaneCounts> = BTreeMap::new();
    let mut by_lob: BTreeMap<String, LaneCounts> = BTreeMap::new();
    let mut by_lane = LaneCounts::default();
    for r in &open {
        let lane_name = json!(r.lane).as_str().unwrap_or("security").to_string();
        *by_control.entry((r.control_id.clone(), lane_name)).or_default() += 1;
        by_env.entry(r.environment.clone()).or_default().add(r.lane, 1);
        let lob = owners
            .get(&r.resource_id)
            .and_then(|o| o.line_of_business_name.clone().or_else(|| o.line_of_business.clone()))
            .unwrap_or_else(|| "Unassigned".into());
        by_lob.entry(lob).or_default().add(r.lane, 1);
        by_lane.add(r.lane, 1);
    }
    let mut by_control: Vec<Value> = by_control
        .into_iter()
        .map(|((control_id, lane), open)| json!({ "control_id": control_id, "lane": lane, "open": open }))
        .collect();
    by_control.sort_by(|a, b| b["open"].as_u64().cmp(&a["open"].as_u64()));

    // Trend: open fails per lane at each finished scan (every scan is a point).
    let (trend_rows, scans) = if scope_empty {
        (Vec::new(), Vec::new())
    } else {
        (
            db::compliance_trend(&state.pool, &scope, db::TREND_SCANS).await?,
            db::trend_scans(&state.pool, db::TREND_SCANS).await?,
        )
    };
    let trend: Vec<Value> = scans
        .iter()
        .map(|s| {
            let mut c = LaneCounts::default();
            for r in trend_rows.iter().filter(|r| r.scan_id == s.scan_id) {
                c.add(r.lane, r.open);
            }
            let mut v = c.json();
            v["scan_started_at"] = json!(s.started_at);
            v
        })
        .collect();

    // Coverage-gap categories of active packs (gaps are stored per pack, not per subscription).
    let mut gap_categories: Vec<Value> = Vec::new();
    if !scope_empty {
        let active: HashSet<String> = db::active_policy_packs(&state.pool)
            .await?
            .iter()
            .filter_map(|p| p.get("id").and_then(|v| v.as_str()).map(str::to_string))
            .collect();
        let mut cats: BTreeMap<String, (BTreeSet<String>, u64)> = BTreeMap::new();
        for g in db::list_coverage_gaps(&state.pool, None).await? {
            if !active.contains(&g.pack_id) {
                continue;
            }
            let category = serde_json::to_value(&g.category)?
                .as_str()
                .unwrap_or_default()
                .to_string();
            let e = cats.entry(category).or_default();
            e.0.insert(format!("{}|{}", g.pack_id, g.control_id));
            e.1 += g.resource_count;
        }
        gap_categories = cats
            .into_iter()
            .map(|(category, (controls, resources))| {
                json!({ "category": category, "controls": controls.len(), "resources": resources })
            })
            .collect();
    }

    // Active exceptions whose scope lies in a tracked subscription.
    let now = Utc::now();
    let exceptions = db::list_exceptions(&state.pool, None, None)
        .await?
        .iter()
        .filter(|x| x.is_active(now))
        .filter(|x| {
            let sub = x
                .subscription_id
                .as_deref()
                .or_else(|| x.resource_id.as_deref().and_then(|r| arm_scope(r).0));
            sub.is_some_and(|s| in_scope(&tracked, s))
        })
        .count();
    let last_scan_at = db::last_finished_scan_started_at(&state.pool).await?;

    let mut payload = json!({
        "format": "readout",
        "scope_empty": scope_empty,
        "scope_size": tracked.len(),
        "open_findings": open.len(),
        "by_lane": by_lane.json(),
        "by_control": by_control,
        "by_environment": LaneCounts::rows(by_env, "environment"),
        "by_line_of_business": LaneCounts::rows(by_lob, "line_of_business"),
        "trend": trend,
        "coverage_gap_categories": gap_categories,
        "exceptions": exceptions,
        "freshness": { "last_scan_at": last_scan_at, "generated_at": now },
    });
    redact_resource_ids(&mut payload);
    Ok(payload)
}

/// Scoped exception request (spec §3.4, §4.5). Scope is `resource_id`, or `subscription_id`,
/// or `subscription_id` + `resource_group`.
#[derive(Deserialize)]
struct ExceptionCreate {
    #[serde(default)]
    control_id: String,
    resource_id: Option<String>,
    subscription_id: Option<String>,
    resource_group: Option<String>,
    reason: Option<String>,
    approved_by: Option<String>,
    ticket_ref: Option<String>,
    /// RFC 3339, or a date (`YYYY-MM-DD`) meaning the end of that day in UTC.
    expires_at: Option<String>,
}

fn trimmed(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn parse_exception_expiry(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d.with_timezone(&Utc));
    }
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(23, 59, 59))
        .map(|dt| dt.and_utc())
}

async fn create_exception(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ExceptionCreate>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_mutation(&state, &headers).map_err(|s| (s, Json(json!({}))))?;
    let bad = |msg: &str| (StatusCode::BAD_REQUEST, Json(json!({ "error": msg })));
    let control_id = body.control_id.trim().to_string();
    if control_id.is_empty() {
        return Err(bad("control_id is required"));
    }
    let resource_id = trimmed(body.resource_id);
    let (subscription_id, resource_group) = if resource_id.is_some() {
        // A resource scope is exact; subscription and group would be ignored, so drop them.
        (None, None)
    } else {
        (trimmed(body.subscription_id), trimmed(body.resource_group))
    };
    if resource_id.is_none() && subscription_id.is_none() {
        return Err(bad(
            "scope is empty: set resource_id, or subscription_id (optionally with resource_group)",
        ));
    }
    let expires_at = match trimmed(body.expires_at) {
        None => None,
        Some(s) => Some(
            parse_exception_expiry(&s)
                .ok_or_else(|| bad("expires_at must be RFC 3339 or YYYY-MM-DD"))?,
        ),
    };
    let now = Utc::now();
    let ex = ExceptionRecord {
        id: Uuid::new_v4().to_string(),
        control_id,
        resource_id,
        subscription_id,
        resource_group,
        reason: trimmed(body.reason),
        approved_by: trimmed(body.approved_by),
        ticket_ref: trimmed(body.ticket_ref),
        expires_at,
        created_at: now,
    };
    db::insert_exception(&state.pool, &ex).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "store error" })),
        )
    })?;
    // Spec §7: an expiry already in the past is accepted (backfill) but never overlays.
    let expired = !ex.is_active(now);
    Ok(Json(json!({ "exception": ex, "expired": expired })))
}

#[derive(Deserialize)]
struct ExceptionListQuery {
    control_id: Option<String>,
    resource_id: Option<String>,
}

async fn list_exceptions_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ExceptionListQuery>,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let rows = db::list_exceptions(
        &state.pool,
        q.control_id.as_deref(),
        q.resource_id.as_deref(),
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "exceptions": rows })))
}

#[derive(Deserialize)]
struct DispositionCreate {
    evaluation_id: String,
    owner: Option<String>,
    disposition: String,
    ticket_ref: Option<String>,
}

async fn create_disposition(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DispositionCreate>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let d = DispositionRecord {
        id: Uuid::new_v4().to_string(),
        evaluation_id: body.evaluation_id,
        owner: body.owner,
        disposition: body.disposition,
        ticket_ref: body.ticket_ref,
        created_at: Utc::now(),
    };
    db::insert_disposition(&state.pool, &d)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "disposition": d })))
}

#[derive(Deserialize)]
struct DispositionListQuery {
    evaluation_id: Option<String>,
}

async fn list_dispositions_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<DispositionListQuery>,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let rows = db::list_dispositions(&state.pool, q.evaluation_id.as_deref())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "dispositions": rows })))
}

async fn list_class_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let rules = db::list_classification_rules(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "rules": rules })))
}

async fn save_class_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(rule): Json<ClassificationRule>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_mutation(&state, &headers).map_err(status_json)?;
    // Invariant 16: every rule regex compiles at save time.
    validate_rule(&rule).map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))))?;
    db::upsert_classification_rule(&state.pool, &rule)
        .await
        .map_err(|_| status_json(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(json!({ "ok": true })))
}

fn status_json(s: StatusCode) -> (StatusCode, Json<Value>) {
    (s, Json(json!({ "error": s.canonical_reason().unwrap_or("error") })))
}

/// Default rules for the operator to review and save. Never saved automatically.
async fn suggested_class_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    Ok(Json(json!({ "rules": suggested_rules() })))
}

/// Data quality: counts by classification source over tracked resources, plus tracked
/// subscriptions whose name gives no environment (ports of azcompliance `run_fact` kinds
/// `environment_source` and `no_environment_token`).
async fn classification_quality(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let tracked = db::tracked_subscription_ids(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut resources = db::list_latest_resources(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    resources.retain(|r| tracked.iter().any(|t| t == r.subscription_id.as_str()));
    let ctx = ClassCtx::load(&state).await;

    let mut by_source: std::collections::BTreeMap<&'static str, u64> = Default::default();
    let mut by_environment: std::collections::BTreeMap<&'static str, u64> = Default::default();
    let (mut conflicting, mut missing_tag) = (0u64, 0u64);
    for r in &resources {
        let c = ctx.classify(r);
        *by_source.entry(c.source.as_str()).or_default() += 1;
        *by_environment.entry(c.environment.as_str()).or_default() += 1;
        conflicting += c.conflicting as u64;
        missing_tag += c.missing_tag as u64;
    }

    // Subscription-name check uses the saved name patterns, or the suggested ones when none
    // are saved. A subscription pinned by an explicit `subscription` rule is not reported.
    let saved_name_rules: Vec<ClassificationRule> = ctx
        .rules
        .iter()
        .filter(|r| r.kind == ClassificationRuleKind::SubscriptionNamePattern)
        .cloned()
        .collect();
    let (name_rules, name_rules_source) = if saved_name_rules.is_empty() {
        let suggested: Vec<ClassificationRule> = suggested_rules()
            .into_iter()
            .filter(|r| r.kind == ClassificationRuleKind::SubscriptionNamePattern)
            .collect();
        (suggested, "suggested")
    } else {
        (saved_name_rules, "saved")
    };
    let pinned: std::collections::HashSet<&str> = ctx
        .rules
        .iter()
        .filter(|r| r.kind == ClassificationRuleKind::Subscription)
        .filter_map(|r| r.subscription_id.as_ref().map(|s| s.as_str()))
        .collect();
    let subs = db::list_subscriptions(&state.pool).await.unwrap_or_default();
    let no_token: Vec<Value> = subs
        .iter()
        .filter(|s| tracked.iter().any(|t| t == s.id.as_str()))
        .filter(|s| !pinned.contains(s.id.as_str()))
        .filter(|s| subscription_name_environment(&s.name, &name_rules).is_none())
        .map(|s| json!({ "id": s.id, "name": s.name }))
        .collect();

    Ok(Json(json!({
        "total": resources.len(),
        "by_source": by_source,
        "by_environment": by_environment,
        "conflicting": conflicting,
        "missing_tag": missing_tag,
        "subscriptions_without_environment_token": no_token,
        "name_rules": name_rules_source,
    })))
}

/// Classification inputs loaded once per request: rules, subscription names, RG tags and
/// the ownership config. Ownership is derived at read time, so a config change needs no rescan.
struct ClassCtx {
    rules: Vec<ClassificationRule>,
    sub_names: std::collections::HashMap<String, String>,
    rg_tags: std::collections::HashMap<(String, String), Value>,
    ownership: OwnershipConfig,
}

impl ClassCtx {
    async fn load(state: &AppState) -> Self {
        let rules = db::list_classification_rules(&state.pool)
            .await
            .unwrap_or_default();
        let sub_names = db::list_subscriptions(&state.pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|s| (s.id.as_str().to_string(), s.name))
            .collect();
        let rg_tags = db::get_resource_group_tags(&state.pool, None)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| {
                let key = (
                    r.subscription_id.as_str().to_string(),
                    r.resource_group.to_lowercase(),
                );
                (key, r.tags)
            })
            .collect();
        let ownership = state
            .settings
            .read()
            .await
            .ownership
            .clone()
            .unwrap_or_default();
        Self {
            rules,
            sub_names,
            rg_tags,
            ownership,
        }
    }

    fn input<'a>(&'a self, obs: &'a ResourceObservation) -> ClassifyInput<'a> {
        ClassifyInput {
            obs,
            subscription_name: self
                .sub_names
                .get(obs.subscription_id.as_str())
                .map(|s| s.as_str()),
            rg_tags: obs.resource_group.as_ref().and_then(|rg| {
                self.rg_tags
                    .get(&(obs.subscription_id.as_str().to_string(), rg.to_lowercase()))
            }),
        }
    }

    fn classify(&self, obs: &ResourceObservation) -> ClassificationResult {
        classify(&self.input(obs), &self.rules)
    }

    fn ownership(&self, obs: &ResourceObservation) -> Ownership {
        derive_ownership(&self.input(obs), &self.ownership)
    }
}

fn eq_filter(value: Option<&str>, want: Option<&str>) -> bool {
    match want.map(str::trim).filter(|w| !w.is_empty()) {
        None => true,
        Some(w) => value.is_some_and(|v| v.trim().eq_ignore_ascii_case(w)),
    }
}

/// AC-P4-6: inbox `application` / `owner` filters read the derived ownership.
fn ownership_filter_ok(o: &Ownership, application: Option<&str>, owner: Option<&str>) -> bool {
    (eq_filter(o.application.as_deref(), application)
        || eq_filter(o.application_id.as_deref(), application))
        && eq_filter(o.owner.as_deref(), owner)
}

fn inbox_group_key(
    group_by: Option<&str>,
    o: &Ownership,
    ctx: &ClassCtx,
    subscription_id: &str,
) -> Option<String> {
    match group_by? {
        "owner" => o.owner.clone(),
        "application" => o.application.clone().or_else(|| o.application_id.clone()),
        "subscription" => Some(
            ctx.sub_names
                .get(subscription_id)
                .cloned()
                .unwrap_or_else(|| subscription_id.to_string()),
        ),
        _ => None,
    }
}

/// Stable-sort rows by `group_key` (unassigned last), keeping the triage order within a
/// group, and return `[{key, count}]` in display order. No-op without a recognised `group_by`.
fn group_inbox_rows(rows: &mut [Value], group_by: Option<&str>) -> Vec<Value> {
    if !matches!(group_by, Some("owner" | "application" | "subscription")) {
        return Vec::new();
    }
    let key = |r: &Value| {
        r.get("group_key")
            .and_then(|v| v.as_str())
            .map(str::to_lowercase)
    };
    rows.sort_by(|a, b| match (key(a), key(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    let mut groups: Vec<(Option<String>, Option<String>, u64)> = Vec::new();
    for r in rows.iter() {
        let display = r
            .get("group_key")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let k = key(r);
        match groups.last_mut() {
            Some((last, _, n)) if *last == k => *n += 1,
            _ => groups.push((k, display, 1)),
        }
    }
    groups
        .into_iter()
        .map(|(_, display, n)| json!({ "key": display, "count": n }))
        .collect()
}

async fn list_packs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let packs = db::list_policy_packs(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "packs": packs })))
}

#[derive(Deserialize)]
struct ImportPackReq {
    yaml: Option<String>,
    json: Option<String>,
    reviewed_by: String,
    activate: bool,
}

/// 422 with the validation message (it names the failing control); nothing is saved.
fn pack_rejected(e: anyhow::Error) -> axum::response::Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({ "ok": false, "activated": false, "error": e.to_string() })),
    )
        .into_response()
}

async fn import_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ImportPackReq>,
) -> Result<axum::response::Response, StatusCode> {
    require_mutation(&state, &headers)?;
    let parsed = if let Some(y) = &req.yaml {
        parse_pack_yaml(y)
    } else if let Some(j) = &req.json {
        parse_pack_json(j)
    } else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let pack = match parsed {
        Ok(p) => p,
        Err(e) => return Ok(pack_rejected(e)),
    };
    let kinds = builtin_resource_kinds();
    let issues = match lint_and_validate_pack(&pack, kinds) {
        Ok(i) => i,
        Err(e) => return Ok(pack_rejected(e)),
    };
    let examples = match run_example_cases(&pack, kinds) {
        Ok(x) => x,
        Err(e) => return Ok(pack_rejected(e)),
    };
    if examples.iter().any(|x| !x.ok) {
        return Ok(Json(json!({
            "activated": false,
            "error": "example cases failed",
            "examples": examples,
            "issues": issues,
            "coverage": coverage_report(&pack),
        }))
        .into_response());
    }
    let content = serde_json::to_value(&pack).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    db::save_policy_pack(
        &state.pool,
        &pack.id,
        &pack.name,
        &pack.revision,
        pack.owner.as_deref(),
        Some(&req.reviewed_by),
        req.activate,
        &content,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if req.activate {
        activate_revision(&state, &pack.id, &pack.revision)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    // Persist pack file privately
    let path = state
        .profile
        .join("packs")
        .join(format!("{}-{}.yaml", pack.id, pack.revision));
    let _ = std::fs::write(&path, req.yaml.unwrap_or_else(|| serde_yaml::to_string(&pack).unwrap_or_default()));

    Ok(Json(json!({
        "activated": req.activate,
        "examples": examples,
        "issues": issues,
        "coverage": coverage_report(&pack),
        "id": pack.id,
        "revision": pack.revision,
    }))
    .into_response())
}

async fn load_pilot(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let pack = pilot_pack();
    let content = serde_json::to_value(&pack).unwrap();
    db::save_policy_pack(
        &state.pool,
        &pack.id,
        &pack.name,
        &pack.revision,
        pack.owner.as_deref(),
        Some("pilot"),
        true,
        &content,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    activate_revision(&state, &pack.id, &pack.revision)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({
        "id": pack.id,
        "revision": pack.revision,
        "coverage": coverage_report(&pack),
        "examples": run_example_cases(&pack, builtin_resource_kinds()).unwrap_or_default(),
    })))
}

/// Make `revision` the pack's only active revision. When a different revision was active,
/// its open findings close with `pack_revision` (spec invariant 8, AC-P3-3). Returns the
/// number of intervals closed.
async fn activate_revision(state: &AppState, pack_id: &str, revision: &str) -> anyhow::Result<u64> {
    let before = db::set_pack_active_revision(&state.pool, pack_id, Some(revision)).await?;
    if before.iter().any(|r| r != revision) {
        return db::close_findings_for_pack(&state.pool, pack_id, CloseReason::PackRevision).await;
    }
    Ok(0)
}

#[derive(Deserialize)]
struct ActivatePackReq {
    revision: String,
}

/// `POST /api/packs/{id}/activate {revision}`: switch the active revision of a stored pack.
async fn activate_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ActivatePackReq>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let id = urlencoding_decode(&id);
    let exists = db::list_policy_packs(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .iter()
        .any(|p| p["id"] == id.as_str() && p["revision"] == req.revision.as_str());
    if !exists {
        return Err(StatusCode::NOT_FOUND);
    }
    let closed = activate_revision(&state, &id, &req.revision)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "id": id, "revision": req.revision, "activated": true, "closed": closed })))
}

/// `POST /api/packs/{id}/deactivate`: deactivate every revision and close the pack's open
/// findings with `pack_deactivated` (AC-P3-9).
async fn deactivate_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let id = urlencoding_decode(&id);
    db::set_pack_active_revision(&state.pool, &id, None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let closed = db::close_findings_for_pack(&state.pool, &id, CloseReason::PackDeactivated)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "id": id, "activated": false, "closed": closed })))
}

async fn validate_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<axum::response::Response, StatusCode> {
    require_mutation(&state, &headers)?;
    let parsed = if body.get("yaml").is_some() {
        parse_pack_yaml(body["yaml"].as_str().unwrap_or(""))
    } else {
        parse_pack_json(&body.to_string())
    };
    let pack: PolicyPack = match parsed {
        Ok(p) => p,
        Err(e) => return Ok(pack_rejected(e)),
    };
    let kinds = builtin_resource_kinds();
    let issues = match lint_and_validate_pack(&pack, kinds) {
        Ok(i) => i,
        Err(e) => return Ok(pack_rejected(e)),
    };
    Ok(Json(json!({
        "ok": true,
        "issues": issues,
        "coverage": coverage_report(&pack),
        "examples": run_example_cases(&pack, kinds).unwrap_or_default(),
    }))
    .into_response())
}

#[derive(Deserialize)]
struct ExportPreviewReq {
    pack_id: String,
    pack_revision: String,
    control_id: String,
    target_scope: String,
}

async fn export_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ExportPreviewReq>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let packs = db::list_policy_packs(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let pack_val = packs
        .into_iter()
        .find(|p| {
            p.get("id").and_then(|v| v.as_str()) == Some(req.pack_id.as_str())
                && p.get("revision").and_then(|v| v.as_str()) == Some(req.pack_revision.as_str())
        })
        .ok_or(StatusCode::NOT_FOUND)?;
    let pack: PolicyPack =
        serde_json::from_value(pack_val.get("content").cloned().unwrap_or(Value::Null))
            .map_err(|_| StatusCode::BAD_REQUEST)?;
    let resources = db::list_latest_resources(&state.pool)
        .await
        .unwrap_or_default();
    let matching: Vec<(String, String)> = resources
        .iter()
        .map(|r| (r.resource_id.0.clone(), r.name.clone()))
        .collect();
    let preview = suggest_and_preview(&pack, &req.control_id, &matching, &[], &req.target_scope)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(json!({
        "control_id": preview.control_id,
        "control_revision": preview.control_revision,
        "effect": preview.effect,
        "supported": preview.supported,
        "reason": preview.reason,
        "required_inputs": preview.required_inputs,
        "matching_count": preview.matching_count,
        "sample_resources": preview.sample_resources,
        "overlap_warning": preview.overlap_warning,
        "bicep": preview.bicep,
        "mapping": preview.mapping,
    })))
}

#[derive(Deserialize)]
struct CreateExportReq {
    pack_id: String,
    pack_revision: String,
    control_id: String,
    target_scope: String,
    parameters: Option<Value>,
}

async fn create_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateExportReq>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let preview = export_preview(
        State(state.clone()),
        headers.clone(),
        Json(ExportPreviewReq {
            pack_id: req.pack_id.clone(),
            pack_revision: req.pack_revision.clone(),
            control_id: req.control_id.clone(),
            target_scope: req.target_scope.clone(),
        }),
    )
    .await?
    .0;
    let id = Uuid::new_v4().to_string();
    db::insert_export_artifact(
        &state.pool,
        &id,
        &req.pack_id,
        &req.pack_revision,
        &req.control_id,
        "exported",
        &json!({ "scope": req.target_scope }),
        &req.parameters.unwrap_or(json!({})),
        preview.get("bicep").and_then(|v| v.as_str()),
        preview.get("mapping").unwrap_or(&Value::Null),
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "id": id, "state": "exported", "preview": preview })))
}

async fn list_exports_api(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let rows = db::list_exports(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "exports": rows })))
}

#[derive(Deserialize)]
struct UpdateExportReq {
    state: String,
    evidence: Option<Value>,
}

async fn update_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateExportReq>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    db::update_export_state(
        &state.pool,
        &id,
        &req.state,
        &req.evidence.unwrap_or(json!({})),
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "ok": true })))
}

async fn list_views_api(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let views = db::list_views(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "views": views })))
}

async fn save_view_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut view): Json<SavedView>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    if view.id.is_empty() {
        view.id = Uuid::new_v4().to_string();
    }
    view.updated_at = Utc::now();
    db::save_view(&state.pool, &view)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "id": view.id })))
}

async fn get_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let s = state.settings.read().await.clone();
    Ok(Json(json!({ "settings": s })))
}

async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(settings): Json<SettingsDoc>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_mutation(&state, &headers).map_err(status_json)?;
    if let Some(o) = &settings.ownership {
        validate_ownership_config(o)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))))?;
    }
    *state.settings.write().await = settings;
    save_settings(&state)
        .await
        .map_err(|_| status_json(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(json!({ "ok": true })))
}

async fn get_theme(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let settings = state.settings.read().await.clone();
    let theme = if let Some(path) = settings.theme_path {
        load_theme(std::path::Path::new(&path)).unwrap_or_else(|_| neutral_theme())
    } else {
        let default_path = state.profile.join("themes/company.yaml");
        if default_path.exists() {
            load_theme(&default_path).unwrap_or_else(|_| neutral_theme())
        } else {
            neutral_theme()
        }
    };
    Ok(Json(theme_preview_payload(&theme)))
}

#[derive(Deserialize)]
struct ThemeReq {
    yaml: String,
}

async fn set_theme(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ThemeReq>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let path = state.profile.join("themes/company.yaml");
    std::fs::write(&path, &req.yaml).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let theme: crate::theme::ThemeDoc =
        serde_yaml::from_str(&req.yaml).map_err(|_| StatusCode::BAD_REQUEST)?;
    {
        let mut s = state.settings.write().await;
        s.theme_path = Some(path.display().to_string());
    }
    save_settings(&state)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(theme_preview_payload(&theme)))
}

#[derive(Deserialize)]
struct SnowTestReq {
    config: ServiceNowConfig,
    password: String,
}

async fn snow_test(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SnowTestReq>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let client = ServiceNowClient::connect(req.config.clone(), req.password.clone());
    match client.test_access().await {
        Ok(detail) => {
            ServiceNowClient::save_credentials(&req.config, &req.password)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            db::set_connector_status(&state.pool, "servicenow", true, Some(true), &detail)
                .await
                .ok();
            let mut s = state.settings.write().await;
            s.servicenow = Some(serde_json::to_value(&req.config).unwrap_or(Value::Null));
            drop(s);
            save_settings(&state).await.ok();
            Ok(Json(json!({ "ok": true, "detail": detail })))
        }
        Err(e) => {
            db::set_connector_status(
                &state.pool,
                "servicenow",
                true,
                Some(false),
                &json!({ "error": e.to_string() }),
            )
            .await
            .ok();
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

async fn snow_disconnect(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let url = state
        .settings
        .read()
        .await
        .servicenow
        .as_ref()
        .and_then(|v| v.get("instance_url"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if !url.is_empty() {
        let _ = ServiceNowClient::disconnect(&url);
    }
    db::set_connector_status(&state.pool, "servicenow", false, None, &json!({}))
        .await
        .ok();
    let mut s = state.settings.write().await;
    s.servicenow = None;
    drop(s);
    save_settings(&state).await.ok();
    Ok(Json(json!({ "ok": true })))
}

async fn snow_client(state: &AppState) -> Result<ServiceNowClient, StatusCode> {
    let cfg_val = state
        .settings
        .read()
        .await
        .servicenow
        .clone()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let cfg: ServiceNowConfig =
        serde_json::from_value(cfg_val).map_err(|_| StatusCode::BAD_REQUEST)?;
    ServiceNowClient::from_stored(cfg).map_err(|_| StatusCode::BAD_REQUEST)
}

async fn snow_refresh_queues(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let client = snow_client(&state).await?;
    let snap = client
        .refresh_queues(Utc::now())
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let instance = client.config.instance_url.clone();
    let instant = snap.refresh_instant.to_rfc3339();

    let map_queue = |_name: &str, tickets: &[estatetrace_integrations::SnTicket]| {
        tickets
            .iter()
            .map(|t| (t.sys_id.clone(), serde_json::to_value(t).unwrap_or(Value::Null)))
            .collect::<Vec<_>>()
    };

    for (name, tickets, err_key) in [
        ("executed", snap.executed.as_slice(), "executed"),
        ("scheduled_today", snap.scheduled_today.as_slice(), "scheduled_today"),
        (
            "high_priority_incidents",
            snap.high_priority_incidents.as_slice(),
            "high_priority_incidents",
        ),
    ] {
        let failed = snap.errors.contains_key(err_key);
        if failed {
            let has_cache = !db::get_queue_cache(&state.pool, name)
                .await
                .unwrap_or_default()
                .is_empty();
            db::set_queue_meta(
                &state.pool,
                name,
                None,
                has_cache,
                !has_cache,
                snap.errors.get(err_key).map(|s| s.as_str()),
            )
            .await
            .ok();
        } else {
            db::replace_queue_cache(
                &state.pool,
                name,
                &instance,
                &instant,
                &map_queue(name, tickets),
            )
            .await
            .ok();
            db::set_queue_meta(&state.pool, name, Some(&instant), false, false, None)
                .await
                .ok();
        }
    }

    Ok(Json(json!({
        "refresh_instant": snap.refresh_instant,
        "timezone": snap.timezone,
        "executed": snap.executed,
        "scheduled_today": snap.scheduled_today,
        "high_priority_incidents": snap.high_priority_incidents,
        "errors": snap.errors,
        "meta": db::get_queue_meta(&state.pool).await.unwrap_or_default(),
    })))
}

async fn snow_queues(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    Ok(Json(json!({
        "executed": db::get_queue_cache(&state.pool, "executed").await.unwrap_or_default(),
        "scheduled_today": db::get_queue_cache(&state.pool, "scheduled_today").await.unwrap_or_default(),
        "high_priority_incidents": db::get_queue_cache(&state.pool, "high_priority_incidents").await.unwrap_or_default(),
        "meta": db::get_queue_meta(&state.pool).await.unwrap_or_default(),
    })))
}

#[derive(Deserialize)]
struct SnowLookupReq {
    resource_id: String,
    ci_sys_id: Option<String>,
}

async fn snow_lookup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SnowLookupReq>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let tracked = db::tracked_subscription_ids(&state.pool)
        .await
        .unwrap_or_default();
    let obs = db::latest_observation(&state.pool, &req.resource_id)
        .await
        .ok()
        .flatten();
    if let Some(ref o) = obs {
        if !tracked.iter().any(|t| t == o.subscription_id.as_str()) {
            return Ok(Json(json!({
                "status": "out_of_scope",
                "tickets": [],
            })));
        }
    }
    let client = match snow_client(&state).await {
        Ok(c) => c,
        Err(_) => {
            return Ok(Json(json!({
                "status": "unavailable",
                "tickets": [],
            })));
        }
    };
    let Some(ci) = req.ci_sys_id else {
        return Ok(Json(json!({
            "status": "zero_matches",
            "tickets": [],
            "note": "No configuration item mapping supplied"
        })));
    };
    match client.lookup_changes_for_ci(&ci).await {
        Ok(tickets) => {
            for t in &tickets {
                db::insert_ticket_relationship(
                    &state.pool,
                    Some(&req.resource_id),
                    None,
                    t.service.as_deref(),
                    &client.config.instance_url,
                    &t.sys_id,
                    Some(&t.number),
                    "explicit",
                    &json!({ "ci": ci }),
                    "ok",
                )
                .await
                .ok();
            }
            Ok(Json(json!({
                "status": if tickets.is_empty() { "zero_matches" } else { "ok" },
                "tickets": tickets,
            })))
        }
        Err(e) => {
            let status = if e.to_string().contains("unauthorized") {
                "unauthorized"
            } else {
                "unavailable"
            };
            Ok(Json(json!({ "status": status, "error": e.to_string(), "tickets": [] })))
        }
    }
}

#[derive(Deserialize)]
struct ChangesBeforeQuery {
    lookback_hours: Option<i64>,
}

async fn snow_changes_before(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<ChangesBeforeQuery>,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let client = snow_client(&state).await?;
    // Load incident from cache
    let incidents = db::get_queue_cache(&state.pool, "high_priority_incidents")
        .await
        .unwrap_or_default();
    let incident = incidents
        .into_iter()
        .find(|i| {
            i.get("sys_id").and_then(|v| v.as_str()) == Some(id.as_str())
                || i.get("number").and_then(|v| v.as_str()) == Some(id.as_str())
        })
        .ok_or(StatusCode::NOT_FOUND)?;
    let ticket: estatetrace_integrations::SnTicket =
        serde_json::from_value(incident).map_err(|_| StatusCode::BAD_REQUEST)?;
    let lookback = q.lookback_hours.unwrap_or(48);
    let result = client
        .changes_before_incident(&ticket, lookback, Utc::now())
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    db::save_incident_lookup(
        &state.pool,
        &ticket.sys_id,
        result.get("anchor").and_then(|v| v.as_str()),
        result.get("anchor_source").and_then(|v| v.as_str()),
        lookback,
        result.get("completed").unwrap_or(&Value::Null),
        result.get("coverage").unwrap_or(&Value::Null),
        &json!({ "operating_scope": true }),
    )
    .await
    .ok();
    Ok(Json(result))
}

#[derive(Deserialize)]
struct ChatTestReq {
    config: ChatConfig,
    key: String,
}

async fn chat_test(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ChatTestReq>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    ChatClient::save_credentials(&req.config, &req.key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let client = ChatClient::connect(req.config.clone(), req.key);
    match client.test_synthetic().await {
        Ok(detail) => {
            db::set_connector_status(&state.pool, "chat", true, Some(true), &json!({ "tested": true }))
                .await
                .ok();
            let mut s = state.settings.write().await;
            s.chat = Some(serde_json::to_value(&req.config).unwrap_or(Value::Null));
            drop(s);
            save_settings(&state).await.ok();
            Ok(Json(json!({ "ok": true, "detail": detail })))
        }
        Err(e) => {
            db::set_connector_status(
                &state.pool,
                "chat",
                true,
                Some(false),
                &json!({ "error": e.to_string() }),
            )
            .await
            .ok();
            Ok(Json(json!({ "ok": false, "error": e.to_string() })))
        }
    }
}

async fn chat_disconnect(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let url = state
        .settings
        .read()
        .await
        .chat
        .as_ref()
        .and_then(|v| v.get("gateway_url"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if !url.is_empty() {
        let _ = ChatClient::disconnect(&url);
    }
    db::set_connector_status(&state.pool, "chat", false, None, &json!({}))
        .await
        .ok();
    let mut s = state.settings.write().await;
    s.chat = None;
    drop(s);
    save_settings(&state).await.ok();
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct ChatAskReq {
    question: String,
    include_ticket_notes: Option<bool>,
    environment: Option<String>,
    subscription_id: Option<String>,
    severity: Option<String>,
}

async fn chat_ask(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ChatAskReq>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let cfg_val = state
        .settings
        .read()
        .await
        .chat
        .clone()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let cfg: ChatConfig = serde_json::from_value(cfg_val).map_err(|_| StatusCode::BAD_REQUEST)?;
    let client = ChatClient::from_stored(cfg).map_err(|_| StatusCode::BAD_REQUEST)?;

    let tracked = db::tracked_subscription_ids(&state.pool)
        .await
        .unwrap_or_default();
    let rules = db::list_classification_rules(&state.pool)
        .await
        .unwrap_or_default();
    let resources = db::list_latest_resources(&state.pool)
        .await
        .unwrap_or_default();
    // Open findings in scope, grouped by resource (no global LIMIT).
    let mut findings_by_resource: std::collections::HashMap<String, Vec<FindingInterval>> =
        std::collections::HashMap::new();
    for f in db::list_open_findings(
        &state.pool,
        &FindingQuery {
            subscriptions: Some(tracked.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_default()
    {
        findings_by_resource
            .entry(f.resource_id.as_str().to_string())
            .or_default()
            .push(f);
    }
    let mut gaps = Vec::new();
    let mut records = Vec::new();
    for r in resources {
        if !tracked.iter().any(|t| t == r.subscription_id.as_str()) {
            continue;
        }
        if let Some(ref sid) = req.subscription_id {
            if r.subscription_id.as_str() != sid {
                continue;
            }
        }
        let class = classify_resource(&r, &rules);
        if let Some(ref env) = req.environment {
            if class.environment.as_str() != env {
                continue;
            }
        }
        let resource_findings = findings_by_resource
            .get(r.resource_id.as_str())
            .map(Vec::as_slice)
            .unwrap_or_default();
        if let Some(ref sev) = req.severity {
            if !resource_findings.iter().any(|f| f.severity.as_str() == sev) {
                continue;
            }
        }
        // Worst outcome across the resource's controls (fail > unknown > pass > inapplicable).
        let outcome_rank = |o: &EvalOutcome| match o {
            EvalOutcome::Fail => 0,
            EvalOutcome::Unknown => 1,
            EvalOutcome::Pass => 2,
            EvalOutcome::Inapplicable => 3,
        };
        let related = resource_findings.iter().min_by_key(|f| outcome_rank(&f.outcome));
        let failing_controls: Vec<&str> = resource_findings
            .iter()
            .filter(|f| f.outcome == EvalOutcome::Fail)
            .map(|f| f.control_id.as_str())
            .collect();
        let tickets = db::list_ticket_relationships(&state.pool, r.resource_id.as_str())
            .await
            .unwrap_or_default();
        if tickets.is_empty() {
            gaps.push(format!("no ticket link for {}", r.resource_id));
        }
        records.push(json!({
            "resource_id": r.resource_id,
            "name": r.name,
            "subscription_id": r.subscription_id,
            "observation_time": r.observation_time,
            "environment": class.environment,
            "compliance": related.map(|f| f.outcome.as_str()),
            "severity": related.map(|f| f.severity.as_str()),
            "failing_controls": failing_controls,
            "ticket_number": tickets.first().and_then(|t| t.get("record_number").cloned()),
            "ticket_state": tickets.first().and_then(|t| t.get("lookup_status").cloned()),
        }));
    }

    let snow = db::get_connector_status(&state.pool, "servicenow")
        .await
        .ok()
        .flatten();
    if snow
        .as_ref()
        .and_then(|s| s.get("configured"))
        .and_then(|v| v.as_bool())
        != Some(true)
    {
        gaps.push("ServiceNow connector disconnected".into());
    }

    let ctx = ApprovedChatContext {
        question: req.question,
        view_filters: json!({
            "environment": req.environment,
            "subscription_id": req.subscription_id,
            "severity": req.severity,
            "tracked_only": true
        }),
        records,
        evidence_time: Some(Utc::now().to_rfc3339()),
        gaps,
        include_ticket_notes: req.include_ticket_notes.unwrap_or(false),
    };

    match client.ask(&ctx).await {
        Ok(answer) => Ok(Json(answer)),
        Err(e) => Ok(Json(json!({
            "error": e.to_string(),
            "preserved_view": ctx.view_filters,
            "gaps": ctx.gaps,
            "records_count": ctx.records.len(),
        }))),
    }
}

async fn connectors_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    Ok(Json(json!({
        "servicenow": db::get_connector_status(&state.pool, "servicenow").await.ok().flatten(),
        "chat": db::get_connector_status(&state.pool, "chat").await.ok().flatten(),
    })))
}

async fn do_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let dest = state.profile.join(format!(
        "backups/estatetrace-backup-{}.zip",
        Utc::now().format("%Y%m%dT%H%M%SZ")
    ));
    crate::backup::create_backup(&state.profile, &dest).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "path": dest.display().to_string() })))
}

async fn evidence_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<impl IntoResponse, StatusCode> {
    require_mutation(&state, &headers)?;
    // P6.3: leadership readout, aggregates only (no resource IDs).
    if body.get("format").and_then(|v| v.as_str()) == Some("readout") {
        let payload = readout_payload(&state)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let bytes = Bytes::from(serde_json::to_vec_pretty(&payload).unwrap_or_default());
        return Ok((
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            bytes,
        ));
    }
    let resource_id = body
        .get("resource_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let obs = db::latest_observation(&state.pool, resource_id)
        .await
        .ok()
        .flatten();
    let changes = db::list_changes_for_resource(&state.pool, resource_id)
        .await
        .unwrap_or_default();
    let tracked = db::tracked_subscription_ids(&state.pool)
        .await
        .unwrap_or_default();
    let findings: Vec<FindingInterval> = db::findings_for_resource(&state.pool, resource_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|f| in_scope(&tracked, f.subscription_id.as_str()))
        .collect();
    let tickets = db::list_ticket_relationships(&state.pool, resource_id)
        .await
        .unwrap_or_default();
    let payload = json!({
        "resource": obs,
        "changes": changes,
        "findings": findings,
        "tickets": tickets,
        "filter_scope": body.get("filter_scope"),
        "exported_at": Utc::now(),
    });
    let bytes = Bytes::from(serde_json::to_vec_pretty(&payload).unwrap_or_default());
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json",
        )],
        bytes,
    ))
}

fn urlencoding_decode(s: &str) -> String {
    // Resource IDs contain slashes; UI should pass them URL-encoded.
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod auth_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn test_app() -> (axum::Router, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::bootstrap_in(dir.path().to_path_buf())
            .await
            .expect("bootstrap");
        let token = state.session_token.clone();
        // Keep tempdir alive by leaking path ownership into state profile only;
        // hold dir via into_path so DB files remain for the test process lifetime.
        let _kept = dir.keep();
        (router(state), token)
    }

    async fn status_of(app: axum::Router, req: Request<Body>) -> StatusCode {
        let res = app.oneshot(req).await.expect("oneshot");
        res.status()
    }

    #[tokio::test]
    async fn sensitive_reads_require_session() {
        let (app, token) = test_app().await;
        for path in [
            "/api/resources",
            "/api/coverage",
            "/api/settings",
            "/api/theme",
            "/api/scope/exclusion-rules",
            "/api/inbox",
        ] {
            let unauth = Request::builder()
                .uri(path)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                status_of(app.clone(), unauth).await,
                StatusCode::UNAUTHORIZED,
                "{path} should 401 without session"
            );

            let auth = Request::builder()
                .uri(path)
                .header("x-session-token", &token)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                status_of(app.clone(), auth).await,
                StatusCode::OK,
                "{path} should 200 with session"
            );
        }
    }

    #[tokio::test]
    async fn evidence_export_requires_session() {
        let (app, token) = test_app().await;
        let unauth = Request::builder()
            .method("POST")
            .uri("/api/evidence/export")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"resource_id":"x"}"#))
            .unwrap();
        assert_eq!(
            status_of(app.clone(), unauth).await,
            StatusCode::UNAUTHORIZED
        );

        let auth = Request::builder()
            .method("POST")
            .uri("/api/evidence/export")
            .header("content-type", "application/json")
            .header("x-session-token", &token)
            .body(Body::from(r#"{"resource_id":"x"}"#))
            .unwrap();
        assert_eq!(status_of(app, auth).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn mutations_reject_non_loopback_origin() {
        let (app, token) = test_app().await;
        let bad = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("x-session-token", &token)
            .header("origin", "https://evil.example")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(app.clone(), bad).await, StatusCode::FORBIDDEN);

        let good = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("x-session-token", &token)
            .header("origin", "http://127.0.0.1:8787")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(app, good).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn health_and_session_remain_public() {
        let (app, token) = test_app().await;
        assert_eq!(
            status_of(
                app.clone(),
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap()
            )
            .await,
            StatusCode::OK
        );
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["token"].as_str().unwrap(), token);
    }

    #[test]
    fn origin_helper_accepts_loopback_only() {
        let mut headers = HeaderMap::new();
        assert!(origin_ok(&headers));
        headers.insert("origin", "http://127.0.0.1:8787".parse().unwrap());
        assert!(origin_ok(&headers));
        headers.insert("origin", "http://localhost:5173".parse().unwrap());
        assert!(origin_ok(&headers));
        headers.insert("origin", "https://127.0.0.1".parse().unwrap());
        assert!(origin_ok(&headers));
        headers.insert("origin", "http://[::1]:8787".parse().unwrap());
        assert!(origin_ok(&headers));
        headers.insert("origin", "https://evil.example".parse().unwrap());
        assert!(!origin_ok(&headers));
        headers.insert("origin", "null".parse().unwrap());
        assert!(!origin_ok(&headers));
    }

    #[test]
    fn origin_helper_rejects_lookalikes_and_userinfo() {
        assert!(!is_loopback_origin("http://127.0.0.1.evil.example"));
        assert!(!is_loopback_origin("http://localhost.evil.example"));
        assert!(!is_loopback_origin("http://127.0.0.1@evil.example"));
        assert!(!is_loopback_origin("http://localhost@evil.example"));
        assert!(!is_loopback_origin("null"));
        assert!(!is_loopback_origin("not-a-url"));
        assert!(!is_loopback_origin("ftp://127.0.0.1"));
        assert!(!is_loopback_origin("http://192.168.1.1"));
        assert!(!is_loopback_origin("http://0.0.0.0"));
        assert!(is_loopback_origin("http://127.0.0.1:8787"));
        assert!(is_loopback_origin("http://localhost"));
        assert!(is_loopback_origin("http://[::1]"));
    }
}

#[cfg(test)]
mod exception_tests {
    //! P2: `POST /api/exceptions` (spec §3.4, AC-P2-5, §7 expired-at-creation row).
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const SUB: &str = "11111111-2222-3333-4444-555555555555";

    async fn app() -> (axum::Router, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::bootstrap_in(dir.path().to_path_buf())
            .await
            .expect("bootstrap");
        let token = state.session_token.clone();
        let _kept = dir.keep();
        (router(state), token)
    }

    async fn call(
        app: &axum::Router,
        token: &str,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-session-token", token)
            .header("origin", "http://127.0.0.1:8787");
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let res = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn ac_p2_5_post_exception_without_scope_returns_400() {
        let (app, token) = app().await;
        for body in [
            json!({ "control_id": "STG-001" }),
            json!({ "control_id": "STG-001", "resource_id": "  ", "subscription_id": "" }),
            json!({ "control_id": "STG-001", "resource_group": "rg-app" }),
        ] {
            let (status, out) =
                call(&app, &token, "POST", "/api/exceptions", Some(body.clone())).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert!(out["error"].as_str().unwrap().contains("scope"), "{out}");
        }
        let (_, listed) = call(&app, &token, "GET", "/api/exceptions", None).await;
        assert_eq!(listed["exceptions"].as_array().unwrap().len(), 0, "nothing stored");
    }

    #[tokio::test]
    async fn post_exception_rejects_missing_control_and_bad_expiry() {
        let (app, token) = app().await;
        let (s, _) = call(
            &app,
            &token,
            "POST",
            "/api/exceptions",
            Some(json!({ "subscription_id": SUB })),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = call(
            &app,
            &token,
            "POST",
            "/api/exceptions",
            Some(json!({ "control_id": "C", "subscription_id": SUB, "expires_at": "next tuesday" })),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_scoped_exception_and_list_by_covered_resource() {
        let (app, token) = app().await;
        let (s, out) = call(
            &app,
            &token,
            "POST",
            "/api/exceptions",
            Some(json!({
                "control_id": "STG-001",
                "subscription_id": SUB,
                "resource_group": "rg-app",
                "ticket_ref": "CHG0042",
                "expires_at": "2099-12-31"
            })),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{out}");
        assert_eq!(out["expired"], json!(false));
        assert_eq!(out["exception"]["resource_id"], Value::Null);
        assert_eq!(out["exception"]["resource_group"], json!("rg-app"));
        assert_eq!(out["exception"]["ticket_ref"], json!("CHG0042"));

        let inside = format!(
            "/subscriptions/{SUB}/resourceGroups/RG-APP/providers/Microsoft.Storage/storageAccounts/st1"
        );
        let outside = format!(
            "/subscriptions/{SUB}/resourceGroups/rg-other/providers/Microsoft.Storage/storageAccounts/st2"
        );
        let enc = |s: &str| s.replace('/', "%2F");
        let (_, hit) = call(
            &app,
            &token,
            "GET",
            &format!("/api/exceptions?resource_id={}", enc(&inside)),
            None,
        )
        .await;
        assert_eq!(hit["exceptions"].as_array().unwrap().len(), 1);
        let (_, miss) = call(
            &app,
            &token,
            "GET",
            &format!("/api/exceptions?resource_id={}", enc(&outside)),
            None,
        )
        .await;
        assert_eq!(miss["exceptions"].as_array().unwrap().len(), 0);
        let (_, by_control) =
            call(&app, &token, "GET", "/api/exceptions?control_id=STG-002", None).await;
        assert_eq!(by_control["exceptions"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn past_expiry_is_accepted_but_flagged_expired() {
        let (app, token) = app().await;
        let (s, out) = call(
            &app,
            &token,
            "POST",
            "/api/exceptions",
            Some(json!({
                "control_id": "STG-001",
                "resource_id": "/subscriptions/x/resourceGroups/rg/providers/a/b/c",
                "subscription_id": SUB,
                "expires_at": "2020-01-01T00:00:00Z"
            })),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(out["expired"], json!(true));
        // A resource scope drops the redundant subscription so the stored shape is exact.
        assert_eq!(out["exception"]["subscription_id"], Value::Null);

        let (_, summary) = call(&app, &token, "GET", "/api/compliance", None).await;
        assert_eq!(summary["exceptions"], json!(0), "expired exceptions are not active");
        assert_eq!(summary["excepted"], json!(0));
    }

    #[tokio::test]
    async fn post_exception_requires_session_and_loopback_origin() {
        let (app, token) = app().await;
        let body = json!({ "control_id": "C", "subscription_id": SUB }).to_string();
        let unauth = Request::builder()
            .method("POST")
            .uri("/api/exceptions")
            .header("content-type", "application/json")
            .body(Body::from(body.clone()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(unauth).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let bad_origin = Request::builder()
            .method("POST")
            .uri("/api/exceptions")
            .header("content-type", "application/json")
            .header("x-session-token", &token)
            .header("origin", "https://evil.example")
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            app.oneshot(bad_origin).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
}

/// Phase 4 API tests (AC-P4-6 and rule handlers). Fictional names only.
#[cfg(test)]
mod classification_api_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn seeded() -> (axum::Router, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::bootstrap_in(dir.path().to_path_buf())
            .await
            .expect("bootstrap");
        let _kept = dir.keep();
        let pool = &state.pool;
        db::upsert_tenant(
            pool,
            &TenantInfo {
                id: TenantId::new("tenant-contoso"),
                name: "Contoso".into(),
                needs_sign_in: false,
                last_refresh: Some(Utc::now()),
                access_issue: None,
            },
        )
        .await
        .unwrap();
        for (id, name) in [
            ("sub-contoso-prod", "Contoso-Prod-01"),
            ("sub-contoso-shared", "Products-Shared"),
        ] {
            db::upsert_subscription(
                pool,
                &SubscriptionInfo {
                    id: SubscriptionId::new(id),
                    tenant_id: TenantId::new("tenant-contoso"),
                    name: name.into(),
                    state: "Enabled".into(),
                    quota_id: None,
                    tags: json!({}),
                    access_issue: None,
                    last_refresh: Some(Utc::now()),
                },
            )
            .await
            .unwrap();
            db::insert_scope_decision(
                pool,
                &ScopeDecision {
                    id: format!("track-{id}"),
                    provider: Provider::Azure,
                    tenant_id: TenantId::new("tenant-contoso"),
                    subscription_id: Some(SubscriptionId::new(id)),
                    decision: DecisionKind::Track,
                    source: DecisionSource::Explicit,
                    matching_rule_id: None,
                    reason: None,
                    effective_from: Utc::now(),
                    effective_to: None,
                },
            )
            .await
            .unwrap();
        }
        let resources = [
            ("web-payments", "rg-pay", json!({ "app-name": "Payments", "owner": "team-a" })),
            ("web-ledger", "rg-ledger", json!({ "app-name": "undefined" })),
        ];
        for (name, rg, tags) in resources {
            let rid = format!(
                "/subscriptions/sub-contoso-prod/resourceGroups/{rg}/providers/Microsoft.Web/sites/{name}"
            );
            db::insert_observation(
                pool,
                &ResourceObservation {
                    id: format!("obs-{name}"),
                    provider: Provider::Azure,
                    resource_id: ResourceId::new(rid.clone()),
                    tenant_id: TenantId::new("tenant-contoso"),
                    subscription_id: SubscriptionId::new("sub-contoso-prod"),
                    resource_type: "Microsoft.Web/sites".into(),
                    name: name.into(),
                    location: Some("eastus".into()),
                    resource_group: Some(rg.into()),
                    tags,
                    properties: json!({}),
                    scan_id: "scan-1".into(),
                    observation_time: Utc::now(),
                    evidence_available: true,
                    lifecycle_epoch: 1,
                    arm_meta: serde_json::json!({}),
                },
            )
            .await
            .unwrap();
            db::insert_change_event(
                pool,
                &ChangeEvent {
                    id: format!("chg-{name}"),
                    resource_id: ResourceId::new(rid),
                    subscription_id: SubscriptionId::new("sub-contoso-prod"),
                    source_event_id: Some(format!("test:{name}")),
                    label: ChangeLabel::Updated,
                    times: DualTime::observed_now(),
                    before: None,
                    after: None,
                    property_diffs: json!({}),
                },
            )
            .await
            .unwrap();
        }
        // RG name stored in different case than the observation: lookup is case-insensitive.
        db::upsert_resource_group_tags(
            pool,
            &[ResourceGroupTags {
                subscription_id: SubscriptionId::new("sub-contoso-prod"),
                resource_group: "RG-Ledger".into(),
                tags: json!({ "App-Name": "Ledger", "Owner": "team-b", "Environment": "prod" }),
                observed_at: Utc::now(),
            }],
        )
        .await
        .unwrap();
        state.settings.write().await.ownership = Some(OwnershipConfig {
            application_tag: Some("app-name".into()),
            owner_tag: Some("owner".into()),
            ..Default::default()
        });
        let token = state.session_token.clone();
        (router(state), token)
    }

    async fn get_json(app: &axum::Router, token: &str, uri: &str) -> Value {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("x-session-token", token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{uri}");
        let body = res.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    async fn post(app: &axum::Router, token: &str, uri: &str, body: Value) -> StatusCode {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("x-session-token", token)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    fn names(v: &Value) -> Vec<String> {
        v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["resource"]["name"].as_str().unwrap_or("").to_string())
            .collect()
    }

    #[tokio::test]
    async fn ac_p4_6_inbox_application_owner_filters_and_group_by_use_derive_ownership() {
        let (app, token) = seeded().await;

        let all = get_json(&app, &token, "/api/inbox").await;
        assert_eq!(all["rows"].as_array().unwrap().len(), 2);

        // web-ledger's own app tag is `undefined`; the RG tag supplies the application.
        let ledger = get_json(&app, &token, "/api/inbox?application=ledger").await;
        assert_eq!(names(&ledger), vec!["web-ledger"]);
        assert_eq!(ledger["rows"][0]["ownership"]["application"], "Ledger");
        assert_eq!(ledger["rows"][0]["ownership"]["from_resource_group"], true);

        let team_a = get_json(&app, &token, "/api/inbox?owner=TEAM-A").await;
        assert_eq!(names(&team_a), vec!["web-payments"]);
        let team_b = get_json(&app, &token, "/api/inbox?owner=team-b&application=Ledger").await;
        assert_eq!(names(&team_b), vec!["web-ledger"]);
        let none = get_json(&app, &token, "/api/inbox?owner=team-c").await;
        assert!(none["rows"].as_array().unwrap().is_empty());

        let by_owner = get_json(&app, &token, "/api/inbox?group_by=owner").await;
        assert_eq!(names(&by_owner), vec!["web-payments", "web-ledger"]);
        assert_eq!(
            by_owner["groups"],
            json!([{ "key": "team-a", "count": 1 }, { "key": "team-b", "count": 1 }])
        );
        assert_eq!(by_owner["rows"][1]["group_key"], "team-b");

        let by_app = get_json(&app, &token, "/api/inbox?group_by=application").await;
        assert_eq!(names(&by_app), vec!["web-ledger", "web-payments"]);
        assert_eq!(by_app["groups"][0]["key"], "Ledger");
    }

    #[tokio::test]
    async fn rule_save_validates_regex_and_suggested_rules_are_not_saved() {
        let (app, token) = seeded().await;

        let suggested = get_json(&app, &token, "/api/classification/suggested-rules").await;
        assert!(suggested["rules"].as_array().unwrap().len() >= 5);
        let saved = get_json(&app, &token, "/api/classification/rules").await;
        assert!(
            saved["rules"].as_array().unwrap().is_empty(),
            "suggested rules are never auto-saved"
        );

        let bad = json!({
            "id": "bad", "kind": "subscription_name_pattern", "subscription_id": null,
            "resource_group": null, "tag_key": null, "tag_value": null,
            "environment": "prod", "priority": 10, "pattern": "(?<!non)prod"
        });
        assert_eq!(
            post(&app, &token, "/api/classification/rules", bad).await,
            StatusCode::BAD_REQUEST
        );

        let good = json!({
            "id": "subname-prod", "kind": "subscription_name_pattern", "subscription_id": null,
            "resource_group": null, "tag_key": null, "tag_value": null,
            "environment": "prod", "priority": 490,
            "pattern": "(?i)(^|[^a-z0-9])prod(uction)?([^a-z0-9]|$)"
        });
        assert_eq!(
            post(&app, &token, "/api/classification/rules", good).await,
            StatusCode::OK
        );
        let seg = json!({
            "id": "svc-seg", "kind": "tag_segment", "subscription_id": null,
            "resource_group": null, "tag_key": "svc", "tag_value": null,
            "environment": "unknown", "priority": 300,
            "segment_map": { "dev": "dev", "prod": "prod" }
        });
        assert_eq!(
            post(&app, &token, "/api/classification/rules", seg).await,
            StatusCode::OK
        );
        let saved = get_json(&app, &token, "/api/classification/rules").await;
        let rules = saved["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        let seg_rule = rules.iter().find(|r| r["id"] == "svc-seg").unwrap();
        assert_eq!(seg_rule["kind"], "tag_segment");
        assert_eq!(seg_rule["segment_map"]["dev"], "dev");
        let name_rule = rules.iter().find(|r| r["id"] == "subname-prod").unwrap();
        assert_eq!(name_rule["pattern"], "(?i)(^|[^a-z0-9])prod(uction)?([^a-z0-9]|$)");

        // Resources in Contoso-Prod-01 are now Prod by subscription name.
        let res = get_json(&app, &token, "/api/resources").await;
        for r in res["resources"].as_array().unwrap() {
            assert_eq!(r["classification"]["environment"], "prod");
            assert_eq!(r["classification"]["source"], "subscription_name");
        }

        // Ownership config with a bad rollup regex is rejected.
        let bad_settings = json!({
            "scan_interval_minutes": 60, "operations_timezone": null, "chat_history_enabled": false,
            "retention": {}, "production_mappings": {}, "servicenow": null, "chat": null,
            "theme_path": null, "ownership": { "lob_rollup_pattern": "(" }
        });
        assert_eq!(
            post(&app, &token, "/api/settings", bad_settings).await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn classification_quality_counts_sources_and_tokenless_subscriptions() {
        let (app, token) = seeded().await;
        let rg_rule = json!({
            "id": "rgtag-env", "kind": "resource_group_tag", "subscription_id": null,
            "resource_group": null, "tag_key": "Environment", "tag_value": null,
            "environment": "unknown", "priority": 270
        });
        assert_eq!(
            post(&app, &token, "/api/classification/rules", rg_rule).await,
            StatusCode::OK
        );

        let q = get_json(&app, &token, "/api/classification/quality").await;
        assert_eq!(q["total"], 2);
        assert_eq!(q["by_source"]["resource_group_tag"], 1);
        assert_eq!(q["by_source"]["none"], 1);
        assert_eq!(q["name_rules"], "suggested");
        let tokenless: Vec<&str> = q["subscriptions_without_environment_token"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["name"].as_str().unwrap())
            .collect();
        assert_eq!(tokenless, vec!["Products-Shared"]);
    }
}

// ---------------------------------------------------------------------------
// Phase 7: check-map compile (spec §3.4, §4.8, §7 "check-map compile with error issues")
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CompilePackReq {
    catalog: String,
    check_map: String,
    #[serde(default)]
    settings: Option<String>,
}

/// `POST /api/packs/compile`: catalog + check map (+ settings), all YAML or JSON text, to a
/// pack. Returns `{ pack, issues }`; 422 with the full issue list (and `pack: null`) when any
/// issue is an error. Nothing is saved: the UI imports the pack through `POST /api/packs`.
async fn compile_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CompilePackReq>,
) -> Result<axum::response::Response, StatusCode> {
    use estatetrace_policy::{
        compile_check_map, parse_catalog, parse_check_map_yaml, parse_compile_settings,
        LintIssue, LintSeverity,
    };
    require_mutation(&state, &headers)?;
    let rejected = |issues: Vec<LintIssue>| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "pack": Value::Null, "issues": issues })),
        )
            .into_response()
    };
    let input_error = |e: anyhow::Error| LintIssue {
        severity: LintSeverity::Error,
        control_id: None,
        message: format!("{e:#}"),
    };
    let mut input_issues = Vec::new();
    let catalog = parse_catalog(&req.catalog)
        .map_err(|e| input_issues.push(input_error(e)))
        .ok();
    let map = parse_check_map_yaml(&req.check_map)
        .map_err(|e| input_issues.push(input_error(e)))
        .ok();
    let settings = parse_compile_settings(req.settings.as_deref().unwrap_or(""))
        .map_err(|e| input_issues.push(input_error(e)))
        .ok();
    let (Some(catalog), Some(map), Some(settings)) = (catalog, map, settings) else {
        return Ok(rejected(input_issues));
    };
    let (pack, issues) =
        match compile_check_map(&catalog, &map, &settings, builtin_resource_kinds()) {
            Ok(x) => x,
            Err(e) => return Ok(rejected(vec![input_error(e)])),
        };
    if issues.iter().any(|i| i.severity == LintSeverity::Error) {
        return Ok(rejected(issues));
    }
    Ok(Json(json!({ "pack": pack, "issues": issues })).into_response())
}

/// Phase 7 API tests (AC-P7-1, AC-P7-4, §7 compile row). Fictional fixture only.
#[cfg(test)]
mod compile_api_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const CATALOG: &str =
        include_str!("../../../kits/policy-authoring/examples/check_map/catalog.yaml");
    const MAP: &str =
        include_str!("../../../kits/policy-authoring/examples/check_map/check_map.yaml");
    const SETTINGS: &str =
        include_str!("../../../kits/policy-authoring/examples/check_map/settings.yaml");

    async fn app() -> (axum::Router, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::bootstrap_in(dir.path().to_path_buf())
            .await
            .expect("bootstrap");
        let token = state.session_token.clone();
        let _kept = dir.keep();
        (router(state), token)
    }

    async fn call(
        app: &axum::Router,
        token: &str,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-session-token", token)
            .header("origin", "http://127.0.0.1:8787");
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let res = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn pack_count(app: &axum::Router, token: &str) -> usize {
        let (_, packs) = call(app, token, "GET", "/api/packs", None).await;
        packs["packs"].as_array().map(|a| a.len()).unwrap_or(0)
    }

    #[tokio::test]
    async fn ac_p7_4_compiled_pack_imports_through_api_packs() {
        let (app, token) = app().await;
        let before = pack_count(&app, &token).await;
        let (s, out) = call(
            &app,
            &token,
            "POST",
            "/api/packs/compile",
            Some(json!({ "catalog": CATALOG, "check_map": MAP, "settings": SETTINGS })),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{out}");
        assert_eq!(out["pack"]["id"], json!("EXAMPLE-WORKPLACE-CATALOG"));
        assert_eq!(out["pack"]["controls"].as_array().unwrap().len(), 5);
        let issues = out["issues"].as_array().unwrap();
        assert!(issues.iter().all(|i| i["severity"] == json!("warning")), "{out}");
        assert!(issues
            .iter()
            .any(|i| i["message"].as_str().unwrap().contains("verified: false")));
        assert_eq!(pack_count(&app, &token).await, before, "compile saves nothing");

        // Import the compiled pack the way the UI does.
        let (s, imported) = call(
            &app,
            &token,
            "POST",
            "/api/packs",
            Some(json!({
                "json": out["pack"].to_string(),
                "reviewed_by": "operator",
                "activate": true
            })),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{imported}");
        assert_eq!(imported["activated"], json!(true), "{imported}");
        assert_eq!(imported["id"], json!("EXAMPLE-WORKPLACE-CATALOG"));
        assert!(imported["revision"].as_str().unwrap().starts_with("2.1+"));
        assert_eq!(pack_count(&app, &token).await, before + 1);
    }

    #[tokio::test]
    async fn compile_with_error_issues_returns_422_and_saves_nothing() {
        let (app, token) = app().await;
        let before = pack_count(&app, &token).await;
        // No settings: expected_setting cannot resolve.
        let (s, out) = call(
            &app,
            &token,
            "POST",
            "/api/packs/compile",
            Some(json!({ "catalog": CATALOG, "check_map": MAP })),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{out}");
        assert_eq!(out["pack"], Value::Null);
        let issues = out["issues"].as_array().unwrap();
        assert!(issues.iter().any(|i| i["severity"] == json!("error")
            && i["control_id"] == json!("EXW-AVD-02/pooled")
            && i["message"].as_str().unwrap().contains("expected_setting")));
        // The full list: warnings come back beside the errors.
        assert!(issues.iter().any(|i| i["severity"] == json!("warning")));

        // AC-P7-1 through the API: the unaccounted control is named.
        let map = MAP
            .replace("\r\n", "\n")
            .replace("  EXW-REG-04:\n", "  EXW-OTHER:\n");
        let (s, out) = call(
            &app,
            &token,
            "POST",
            "/api/packs/compile",
            Some(json!({ "catalog": CATALOG, "check_map": map, "settings": SETTINGS })),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{out}");
        assert!(out["issues"].as_array().unwrap().iter().any(|i| i["control_id"]
            == json!("EXW-REG-04")
            && i["severity"] == json!("error")));

        // Unparseable input is an error issue too, one per bad document.
        let (s, out) = call(
            &app,
            &token,
            "POST",
            "/api/packs/compile",
            Some(json!({ "catalog": "controls: 3", "check_map": "{not yaml" })),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(out["issues"].as_array().unwrap().len(), 2, "{out}");

        assert_eq!(pack_count(&app, &token).await, before);
    }

    #[tokio::test]
    async fn compile_requires_session_and_loopback_origin() {
        let (app, token) = app().await;
        let body = json!({ "catalog": CATALOG, "check_map": MAP }).to_string();
        let unauth = Request::builder()
            .method("POST")
            .uri("/api/packs/compile")
            .header("content-type", "application/json")
            .body(Body::from(body.clone()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(unauth).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let bad_origin = Request::builder()
            .method("POST")
            .uri("/api/packs/compile")
            .header("content-type", "application/json")
            .header("x-session-token", &token)
            .header("origin", "https://evil.example")
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            app.oneshot(bad_origin).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
}

/// Phase 3 API tests: readers use finding intervals, scoped and triaged per control.
#[cfg(test)]
mod findings_api_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Duration;
    use estatetrace_policy::PackEvaluation;
    use http_body_util::BodyExt;
    use std::collections::HashSet;
    use tower::ServiceExt;

    const TRACKED: &str = "sub-tracked";
    const UNTRACKED: &str = "sub-untracked";

    fn rid(sub: &str, name: &str) -> String {
        format!("/subscriptions/{sub}/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/{name}")
    }

    fn ev(resource: &str, control: &str, outcome: EvalOutcome, at: DateTime<Utc>) -> Evaluation {
        Evaluation {
            id: format!("{resource}:{control}"),
            observation_id: format!("obs-{resource}"),
            resource_id: ResourceId::new(resource),
            control_id: control.into(),
            control_revision: "1".into(),
            outcome,
            severity: Severity::High,
            evidence: json!({ "clause_revision": "1", "lane": "security" }),
            evaluated_at: at,
            environment: EnvironmentClass::Unknown,
            detail: String::new(),
        }
    }

    fn result(evaluations: Vec<Evaluation>) -> PackEvaluation {
        PackEvaluation {
            evaluations,
            coverage_gaps: vec![],
        }
    }

    async fn seeded() -> (axum::Router, String, AppState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::bootstrap_in(dir.path().to_path_buf())
            .await
            .expect("bootstrap");
        let _kept = dir.keep();
        let pool = &state.pool;
        db::upsert_tenant(
            pool,
            &TenantInfo {
                id: TenantId::new("tenant-fabrikam"),
                name: "Fabrikam".into(),
                needs_sign_in: false,
                last_refresh: Some(Utc::now()),
                access_issue: None,
            },
        )
        .await
        .unwrap();
        for (id, decision) in [(TRACKED, DecisionKind::Track), (UNTRACKED, DecisionKind::Exclude)] {
            db::upsert_subscription(
                pool,
                &SubscriptionInfo {
                    id: SubscriptionId::new(id),
                    tenant_id: TenantId::new("tenant-fabrikam"),
                    name: id.into(),
                    state: "Enabled".into(),
                    quota_id: None,
                    tags: json!({}),
                    access_issue: None,
                    last_refresh: Some(Utc::now()),
                },
            )
            .await
            .unwrap();
            db::insert_scope_decision(
                pool,
                &ScopeDecision {
                    id: format!("decision-{id}"),
                    provider: Provider::Azure,
                    tenant_id: TenantId::new("tenant-fabrikam"),
                    subscription_id: Some(SubscriptionId::new(id)),
                    decision,
                    source: DecisionSource::Explicit,
                    matching_rule_id: None,
                    reason: None,
                    effective_from: Utc::now(),
                    effective_to: None,
                },
            )
            .await
            .unwrap();
        }
        for sub in [TRACKED, UNTRACKED] {
            let r = rid(sub, "st1");
            db::insert_observation(
                pool,
                &ResourceObservation {
                    id: format!("obs-{r}"),
                    provider: Provider::Azure,
                    resource_id: ResourceId::new(r.clone()),
                    tenant_id: TenantId::new("tenant-fabrikam"),
                    subscription_id: SubscriptionId::new(sub),
                    resource_type: "Microsoft.Storage/storageAccounts".into(),
                    name: format!("st1-{sub}"),
                    location: Some("eastus".into()),
                    resource_group: Some("rg-app".into()),
                    tags: json!({}),
                    properties: json!({}),
                    scan_id: "scan-1".into(),
                    observation_time: Utc::now(),
                    evidence_available: true,
                    lifecycle_epoch: 1,
                    arm_meta: json!({}),
                },
            )
            .await
            .unwrap();
            db::insert_change_event(
                pool,
                &ChangeEvent {
                    id: format!("chg-{sub}"),
                    resource_id: ResourceId::new(r.clone()),
                    subscription_id: SubscriptionId::new(sub),
                    source_event_id: Some(format!("test:{sub}")),
                    label: ChangeLabel::Updated,
                    times: DualTime::observed_now(),
                    before: None,
                    after: None,
                    property_diffs: json!({}),
                },
            )
            .await
            .unwrap();
        }
        // The tracked resource fails control A and passes control B; the untracked one
        // fails A.
        let at = Utc::now() - Duration::hours(1);
        let tracked = rid(TRACKED, "st1");
        db::save_policy_pack(pool, "PACK-1", "Pack", "1", None, Some("test"), true, &json!({}))
            .await
            .unwrap();
        db::record_pack_evaluation(
            pool,
            "scan-1",
            "PACK-1",
            "1",
            &HashSet::new(),
            &result(vec![
                ev(&tracked, "CTL-A", EvalOutcome::Fail, at),
                ev(&tracked, "CTL-B", EvalOutcome::Pass, at),
                ev(&rid(UNTRACKED, "st1"), "CTL-A", EvalOutcome::Fail, at),
            ]),
        )
        .await
        .unwrap();
        let token = state.session_token.clone();
        (router(state.clone()), token, state)
    }

    async fn call(
        app: &axum::Router,
        token: &str,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-session-token", token)
            .header("origin", "http://127.0.0.1:8787");
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let res = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    fn enc(s: &str) -> String {
        s.replace('/', "%2F")
    }

    #[tokio::test]
    async fn ac_p3_7_inbox_triages_per_control_and_pass_does_not_mask_fail() {
        let (app, token, _) = seeded().await;
        let (s, inbox) = call(&app, &token, "GET", "/api/inbox", None).await;
        assert_eq!(s, StatusCode::OK);
        let rows = inbox["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "untracked subscription is out of scope");
        let row = &rows[0];
        assert_eq!(row["triage"]["state"], "actionable", "{row}");
        assert_eq!(row["finding"]["control_id"], "CTL-A");
        let per_control: Vec<(String, String)> = row["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["finding"]["control_id"].as_str().unwrap().to_string(),
                    f["triage"]["state"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(
            per_control,
            vec![
                ("CTL-A".to_string(), "actionable".to_string()),
                ("CTL-B".to_string(), "pass".to_string())
            ]
        );
        assert!(row.get("evaluation").is_none(), "legacy key removed");
    }

    #[tokio::test]
    async fn findings_endpoint_is_scoped_and_returns_full_history() {
        let (app, token, state) = seeded().await;
        let (s, out) = call(&app, &token, "GET", "/api/findings", None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(out["findings"].as_array().unwrap().len(), 2, "tracked subscription only");
        assert_eq!(out["triage"].as_array().unwrap().len(), 2);
        let (_, fails) = call(&app, &token, "GET", "/api/findings?outcome=fail", None).await;
        assert_eq!(fails["findings"].as_array().unwrap().len(), 1);

        // Fail -> pass on CTL-A: the history keeps both intervals (AC-P3-8 read shape).
        let tracked = rid(TRACKED, "st1");
        db::record_pack_evaluation(
            &state.pool,
            "scan-2",
            "PACK-1",
            "1",
            &HashSet::new(),
            &result(vec![ev(&tracked, "CTL-A", EvalOutcome::Pass, Utc::now())]),
        )
        .await
        .unwrap();
        let uri = format!("/api/findings?resource_id={}", enc(&tracked));
        let (_, hist) = call(&app, &token, "GET", &uri, None).await;
        let hist = hist["findings"].as_array().unwrap();
        assert_eq!(hist.len(), 3);
        assert!(hist.iter().any(|f| f["close_reason"] == "state_changed"));

        let uri = format!("/api/resources/{}/timeline", enc(&tracked));
        let (_, timeline) = call(&app, &token, "GET", &uri, None).await;
        let tl_findings = timeline["findings"].as_array().unwrap();
        assert_eq!(tl_findings.len(), 3);
        assert!(timeline.get("evaluations").is_none());
        let triage = timeline["findings_triage"].as_array().unwrap();
        assert_eq!(triage.len(), 3);
        let a_open = tl_findings
            .iter()
            .position(|f| f["control_id"] == "CTL-A" && f["closed_at"].is_null())
            .unwrap();
        assert_eq!(triage[a_open]["state"], "verified_corrected");
        let a_closed = tl_findings
            .iter()
            .position(|f| f["control_id"] == "CTL-A" && !f["closed_at"].is_null())
            .unwrap();
        assert!(triage[a_closed].is_null(), "closed intervals carry no triage");

        // Out-of-scope history is hidden.
        let uri = format!("/api/findings?resource_id={}", enc(&rid(UNTRACKED, "st1")));
        let (_, hidden) = call(&app, &token, "GET", &uri, None).await;
        assert!(hidden["findings"].as_array().unwrap().is_empty());

        let (_, summary) = call(&app, &token, "GET", "/api/compliance", None).await;
        assert_eq!(summary["passing"], 2);
        assert_eq!(summary["failing"], 0, "untracked fail is out of scope");
        assert_eq!(summary["verified_corrected"], 1);

        let (s, export) = call(
            &app,
            &token,
            "POST",
            "/api/evidence/export",
            Some(json!({ "resource_id": tracked })),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(export["findings"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn ac_p3_9_pack_revision_activation_and_deactivation_close_findings() {
        let (app, token, state) = seeded().await;
        let tracked = rid(TRACKED, "st1");
        db::save_policy_pack(&state.pool, "PACK-1", "Pack", "2", None, Some("test"), false, &json!({}))
            .await
            .unwrap();
        let (s, _) = call(
            &app,
            &token,
            "POST",
            "/api/packs/PACK-1/activate",
            Some(json!({ "revision": "9" })),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, out) = call(
            &app,
            &token,
            "POST",
            "/api/packs/PACK-1/activate",
            Some(json!({ "revision": "2" })),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{out}");
        assert_eq!(out["closed"], 3);
        let hist = db::findings_for_resource(&state.pool, &tracked).await.unwrap();
        assert!(hist.iter().all(|f| f.close_reason == Some(CloseReason::PackRevision)));
        let active = db::active_policy_packs(&state.pool).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0]["revision"], "2");

        // Re-activating the active revision closes nothing.
        db::record_pack_evaluation(
            &state.pool,
            "scan-2",
            "PACK-1",
            "2",
            &HashSet::new(),
            &result(vec![ev(&tracked, "CTL-A", EvalOutcome::Fail, Utc::now())]),
        )
        .await
        .unwrap();
        let (_, out) = call(
            &app,
            &token,
            "POST",
            "/api/packs/PACK-1/activate",
            Some(json!({ "revision": "2" })),
        )
        .await;
        assert_eq!(out["closed"], 0);

        let (s, out) = call(&app, &token, "POST", "/api/packs/PACK-1/deactivate", None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(out["closed"], 1);
        assert!(db::list_open_findings(&state.pool, &FindingQuery::default())
            .await
            .unwrap()
            .is_empty());
        let hist = db::findings_for_resource(&state.pool, &tracked).await.unwrap();
        assert!(hist
            .iter()
            .any(|f| f.close_reason == Some(CloseReason::PackDeactivated)));
        assert!(db::active_policy_packs(&state.pool).await.unwrap().is_empty());

        // Mutations still need a loopback origin.
        let bad = Request::builder()
            .method("POST")
            .uri("/api/packs/PACK-1/deactivate")
            .header("x-session-token", &token)
            .header("origin", "https://evil.example")
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.clone().oneshot(bad).await.unwrap().status(), StatusCode::FORBIDDEN);
    }
}

/// Phase 6 API tests: reporting endpoints, readout export and the security-first defaults.
#[cfg(test)]
mod reporting_api_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Duration;
    use estatetrace_policy::PackEvaluation;
    use http_body_util::BodyExt;
    use std::collections::HashSet;
    use tower::ServiceExt;

    const TRACKED: &str = "sub-tracked";
    const UNTRACKED: &str = "sub-untracked";

    fn rid(sub: &str, name: &str) -> String {
        format!("/subscriptions/{sub}/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/{name}")
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
            evidence: json!({ "clause_revision": "1", "lane": lane }),
            evaluated_at: at,
            environment: EnvironmentClass::Prod,
            detail: String::new(),
        }
    }

    async fn empty_app() -> (axum::Router, String, AppState) {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = AppState::bootstrap_in(dir.path().to_path_buf())
            .await
            .expect("bootstrap");
        let _kept = dir.keep();
        let token = state.session_token.clone();
        (router(state.clone()), token, state)
    }

    async fn observe(pool: &sqlx::SqlitePool, sub: &str, name: &str, tags: Value) {
        let r = rid(sub, name);
        db::insert_observation(
            pool,
            &ResourceObservation {
                id: format!("obs-{r}"),
                provider: Provider::Azure,
                resource_id: ResourceId::new(r.clone()),
                tenant_id: TenantId::new("tenant-fabrikam"),
                subscription_id: SubscriptionId::new(sub),
                resource_type: "Microsoft.Storage/storageAccounts".into(),
                name: format!("{name}-{sub}"),
                location: Some("eastus".into()),
                resource_group: Some("rg-app".into()),
                tags,
                properties: json!({}),
                scan_id: "scan-1".into(),
                observation_time: Utc::now(),
                evidence_available: true,
                lifecycle_epoch: 1,
                arm_meta: json!({}),
            },
        )
        .await
        .unwrap();
        db::insert_change_event(
            pool,
            &ChangeEvent {
                id: format!("chg-{sub}-{name}"),
                resource_id: ResourceId::new(r.clone()),
                subscription_id: SubscriptionId::new(sub),
                source_event_id: Some(format!("test:{sub}:{name}")),
                label: ChangeLabel::Updated,
                times: DualTime::observed_now(),
                before: None,
                after: None,
                property_diffs: json!({}),
            },
        )
        .await
        .unwrap();
    }

    /// Tracked: `a` fails SEC-1 (security, opened 1h ago) and TAG-1 (hygiene); `b` fails SEC-1
    /// (opened 9 days ago); `c` passes SEC-2. Untracked: `x` fails OUT-1 and SEC-1.
    /// One finished scan, one coverage gap, one active exception per subscription.
    async fn seeded() -> (axum::Router, String, AppState) {
        let (app, token, state) = empty_app().await;
        let pool = &state.pool;
        db::upsert_tenant(
            pool,
            &TenantInfo {
                id: TenantId::new("tenant-fabrikam"),
                name: "Fabrikam".into(),
                needs_sign_in: false,
                last_refresh: Some(Utc::now()),
                access_issue: None,
            },
        )
        .await
        .unwrap();
        for (id, decision) in [(TRACKED, DecisionKind::Track), (UNTRACKED, DecisionKind::Exclude)] {
            db::upsert_subscription(
                pool,
                &SubscriptionInfo {
                    id: SubscriptionId::new(id),
                    tenant_id: TenantId::new("tenant-fabrikam"),
                    name: format!("{id}-name"),
                    state: "Enabled".into(),
                    quota_id: None,
                    tags: json!({}),
                    access_issue: None,
                    last_refresh: Some(Utc::now()),
                },
            )
            .await
            .unwrap();
            db::insert_scope_decision(
                pool,
                &ScopeDecision {
                    id: format!("decision-{id}"),
                    provider: Provider::Azure,
                    tenant_id: TenantId::new("tenant-fabrikam"),
                    subscription_id: Some(SubscriptionId::new(id)),
                    decision,
                    source: DecisionSource::Explicit,
                    matching_rule_id: None,
                    reason: None,
                    effective_from: Utc::now(),
                    effective_to: None,
                },
            )
            .await
            .unwrap();
        }
        observe(pool, TRACKED, "a", json!({ "app": "Payments", "owner": "team-a", "lob": "11.3" })).await;
        // A pathological LOB tag value that is itself a resource ID (readout must redact it).
        observe(pool, TRACKED, "b", json!({ "app": "Ledger", "owner": "team-b", "lob": rid(TRACKED, "b") })).await;
        observe(pool, TRACKED, "c", json!({})).await;
        observe(pool, UNTRACKED, "x", json!({ "app": "Hidden", "owner": "team-x", "lob": "99" })).await;
        state.settings.write().await.ownership = Some(OwnershipConfig {
            application_tag: Some("app".into()),
            owner_tag: Some("owner".into()),
            line_of_business_tag: Some("lob".into()),
            lob_rollup_pattern: Some(r"^\d+".into()),
            lob_names: [("11".to_string(), "Retail".to_string())].into_iter().collect(),
            ..Default::default()
        });

        let scan = db::create_scan_run(pool, "test").await.unwrap();
        let now = Utc::now();
        let recent = now - Duration::hours(1);
        let old = now - Duration::days(9);
        db::save_policy_pack(pool, "PACK-1", "Pack", "1", None, Some("test"), true, &json!({}))
            .await
            .unwrap();
        db::record_pack_evaluation(
            pool,
            &scan,
            "PACK-1",
            "1",
            &HashSet::new(),
            &PackEvaluation {
                evaluations: vec![
                    ev(&rid(TRACKED, "a"), "SEC-1", EvalOutcome::Fail, recent, "security"),
                    ev(&rid(TRACKED, "a"), "TAG-1", EvalOutcome::Fail, recent, "hygiene"),
                    ev(&rid(TRACKED, "b"), "SEC-1", EvalOutcome::Fail, old, "security"),
                    ev(&rid(TRACKED, "c"), "SEC-2", EvalOutcome::Pass, recent, "security"),
                    ev(&rid(UNTRACKED, "x"), "OUT-1", EvalOutcome::Fail, recent, "security"),
                    ev(&rid(UNTRACKED, "x"), "SEC-1", EvalOutcome::Fail, recent, "security"),
                ],
                coverage_gaps: vec![CoverageGap {
                    pack_id: "PACK-1".into(),
                    control_id: "GAP-1".into(),
                    category: GapCategory::OutsideAzure,
                    note: "evidence lives in the CMDB".into(),
                    resource_type: None,
                    resource_count: 0,
                }],
            },
        )
        .await
        .unwrap();
        db::finish_scan_run(pool, &scan, "complete", None).await.unwrap();
        for (id, sub) in [("ex-tracked", TRACKED), ("ex-untracked", UNTRACKED)] {
            db::insert_exception(
                pool,
                &ExceptionRecord {
                    id: id.into(),
                    control_id: "SEC-1".into(),
                    resource_id: None,
                    subscription_id: Some(sub.into()),
                    resource_group: None,
                    reason: Some("accepted risk".into()),
                    approved_by: Some("ciso".into()),
                    ticket_ref: None,
                    expires_at: None,
                    created_at: Utc::now(),
                },
            )
            .await
            .unwrap();
        }
        (app, token, state)
    }

    async fn call(app: &axum::Router, token: &str, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-session-token", token)
            .header("origin", "http://127.0.0.1:8787");
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let res = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn get(app: &axum::Router, token: &str, uri: &str) -> Value {
        let (s, v) = call(app, token, "GET", uri, None).await;
        assert_eq!(s, StatusCode::OK, "{uri}: {v}");
        v
    }

    fn controls(v: &Value) -> Vec<String> {
        let mut c: Vec<String> = v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["control_id"].as_str().unwrap().to_string())
            .collect();
        c.sort();
        c.dedup();
        c
    }

    #[tokio::test]
    async fn reporting_endpoints_require_session() {
        let (app, _, _) = empty_app().await;
        for path in [
            "/api/compliance/queue",
            "/api/compliance/aging",
            "/api/compliance/flow",
            "/api/compliance/trend",
        ] {
            let req = Request::builder().uri(path).body(Body::empty()).unwrap();
            assert_eq!(
                app.clone().oneshot(req).await.unwrap().status(),
                StatusCode::UNAUTHORIZED,
                "{path}"
            );
        }
        let req = Request::builder()
            .method("POST")
            .uri("/api/evidence/export")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"format":"readout"}"#))
            .unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ac_p6_1_queue_security_lane_excludes_hygiene_and_is_the_default() {
        let (app, token, _) = seeded().await;
        let default = get(&app, &token, "/api/compliance/queue").await;
        assert_eq!(default["lane"], "security");
        assert_eq!(controls(&default), vec!["SEC-1"]);
        let row = &default["rows"][0];
        assert_eq!(row["lane"], "security");
        assert_eq!(row["count"], 2);
        assert_eq!(row["subscriptions"], 1, "untracked subscription is out of scope");
        assert_eq!(row["environment"], "prod");
        assert_eq!(row["group_key"], "");

        let sec = get(&app, &token, "/api/compliance/queue?lane=security").await;
        assert_eq!(sec["rows"], default["rows"]);
        let hyg = get(&app, &token, "/api/compliance/queue?lane=hygiene").await;
        assert_eq!(controls(&hyg), vec!["TAG-1"]);
        assert_eq!(hyg["rows"][0]["lane"], "hygiene");
        let all = get(&app, &token, "/api/compliance/queue?lane=all").await;
        assert_eq!(controls(&all), vec!["SEC-1", "TAG-1"]);

        for bad in ["/api/compliance/queue?lane=bogus", "/api/compliance/queue?group_by=bogus"] {
            let (s, _) = call(&app, &token, "GET", bad, None).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
        }
    }

    #[tokio::test]
    async fn ac_p6_1_inbox_default_view_uses_security_lane() {
        let (app, token, _) = seeded().await;
        let row_controls = |inbox: &Value, name: &str| -> Vec<String> {
            let row = inbox["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["change"]["resource_id"] == rid(TRACKED, name))
                .unwrap_or_else(|| panic!("row {name} in {inbox}"));
            row["findings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["finding"]["control_id"].as_str().unwrap().to_string())
                .collect()
        };
        let inbox = get(&app, &token, "/api/inbox").await;
        assert_eq!(inbox["filter"]["lane"], "security");
        assert_eq!(row_controls(&inbox, "a"), vec!["SEC-1"], "hygiene hidden by default");
        let inbox = get(&app, &token, "/api/inbox?lane=all").await;
        assert_eq!(inbox["filter"]["lane"], "all");
        let mut both = row_controls(&inbox, "a");
        both.sort();
        assert_eq!(both, vec!["SEC-1", "TAG-1"]);
        let inbox = get(&app, &token, "/api/inbox?lane=hygiene").await;
        assert_eq!(row_controls(&inbox, "a"), vec!["TAG-1"]);
        let (s, _) = call(&app, &token, "GET", "/api/inbox?lane=bogus", None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ac_p6_2_queue_new_since_last_visit_reads_meta_last_visit() {
        let (app, token, state) = seeded().await;
        // `a` opened 1h ago, `b` 9 days ago: a visit 2 days ago makes only `a` new.
        let visit = Utc::now() - Duration::days(2);
        db::meta_set(&state.pool, "last_visit", &visit.to_rfc3339()).await.unwrap();
        let q = get(&app, &token, "/api/compliance/queue").await;
        assert_eq!(q["rows"][0]["count"], 2);
        assert_eq!(q["rows"][0]["new_since_last_visit"], 1);
        // The queue reads the visit marker but does not move it (only the inbox does).
        let q = get(&app, &token, "/api/compliance/queue").await;
        assert_eq!(q["rows"][0]["new_since_last_visit"], 1);
        // Same count through the ownership (Rust) aggregation path.
        let q = get(&app, &token, "/api/compliance/queue?group_by=owner").await;
        let total: u64 = q["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["new_since_last_visit"].as_u64().unwrap())
            .sum();
        assert_eq!(total, 1);
    }

    #[tokio::test]
    async fn queue_group_by_uses_derived_ownership_and_subscription_names() {
        let (app, token, _) = seeded().await;
        let keys = |v: &Value| -> Vec<(String, u64)> {
            let mut k: Vec<(String, u64)> = v["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| (r["group_key"].as_str().unwrap().to_string(), r["count"].as_u64().unwrap()))
                .collect();
            k.sort();
            k
        };
        let by_app = get(&app, &token, "/api/compliance/queue?group_by=application").await;
        assert_eq!(by_app["group_by"], "application");
        assert_eq!(keys(&by_app), vec![("Ledger".into(), 1), ("Payments".into(), 1)]);
        let by_owner = get(&app, &token, "/api/compliance/queue?group_by=owner").await;
        assert_eq!(keys(&by_owner), vec![("team-a".into(), 1), ("team-b".into(), 1)]);
        let by_lob = get(&app, &token, "/api/compliance/queue?group_by=line_of_business").await;
        assert!(keys(&by_lob).contains(&("Retail".into(), 1)), "{by_lob}");
        let by_sub = get(&app, &token, "/api/compliance/queue?group_by=subscription").await;
        assert_eq!(keys(&by_sub), vec![(format!("{TRACKED}-name"), 2)]);
    }

    #[tokio::test]
    async fn ac_p6_3_and_4_aging_and_flow_endpoints() {
        let (app, token, _) = seeded().await;
        let aging = get(&app, &token, "/api/compliance/aging").await;
        assert_eq!(aging["buckets"], json!(["0-7", "8-30", "31-90", "90+"]));
        let got: Vec<(String, String, u64)> = aging["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["control_id"].as_str().unwrap().into(),
                    r["bucket"].as_str().unwrap().into(),
                    r["count"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![("SEC-1".into(), "0-7".into(), 1), ("SEC-1".into(), "8-30".into(), 1)]
        );
        let aging_hyg = get(&app, &token, "/api/compliance/aging?lane=hygiene").await;
        assert_eq!(controls(&aging_hyg), vec!["TAG-1"]);

        let flow = get(&app, &token, "/api/compliance/flow?days=90").await;
        assert_eq!(flow["days"], 90);
        let opened: u64 = flow["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["opened"].as_u64().unwrap())
            .sum();
        assert_eq!(opened, 2, "two security fails opened in the window: {flow}");
        // A 1-day window drops the fail opened 9 days ago.
        let flow = get(&app, &token, "/api/compliance/flow?days=1").await;
        let opened: u64 = flow["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["opened"].as_u64().unwrap())
            .sum();
        assert!(opened <= 1, "{flow}");

        let trend = get(&app, &token, "/api/compliance/trend").await;
        assert_eq!(trend["scans"].as_array().unwrap().len(), 1);
        assert_eq!(trend["rows"][0]["control_id"], "SEC-1");
        assert_eq!(trend["rows"][0]["open"], 2);
    }

    #[tokio::test]
    async fn ac_p6_5_readout_export_has_aggregates_and_no_resource_ids() {
        let (app, token, _) = seeded().await;
        let (s, out) = call(
            &app,
            &token,
            "POST",
            "/api/evidence/export",
            Some(json!({ "format": "readout" })),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.to_lowercase().contains("/subscriptions/"), "{text}");
        assert!(!text.contains(TRACKED) && !text.contains(UNTRACKED), "no subscription IDs: {text}");
        assert_eq!(out["format"], "readout");
        assert_eq!(out["scope_empty"], false);
        assert_eq!(out["scope_size"], 1);
        assert_eq!(out["open_findings"], 3);
        assert_eq!(out["by_lane"], json!({ "open": 3, "security": 2, "hygiene": 1 }));
        assert_eq!(out["by_control"][0], json!({ "control_id": "SEC-1", "lane": "security", "open": 2 }));
        assert_eq!(out["by_environment"][0]["environment"], "prod");
        assert_eq!(out["by_environment"][0]["open"], 3);
        let lobs: Vec<&str> = out["by_line_of_business"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["line_of_business"].as_str().unwrap())
            .collect();
        assert!(lobs.contains(&"Retail"), "{lobs:?}");
        assert!(lobs.contains(&"[redacted]"), "a resource-ID-like tag value is redacted: {lobs:?}");
        assert_eq!(out["trend"].as_array().unwrap().len(), 1);
        assert_eq!(out["trend"][0]["open"], 3);
        assert_eq!(
            out["coverage_gap_categories"],
            json!([{ "category": "outside_azure", "controls": 1, "resources": 0 }])
        );
        assert_eq!(out["exceptions"], 1, "only the tracked subscription's exception");
        assert!(!out["freshness"]["last_scan_at"].is_null());
        assert!(out.get("findings").is_none() && out.get("resource").is_none());
    }

    #[tokio::test]
    async fn readout_with_empty_scope_returns_zero_counts_and_scope_empty() {
        let (app, token, state) = empty_app().await;
        // Findings exist, but no subscription is tracked.
        db::record_pack_evaluation(
            &state.pool,
            "scan-1",
            "PACK-1",
            "1",
            &HashSet::new(),
            &PackEvaluation {
                evaluations: vec![ev(&rid(UNTRACKED, "x"), "SEC-1", EvalOutcome::Fail, Utc::now(), "security")],
                coverage_gaps: vec![],
            },
        )
        .await
        .unwrap();
        let (s, out) = call(
            &app,
            &token,
            "POST",
            "/api/evidence/export",
            Some(json!({ "format": "readout" })),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(out["scope_empty"], true);
        assert_eq!(out["scope_size"], 0);
        assert_eq!(out["open_findings"], 0);
        assert_eq!(out["by_lane"]["open"], 0);
        assert_eq!(out["exceptions"], 0);
        for k in ["by_control", "by_environment", "by_line_of_business", "trend", "coverage_gap_categories"] {
            assert!(out[k].as_array().unwrap().is_empty(), "{k}: {out}");
        }
        for uri in [
            "/api/compliance/queue?lane=all",
            "/api/compliance/aging?lane=all",
            "/api/compliance/flow?lane=all",
            "/api/compliance/trend?lane=all",
        ] {
            assert!(get(&app, &token, uri).await["rows"].as_array().unwrap().is_empty(), "{uri}");
        }
    }

    #[tokio::test]
    async fn ac_p6_6_every_reporting_endpoint_excludes_untracked_subscriptions() {
        let (app, token, _) = seeded().await;
        let mut uris: Vec<String> = Vec::new();
        for lane in ["security", "hygiene", "all"] {
            for g in ["", "application", "owner", "subscription", "line_of_business"] {
                uris.push(format!("/api/compliance/queue?lane={lane}&group_by={g}"));
            }
            uris.push(format!("/api/compliance/aging?lane={lane}"));
            uris.push(format!("/api/compliance/flow?lane={lane}&days=90"));
            uris.push(format!("/api/compliance/trend?lane={lane}"));
        }
        for uri in &uris {
            let v = get(&app, &token, uri).await;
            let text = v.to_string();
            assert!(!text.contains("OUT-1"), "{uri}: {text}");
            assert!(!text.contains("Hidden") && !text.contains("team-x"), "{uri}: {text}");
            assert!(!text.contains(UNTRACKED), "{uri}: {text}");
        }
        // SEC-1 also fails in the untracked subscription; only the tracked fails are counted.
        let all = get(&app, &token, "/api/compliance/queue?lane=all").await;
        let sec = all["rows"].as_array().unwrap().iter().find(|r| r["control_id"] == "SEC-1").unwrap();
        assert_eq!(sec["count"], 2);
        let trend = get(&app, &token, "/api/compliance/trend").await;
        assert_eq!(trend["rows"][0]["open"], 2);

        let (_, readout) = call(
            &app,
            &token,
            "POST",
            "/api/evidence/export",
            Some(json!({ "format": "readout" })),
        )
        .await;
        let text = readout.to_string();
        assert!(!text.contains("OUT-1") && !text.contains("\"99\""), "{text}");
    }
}
