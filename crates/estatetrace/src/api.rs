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
        .route("/compliance", get(compliance_summary))
        .route("/exceptions", get(list_exceptions_api).post(create_exception))
        .route("/dispositions", get(list_dispositions_api).post(create_disposition))
        .route("/classification/rules", get(list_class_rules).post(save_class_rule))
        .route("/packs", get(list_packs).post(import_pack))
        .route("/packs/pilot", post(load_pilot))
        .route("/packs/validate", post(validate_pack))
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
    let rules = db::list_classification_rules(&state.pool)
        .await
        .unwrap_or_default();
    let rows: Vec<Value> = resources
        .iter()
        .map(|r| {
            let class = classify_resource(r, &rules);
            json!({
                "resource": r,
                "classification": class,
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
    let evals = db::list_evaluations(&state.pool, 500)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let evals: Vec<_> = evals
        .into_iter()
        .filter(|e| e.resource_id.as_str() == decoded)
        .collect();
    let tickets = db::list_ticket_relationships(&state.pool, &decoded)
        .await
        .unwrap_or_default();
    let coverage = db::list_coverage(&state.pool)
        .await
        .unwrap_or_default();
    let now = Utc::now();
    let triage = triage_with_history(&evals, now);
    let exceptions = db::list_exceptions(&state.pool, Some(&decoded))
        .await
        .unwrap_or_default();
    let mut dispositions = Vec::new();
    for e in &evals {
        if let Ok(Some(d)) = db::latest_disposition_for_evaluation(&state.pool, &e.id).await {
            dispositions.push(d);
        }
    }
    Ok(Json(json!({
        "resource": obs,
        "changes": changes,
        "evaluations": evals,
        "triage": triage,
        "exceptions": exceptions,
        "dispositions": dispositions,
        "tickets": tickets,
        "coverage": coverage,
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
}

async fn inbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<InboxQuery>,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let tracked = db::tracked_subscription_ids(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let changes = db::list_recent_changes(&state.pool, 500)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rules = db::list_classification_rules(&state.pool)
        .await
        .unwrap_or_default();
    let evals = db::list_evaluations(&state.pool, 1000)
        .await
        .unwrap_or_default();

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
        if !tracked.iter().any(|t| t == ch.subscription_id.as_str()) {
            continue;
        }
        if let Some(ref sid) = q.subscription_id {
            if ch.subscription_id.as_str() != sid {
                continue;
            }
        }
        let obs = db::latest_observation(&state.pool, ch.resource_id.as_str())
            .await
            .ok()
            .flatten();
        let class = obs
            .as_ref()
            .map(|o| classify_resource(o, &rules))
            .unwrap_or(ClassificationResult {
                environment: EnvironmentClass::Unknown,
                winning_rule_id: None,
                conflicting: false,
                missing_tag: true,
                reason: "no observation".into(),
            });
        if let Some(ref env) = q.environment {
            if class.environment.as_str() != env {
                continue;
            }
        }
        let resource_evals: Vec<_> = evals
            .iter()
            .filter(|e| e.resource_id == ch.resource_id)
            .cloned()
            .collect();
        let related_eval = resource_evals.first().cloned();
        if let Some(ref sev) = q.severity {
            if related_eval
                .as_ref()
                .map(|e| e.severity.as_str() != sev)
                .unwrap_or(true)
            {
                continue;
            }
        }
        let triage = triage_with_history(&resource_evals, now);
        let disposition = if let Some(ref ev) = related_eval {
            db::latest_disposition_for_evaluation(&state.pool, &ev.id)
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let since_last_visit = last_visit_dt
            .map(|lv| ch.times.observation_time > lv)
            .unwrap_or(true);
        rows.push(json!({
            "change": ch,
            "classification": class,
            "evaluation": related_eval,
            "triage": triage,
            "disposition": disposition,
            "resource": obs,
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
                "verified_corrected" => 3,
                _ => 4,
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

    let _ = db::meta_set(&state.pool, "last_visit", &now.to_rfc3339()).await;

    Ok(Json(json!({
        "rows": rows,
        "last_visit": last_visit,
        "filter": q,
    })))
}

async fn compliance_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let evals = db::list_evaluations(&state.pool, 5000)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut pass = 0;
    let mut fail = 0;
    let mut unknown = 0;
    let mut inapplicable = 0;
    for e in &evals {
        match e.outcome {
            EvalOutcome::Pass => pass += 1,
            EvalOutcome::Fail => fail += 1,
            EvalOutcome::Unknown => unknown += 1,
            EvalOutcome::Inapplicable => inapplicable += 1,
        }
    }
    let now = Utc::now();
    let mut actionable = 0;
    let mut awaiting_grace = 0;
    let mut verified = 0;
    // Group by resource+control for triage history
    let mut by_key: std::collections::HashMap<(String, String), Vec<Evaluation>> =
        std::collections::HashMap::new();
    for e in &evals {
        by_key
            .entry((e.resource_id.as_str().to_string(), e.control_id.clone()))
            .or_default()
            .push(e.clone());
    }
    for (_k, hist) in &by_key {
        if let Some(info) = triage_with_history(hist, now) {
            match info.state {
                TriageState::Actionable => actionable += 1,
                TriageState::AwaitingGrace => awaiting_grace += 1,
                TriageState::VerifiedCorrected => verified += 1,
                _ => {}
            }
        }
    }
    let exceptions = db::count_active_exceptions(&state.pool)
        .await
        .unwrap_or(0);

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
        "pending_remediation": actionable,
        "awaiting_grace": awaiting_grace,
        "verified_corrected": verified,
        "freshness": now,
        "scope": db::tracked_subscription_ids(&state.pool).await.unwrap_or_default(),
        "coverage_gaps": coverage_gaps,
        "controls_evaluated": controls_evaluated,
        "controls_total": controls_total,
    })))
}

#[derive(Deserialize)]
struct ExceptionCreate {
    resource_id: String,
    control_id: String,
    reason: Option<String>,
    approved_by: Option<String>,
    expires_at: Option<String>,
}

async fn create_exception(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ExceptionCreate>,
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    let expires_at = body
        .expires_at
        .as_ref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc));
    let ex = ExceptionRecord {
        id: Uuid::new_v4().to_string(),
        resource_id: body.resource_id,
        control_id: body.control_id,
        reason: body.reason,
        approved_by: body.approved_by,
        expires_at,
        created_at: Utc::now(),
    };
    db::insert_exception(&state.pool, &ex)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "exception": ex })))
}

#[derive(Deserialize)]
struct ExceptionListQuery {
    resource_id: Option<String>,
}

async fn list_exceptions_api(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ExceptionListQuery>,
) -> Result<Json<Value>, StatusCode> {
    require_session(&state, &headers)?;
    let rows = db::list_exceptions(&state.pool, q.resource_id.as_deref())
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
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    db::upsert_classification_rule(&state.pool, &rule)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "ok": true })))
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
    Ok(Json(json!({
        "id": pack.id,
        "revision": pack.revision,
        "coverage": coverage_report(&pack),
        "examples": run_example_cases(&pack, builtin_resource_kinds()).unwrap_or_default(),
    })))
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
) -> Result<Json<Value>, StatusCode> {
    require_mutation(&state, &headers)?;
    *state.settings.write().await = settings;
    save_settings(&state)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    let evals = db::list_evaluations(&state.pool, 2000)
        .await
        .unwrap_or_default();
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
        let related = evals.iter().find(|e| e.resource_id == r.resource_id);
        if let Some(ref sev) = req.severity {
            if related.map(|e| e.severity.as_str() != sev).unwrap_or(true) {
                continue;
            }
        }
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
            "compliance": related.map(|e| e.outcome.as_str()),
            "severity": related.map(|e| e.severity.as_str()),
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
    let evals = db::list_evaluations(&state.pool, 100)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.resource_id.as_str() == resource_id)
        .collect::<Vec<_>>();
    let tickets = db::list_ticket_relationships(&state.pool, resource_id)
        .await
        .unwrap_or_default();
    let payload = json!({
        "resource": obs,
        "changes": changes,
        "evaluations": evals,
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