use crate::state::AppState;
use anyhow::Result;
use estatetrace_azure::{run_full_scan_for_subscription, Collector};
use estatetrace_core::{DecisionKind, ResourceObservation};
use estatetrace_db as db;
use estatetrace_policy::{evaluate_pack_on_resources, parse_pack_json, PolicyPack};
use tracing::{info, warn};

pub async fn run_scan(state: &AppState) -> Result<()> {
    let _guard = state.scan_lock.lock().await;
    let scan_id = db::create_scan_run(&state.pool, "azure_resource_graph").await?;
    info!("starting scan {scan_id}");

    let scope = db::resolve_effective_scope(&state.pool).await?;
    let tracked: Vec<_> = scope
        .into_iter()
        .filter(|r| r.decision == DecisionKind::Track)
        .collect();

    if tracked.is_empty() {
        db::finish_scan_run(
            &state.pool,
            &scan_id,
            "empty_scope",
            Some("no tracked subscriptions"),
        )
        .await?;
        return Ok(());
    }

    let collector = Collector::new();
    let mut any_error = false;
    let mut all_obs: Vec<ResourceObservation> = Vec::new();

    for row in &tracked {
        let sub = &row.subscription;
        let previous: Vec<ResourceObservation> = db::list_latest_resources(&state.pool)
            .await?
            .into_iter()
            .filter(|o| o.subscription_id == sub.id)
            .collect();

        let checkpoint = db::get_checkpoint(
            &state.pool,
            "azure_resource_graph",
            sub.id.as_str(),
        )
        .await?;

        match run_full_scan_for_subscription(
            &collector,
            sub.tenant_id.as_str(),
            sub.id.as_str(),
            &scan_id,
            &previous,
            None, // always full pass for MVP correctness; checkpoint retained for resume metadata
        )
        .await
        {
            Ok((resources, changes, last_cp, complete)) => {
                for obs in &resources {
                    db::insert_observation(&state.pool, obs).await?;
                }
                for ch in &changes {
                    let _ = db::insert_change_event(&state.pool, ch).await?;
                }
                // Mark missing
                for prev in &previous {
                    if !resources.iter().any(|r| r.resource_id == prev.resource_id) {
                        db::mark_missing(
                            &state.pool,
                            prev.resource_id.as_str(),
                            chrono::Utc::now(),
                        )
                        .await?;
                    }
                }
                if complete {
                    db::upsert_coverage(
                        &state.pool,
                        "azure_resource_graph",
                        sub.id.as_str(),
                        last_cp.as_deref().or(checkpoint.as_deref()),
                        true,
                        None,
                    )
                    .await?;
                } else {
                    db::upsert_coverage(
                        &state.pool,
                        "azure_resource_graph",
                        sub.id.as_str(),
                        last_cp.as_deref(),
                        false,
                        Some("incomplete page batch"),
                    )
                    .await?;
                    any_error = true;
                }
                all_obs.extend(resources);
            }
            Err(e) => {
                warn!("scan failed for {}: {e}", sub.id);
                db::upsert_coverage(
                    &state.pool,
                    "azure_resource_graph",
                    sub.id.as_str(),
                    None,
                    false,
                    Some(&e.to_string()),
                )
                .await?;
                any_error = true;
            }
        }
    }

    // Evaluate active packs
    if let Err(e) = evaluate_active_packs(state, &all_obs).await {
        warn!("evaluation failed: {e}");
    }

    db::finish_scan_run(
        &state.pool,
        &scan_id,
        if any_error { "partial" } else { "complete" },
        None,
    )
    .await?;
    info!("scan {scan_id} finished");
    Ok(())
}

async fn evaluate_active_packs(state: &AppState, resources: &[ResourceObservation]) -> Result<()> {
    let packs = db::active_policy_packs(&state.pool).await?;
    for p in packs {
        let content = p.get("content").cloned().unwrap_or_default();
        let revision = p
            .get("revision")
            .and_then(|v| v.as_str())
            .unwrap_or("1")
            .to_string();
        let pack: PolicyPack = if content.is_object() {
            serde_json::from_value(content)?
        } else {
            parse_pack_json(&content.to_string())?
        };
        let evals = evaluate_pack_on_resources(&pack.controls, &revision, resources);
        for ev in evals {
            db::insert_evaluation(&state.pool, &ev).await?;
        }
    }
    Ok(())
}