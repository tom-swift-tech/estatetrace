use crate::state::AppState;
use anyhow::Result;
use estatetrace_azure::{diff_observations, Collector};
use estatetrace_core::{classify, ChangeLabel, ClassifyInput, DecisionKind, ResourceId, ResourceObservation};
use estatetrace_db as db;
use estatetrace_policy::{
    builtin_resource_kinds, evaluate_pack, parse_pack_json, JoinIndex, PolicyPack,
};
use std::collections::HashSet;
use tracing::{info, warn};

pub async fn run_scan(state: &AppState) -> Result<()> {
    run_scan_for(state, None).await
}

pub async fn run_scan_for(state: &AppState, subscription_ids: Option<&[String]>) -> Result<()> {
    let _guard = state.scan_lock.lock().await;
    let scan_id = db::create_scan_run(&state.pool, "azure_resource_graph").await?;
    info!("starting scan {scan_id}");

    let scope = db::resolve_effective_scope(&state.pool).await?;
    let tracked: Vec<_> = scope
        .into_iter()
        .filter(|r| r.decision == DecisionKind::Track)
        .filter(|r| {
            subscription_ids
                .map(|ids| ids.iter().any(|id| id == r.subscription.id.as_str()))
                .unwrap_or(true)
        })
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

        let start_checkpoint = db::get_checkpoint(
            &state.pool,
            "azure_resource_graph",
            sub.id.as_str(),
        )
        .await?;
        let started_from_beginning = start_checkpoint.is_none();

        match scan_subscription_paged(
            state,
            &collector,
            sub.tenant_id.as_str(),
            sub.id.as_str(),
            &scan_id,
            &previous,
            start_checkpoint,
            started_from_beginning,
        )
        .await
        {
            Ok(resources) => {
                all_obs.extend(resources);
                // P4: refresh resource-group tags (environment fallback + ownership).
                // Best effort: a failure here never fails the inventory pass.
                match collector.collect_resource_group_tags(sub.id.as_str()).await {
                    Ok(rg_tags) => {
                        if let Err(e) = db::upsert_resource_group_tags(&state.pool, &rg_tags).await {
                            warn!("resource group tag upsert failed for {}: {e}", sub.id);
                        }
                    }
                    Err(e) => warn!("resource group tag query failed for {}: {e}", sub.id),
                }
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

/// Page Resource Graph, commit each batch, resume from checkpoint.
/// `mark_missing` only when the inventory completes AND the pass started from the beginning.
async fn scan_subscription_paged(
    state: &AppState,
    collector: &Collector,
    tenant_id: &str,
    subscription_id: &str,
    scan_id: &str,
    previous: &[ResourceObservation],
    start_checkpoint: Option<String>,
    started_from_beginning: bool,
) -> Result<Vec<ResourceObservation>> {
    let mut checkpoint = start_checkpoint;
    let mut seen: HashSet<ResourceId> = HashSet::new();
    let mut all_new: Vec<ResourceObservation> = Vec::new();

    loop {
        let batch = collector
            .collect_subscription_inventory(
                tenant_id,
                subscription_id,
                scan_id,
                checkpoint.as_deref(),
            )
            .await?;

        for obs in &batch.resources {
            db::insert_observation(&state.pool, obs).await?;
            seen.insert(obs.resource_id.clone());
        }
        all_new.extend(batch.resources);

        if batch.complete {
            // Full inventory page sequence finished — clear checkpoint.
            db::upsert_coverage(
                &state.pool,
                "azure_resource_graph",
                subscription_id,
                None,
                true,
                None,
            )
            .await?;

            // Never mark_missing unless this pass covered the estate from the start.
            if started_from_beginning {
                for prev in previous {
                    if !seen.contains(&prev.resource_id) {
                        db::mark_missing(
                            &state.pool,
                            prev.resource_id.as_str(),
                            chrono::Utc::now(),
                        )
                        .await?;
                    }
                }
            }

            let mut changes = if started_from_beginning {
                diff_observations(previous, &all_new, scan_id)
            } else {
                // Resumed tail only: emit create/update for seen resources, never missing.
                let prev_seen: Vec<_> = previous
                    .iter()
                    .filter(|p| seen.contains(&p.resource_id))
                    .cloned()
                    .collect();
                diff_observations(&prev_seen, &all_new, scan_id)
                    .into_iter()
                    .filter(|e| e.label != ChangeLabel::MissingFromScan)
                    .collect()
            };

            let provider_changes = collector.collect_changes(subscription_id, None).await?;
            changes.extend(provider_changes);
            for ch in &changes {
                let _ = db::insert_change_event(&state.pool, ch).await?;
            }

            return Ok(all_new);
        }

        // Incomplete page — persist checkpoint after batch commit; do not mark_missing.
        checkpoint = batch.checkpoint.clone();
        db::upsert_coverage(
            &state.pool,
            "azure_resource_graph",
            subscription_id,
            checkpoint.as_deref(),
            false,
            Some("incomplete page batch"),
        )
        .await?;

        if checkpoint.is_none() {
            // Defensive: no skip token but incomplete flag — stop without mark_missing.
            break;
        }
    }

    Ok(all_new)
}

/// Evaluate every active pack (spec §3.1 `evaluate_pack`): kind-targeted controls, environment
/// applicability from the classification rules, and coverage gaps for controls that cannot be
/// judged per resource. Until the findings store lands (P3) results still go to `evaluations`.
async fn evaluate_active_packs(state: &AppState, resources: &[ResourceObservation]) -> Result<()> {
    let packs = db::active_policy_packs(&state.pool).await?;
    let rules = db::list_classification_rules(&state.pool).await?;
    // Full classification (subscription-name and resource-group-tag rules), not the
    // resource-only wrapper, so evaluation environments match what the inbox shows.
    let sub_names: std::collections::HashMap<String, String> = db::list_subscriptions(&state.pool)
        .await?
        .into_iter()
        .map(|s| (s.id.as_str().to_ascii_lowercase(), s.name))
        .collect();
    let rg_tags: std::collections::HashMap<(String, String), serde_json::Value> =
        db::get_resource_group_tags(&state.pool, None)
            .await?
            .into_iter()
            .map(|r| {
                (
                    (
                        r.subscription_id.as_str().to_ascii_lowercase(),
                        r.resource_group.to_ascii_lowercase(),
                    ),
                    r.tags,
                )
            })
            .collect();
    let env_of = |obs: &ResourceObservation| {
        let sub = obs.subscription_id.as_str().to_ascii_lowercase();
        let rg = obs.resource_group.as_deref().map(|g| g.to_ascii_lowercase());
        let input = ClassifyInput {
            obs,
            subscription_name: sub_names.get(&sub).map(String::as_str),
            rg_tags: rg.and_then(|g| rg_tags.get(&(sub.clone(), g))),
        };
        classify(&input, &rules).environment
    };
    let kinds = builtin_resource_kinds();
    let joins = JoinIndex::build(&db::list_latest_resources(&state.pool).await?);
    // Every observation in one run carries the run's scan id.
    let scan_id = resources
        .first()
        .map(|o| o.scan_id.clone())
        .unwrap_or_default();
    for p in packs {
        let content = p.get("content").cloned().unwrap_or_default();
        let pack_id = p
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let revision = p
            .get("revision")
            .and_then(|v| v.as_str())
            .unwrap_or("1")
            .to_string();
        let mut pack: PolicyPack = if content.is_object() {
            serde_json::from_value(content)?
        } else {
            parse_pack_json(&content.to_string())?
        };
        // The stored row's revision is authoritative for AC-03.
        pack.revision = revision.clone();
        let result = evaluate_pack(&pack, resources, &env_of, kinds, &joins);
        for ev in &result.evaluations {
            db::insert_evaluation(&state.pool, ev).await?;
        }
        let pack_id = if pack_id.is_empty() { pack.id.clone() } else { pack_id };
        db::replace_coverage_gaps(&state.pool, &pack_id, &revision, &scan_id, &result.coverage_gaps)
            .await?;
    }
    Ok(())
}
