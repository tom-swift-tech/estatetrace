use crate::state::AppState;
use anyhow::Result;
use estatetrace_azure::{diff_observations, Collector};
use estatetrace_core::{
    classify, ChangeLabel, ClassifyInput, DecisionKind, ResourceId, ResourceObservation,
    SubscriptionId,
};
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
    // Subscriptions whose inventory completed in a pass that started from the beginning.
    // Only these may close finding intervals by absence (spec invariant 8, AC-P3-4/5).
    let mut complete_subscriptions: HashSet<SubscriptionId> = HashSet::new();

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
            Ok(pass) => {
                if pass.complete_from_beginning {
                    complete_subscriptions.insert(sub.id.clone());
                }
                all_obs.extend(pass.resources);
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

    // A failed pack write rolls back that pack only; the scan is then partial (spec §7).
    let eval_error = match evaluate_active_packs(state, &scan_id, &all_obs, &complete_subscriptions)
        .await
    {
        Ok(()) => None,
        Err(e) => {
            warn!("evaluation failed: {e}");
            Some(format!("evaluation failed: {e}"))
        }
    };

    db::finish_scan_run(
        &state.pool,
        &scan_id,
        if any_error || eval_error.is_some() { "partial" } else { "complete" },
        eval_error.as_deref(),
    )
    .await?;
    info!("scan {scan_id} finished");
    Ok(())
}

/// Result of one subscription's inventory pass.
struct SubscriptionPass {
    resources: Vec<ResourceObservation>,
    /// The page sequence completed and started from the beginning (no resume checkpoint),
    /// so absence from `resources` means absence from the subscription.
    complete_from_beginning: bool,
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
) -> Result<SubscriptionPass> {
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
            // P5.1 drop guard: a complete pass that suddenly returns far fewer resources (lost
            // access, throttled partial answer, wrong context) must not infer deletions.
            let guards = state.settings.read().await.scan_guards.clone();
            let missing = previous
                .iter()
                .filter(|p| !seen.contains(&p.resource_id))
                .count();
            let drop = guards.check_drop(previous.len(), missing);
            let infer_deletions = started_from_beginning && drop.deletions_allowed;
            let note = if started_from_beginning && !drop.deletions_allowed {
                let n = guards.note(previous.len(), seen.len(), &drop);
                warn!("{subscription_id}: {n}");
                Some(n)
            } else {
                None
            };

            // Full inventory page sequence finished — clear checkpoint.
            db::upsert_coverage(
                &state.pool,
                "azure_resource_graph",
                subscription_id,
                None,
                true,
                note.as_deref(),
            )
            .await?;

            // Never mark_missing unless this pass covered the estate from the start
            // and passed the drop guard.
            if infer_deletions {
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

            let mut changes = if infer_deletions {
                diff_observations(previous, &all_new, scan_id)
            } else {
                // Resumed tail, or a guarded drop: emit create/update for seen resources,
                // never missing.
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

            return Ok(SubscriptionPass {
                resources: all_new,
                // A guarded drop must not close finding intervals by absence either.
                complete_from_beginning: infer_deletions,
            });
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

    Ok(SubscriptionPass {
        resources: all_new,
        complete_from_beginning: false,
    })
}

/// Evaluate every active pack (spec §3.1 `evaluate_pack`): kind-targeted controls, environment
/// applicability from the classification rules, and coverage gaps for controls that cannot be
/// judged per resource. Results are recorded as finding intervals, one transaction per pack
/// (spec §3.3 `record_pack_evaluation`). Every pack is attempted; the error lists the packs
/// whose write failed and rolled back.
async fn evaluate_active_packs(
    state: &AppState,
    scan_id: &str,
    resources: &[ResourceObservation],
    complete_subscriptions: &HashSet<SubscriptionId>,
) -> Result<()> {
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
    // Joins use only resources still present: a VNet marked missing must not supply subnets.
    let joins = JoinIndex::build(&db::list_present_resources(&state.pool).await?);
    let mut failures: Vec<String> = Vec::new();
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
        let pack_id = if pack_id.is_empty() { pack.id.clone() } else { pack_id };
        match db::record_pack_evaluation(
            &state.pool,
            scan_id,
            &pack_id,
            &revision,
            complete_subscriptions,
            &result,
        )
        .await
        {
            Ok(stats) => info!(
                "pack {pack_id} rev {revision}: {} opened, {} continued, {} closed",
                stats.opened, stats.continued, stats.closed
            ),
            Err(e) => failures.push(format!("pack {pack_id}: {e}")),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(failures.join("; "))
    }
}
