//! AC-01 DB-backed: persist exclusion rule, rename, new match, explicit override.

use chrono::Utc;
use estatetrace_core::*;
use estatetrace_db as db;
use serde_json::json;

#[tokio::test]
async fn ac01_persist_exclude_rename_new_match_and_override() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("test.db")).await.unwrap();

    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/multi_tenant_subscriptions.json"))
            .unwrap();

    for t in fixture["tenants"].as_array().unwrap() {
        db::upsert_tenant(
            &pool,
            &TenantInfo {
                id: TenantId::new(t["id"].as_str().unwrap()),
                name: t["name"].as_str().unwrap().into(),
                needs_sign_in: false,
                last_refresh: Some(Utc::now()),
                access_issue: None,
            },
        )
        .await
        .unwrap();
    }
    for s in fixture["subscriptions"].as_array().unwrap() {
        db::upsert_subscription(
            &pool,
            &SubscriptionInfo {
                id: SubscriptionId::new(s["id"].as_str().unwrap()),
                tenant_id: TenantId::new(s["tenant_id"].as_str().unwrap()),
                name: s["name"].as_str().unwrap().into(),
                state: s["state"].as_str().unwrap().into(),
                quota_id: s.get("quota_id").and_then(|v| v.as_str()).map(|s| s.into()),
                tags: s.get("tags").cloned().unwrap_or(json!({})),
                access_issue: None,
                last_refresh: Some(Utc::now()),
                metadata_read: true,
            },
        )
        .await
        .unwrap();
    }

    let rule = ExclusionRule {
        id: "msdn".into(),
        name: "MSDN".into(),
        tenant_id: None,
        filter: ExclusionFilter {
            name_contains: Some("MSDN".into()),
            tag_key: None,
            tag_value: None,
            quota_id: None,
            offer_mapping: Some("MSDN".into()),
        },
        enabled: true,
        created_at: Utc::now(),
    };
    db::upsert_exclusion_rule(&pool, &rule).await.unwrap();

    // Explicit override keeps one MSDN sub tracked.
    db::insert_scope_decision(
        &pool,
        &ScopeDecision {
            id: "keep-msdn-1".into(),
            provider: Provider::Azure,
            tenant_id: TenantId::new("tenant-a"),
            subscription_id: Some(SubscriptionId::new("sub-msdn-1")),
            decision: DecisionKind::Track,
            source: DecisionSource::Explicit,
            matching_rule_id: None,
            reason: Some("override".into()),
            effective_from: Utc::now(),
            effective_to: None,
        },
    )
    .await
    .unwrap();

    let scope = db::resolve_effective_scope(&pool).await.unwrap();
    let msdn1 = scope
        .iter()
        .find(|r| r.subscription.id.as_str() == "sub-msdn-1")
        .unwrap();
    assert_eq!(msdn1.decision, DecisionKind::Track);

    let msdn2 = scope
        .iter()
        .find(|r| r.subscription.id.as_str() == "sub-msdn-2")
        .unwrap();
    assert_eq!(msdn2.decision, DecisionKind::Exclude);

    // Rename excluded subscription — still excluded via saved rule.
    db::upsert_subscription(
        &pool,
        &SubscriptionInfo {
            id: SubscriptionId::new("sub-msdn-2"),
            tenant_id: TenantId::new("tenant-a"),
            name: "MSDN Renamed Workstation".into(),
            state: "Enabled".into(),
            quota_id: Some("MSDN_2014-09-01".into()),
            tags: json!({}),
            access_issue: None,
            last_refresh: Some(Utc::now()),
            metadata_read: true,
        },
    )
    .await
    .unwrap();

    // New matching subscription awaits exclusion via rule.
    db::upsert_subscription(
        &pool,
        &SubscriptionInfo {
            id: SubscriptionId::new("sub-msdn-new"),
            tenant_id: TenantId::new("tenant-a"),
            name: "MSDN Extra".into(),
            state: "Enabled".into(),
            quota_id: Some("MSDN_2014-09-01".into()),
            tags: json!({}),
            access_issue: None,
            last_refresh: Some(Utc::now()),
            metadata_read: true,
        },
    )
    .await
    .unwrap();

    let scope2 = db::resolve_effective_scope(&pool).await.unwrap();
    let renamed = scope2
        .iter()
        .find(|r| r.subscription.id.as_str() == "sub-msdn-2")
        .unwrap();
    assert_eq!(renamed.decision, DecisionKind::Exclude);

    let neu = scope2
        .iter()
        .find(|r| r.subscription.id.as_str() == "sub-msdn-new")
        .unwrap();
    assert_eq!(neu.decision, DecisionKind::Exclude);

    let still = scope2
        .iter()
        .find(|r| r.subscription.id.as_str() == "sub-msdn-1")
        .unwrap();
    assert_eq!(still.decision, DecisionKind::Track);
}
