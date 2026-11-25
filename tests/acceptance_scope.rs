//! AC-01 style fixture exercise for scope resolution.

use chrono::Utc;
use estatetrace_core::*;
use serde_json::json;

#[test]
fn bulk_exclude_rename_and_new_match() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/multi_tenant_subscriptions.json")).unwrap();
    let mut subs = Vec::new();
    for s in fixture["subscriptions"].as_array().unwrap() {
        subs.push(SubscriptionInfo {
            id: SubscriptionId::new(s["id"].as_str().unwrap()),
            tenant_id: TenantId::new(s["tenant_id"].as_str().unwrap()),
            name: s["name"].as_str().unwrap().into(),
            state: s["state"].as_str().unwrap().into(),
            quota_id: s.get("quota_id").and_then(|v| v.as_str()).map(|s| s.into()),
            tags: s.get("tags").cloned().unwrap_or(json!({})),
            access_issue: None,
            last_refresh: None,
            metadata_read: true,
        });
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

    let matched: Vec<_> = subs
        .iter()
        .filter(|s| rule.filter.matches(s))
        .map(|s| s.id.as_str().to_string())
        .collect();
    assert!(matched.contains(&"sub-msdn-1".to_string()));
    assert!(matched.contains(&"sub-msdn-2".to_string()));
    assert!(!matched.contains(&"sub-prod-1".to_string()));

    // Rename manually excluded subscription — still matches name contains MSDN after rename
    // For rename that removes MSDN from name, quota-based rules would be used; here keep MSDN in name.
    let mut renamed = subs[1].clone();
    renamed.name = "MSDN Renamed Workstation".into();
    let (d, _, _, _) = resolve_subscription_decision(&renamed, None, &[rule.clone()], None);
    assert_eq!(d, DecisionKind::Exclude);

    let new_sub = SubscriptionInfo {
        id: SubscriptionId::new("sub-msdn-new"),
        tenant_id: TenantId::new("tenant-a"),
        name: "MSDN Extra".into(),
        state: "Enabled".into(),
        quota_id: Some("MSDN_2014-09-01".into()),
        tags: json!({}),
        access_issue: None,
        last_refresh: None,
        metadata_read: true,
    };
    let (d2, _, _, _) = resolve_subscription_decision(&new_sub, None, &[rule.clone()], None);
    assert_eq!(d2, DecisionKind::Exclude);

    let explicit = ScopeDecision {
        id: "keep".into(),
        provider: Provider::Azure,
        tenant_id: TenantId::new("tenant-a"),
        subscription_id: Some(SubscriptionId::new("sub-msdn-1")),
        decision: DecisionKind::Track,
        source: DecisionSource::Explicit,
        matching_rule_id: None,
        reason: Some("override".into()),
        effective_from: Utc::now(),
        effective_to: None,
    };
    let (d3, src, _, _) =
        resolve_subscription_decision(&renamed, Some(&explicit), &[rule], None);
    assert_eq!(d3, DecisionKind::Track);
    assert_eq!(src, DecisionSource::Explicit);
}