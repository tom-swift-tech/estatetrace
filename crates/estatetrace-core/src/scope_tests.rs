#[cfg(test)]
mod tests {
    use crate::*;
    use chrono::Utc;
    use serde_json::json;

    fn sub(id: &str, name: &str, tenant: &str) -> SubscriptionInfo {
        SubscriptionInfo {
            id: SubscriptionId::new(id),
            tenant_id: TenantId::new(tenant),
            name: name.into(),
            state: "Enabled".into(),
            quota_id: Some("MSDN_2014-09-01".into()),
            tags: json!({}),
            access_issue: None,
            last_refresh: None,
        }
    }

    #[test]
    fn ac01_saved_rule_and_explicit_override() {
        let s1 = sub("sub-msdn-1", "MSDN Visual Studio Pro", "tenant-a");
        let s2 = sub("sub-msdn-new", "MSDN Fresh", "tenant-a");
        let renamed = sub("sub-msdn-1", "MSDN Renamed Title", "tenant-a");

        let rule = ExclusionRule {
            id: "rule-msdn".into(),
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

        let (d1, src1, _, _) =
            resolve_subscription_decision(&s1, None, &[rule.clone()], None);
        assert_eq!(d1, DecisionKind::Exclude);
        assert_eq!(src1, DecisionSource::SavedRule);

        // Rename keeps exclusion via name contains MSDN still... renamed still has MSDN
        let (d_renamed, _, _, _) =
            resolve_subscription_decision(&renamed, None, &[rule.clone()], None);
        assert_eq!(d_renamed, DecisionKind::Exclude);

        // New matching subscription also excluded
        let (d2, _, _, _) = resolve_subscription_decision(&s2, None, &[rule.clone()], None);
        assert_eq!(d2, DecisionKind::Exclude);

        // Explicit track override wins
        let explicit = ScopeDecision {
            id: "ex1".into(),
            provider: Provider::Azure,
            tenant_id: TenantId::new("tenant-a"),
            subscription_id: Some(SubscriptionId::new("sub-msdn-1")),
            decision: DecisionKind::Track,
            source: DecisionSource::Explicit,
            matching_rule_id: None,
            reason: Some("keep tracking".into()),
            effective_from: Utc::now(),
            effective_to: None,
        };
        let (d3, src3, _, _) =
            resolve_subscription_decision(&renamed, Some(&explicit), &[rule], None);
        assert_eq!(d3, DecisionKind::Track);
        assert_eq!(src3, DecisionSource::Explicit);
    }
}