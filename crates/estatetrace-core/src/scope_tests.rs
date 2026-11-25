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
            metadata_read: true,
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

    #[test]
    fn refresh_keeps_unread_quota_tags_and_tenant_display_name() {
        let previous_tenant = TenantInfo {
            id: TenantId::new("tenant-a"),
            name: "Contoso".into(),
            needs_sign_in: false,
            last_refresh: None,
            access_issue: None,
        };
        let mut previous_sub = sub("SUB-1", "Pay as you go", "tenant-a");
        previous_sub.tags = json!({ "costCenter": "lab" });
        let mut incoming_sub = sub("sub-1", "Pay as you go", "tenant-a");
        incoming_sub.quota_id = None;
        incoming_sub.tags = json!({});
        incoming_sub.metadata_read = false;
        let incoming_tenant = TenantInfo {
            id: TenantId::new("TENANT-A"),
            name: "TENANT-A".into(),
            needs_sign_in: false,
            last_refresh: None,
            access_issue: None,
        };
        let (tenants, subs) = merge_discovered_scope(
            vec![incoming_tenant],
            vec![incoming_sub],
            &[previous_tenant],
            &[previous_sub],
        );
        assert_eq!(tenants[0].name, "Contoso");
        assert_eq!(subs[0].quota_id.as_deref(), Some("MSDN_2014-09-01"));
        assert_eq!(subs[0].tags, json!({ "costCenter": "lab" }));
    }

    #[test]
    fn refresh_applies_quota_and_tags_when_metadata_was_read() {
        let mut previous = sub("sub-1", "Old", "tenant-a");
        previous.tags = json!({ "costCenter": "lab" });
        let mut incoming = sub("sub-1", "Old", "tenant-a");
        incoming.quota_id = None;
        incoming.tags = json!({});
        incoming.metadata_read = true;
        let named = TenantInfo {
            id: TenantId::new("tenant-a"),
            name: "Contoso".into(),
            needs_sign_in: false,
            last_refresh: None,
            access_issue: None,
        };
        let (tenants, subs) =
            merge_discovered_scope(vec![named], vec![incoming], &[], &[previous]);
        assert_eq!(tenants[0].name, "Contoso");
        assert!(subs[0].quota_id.is_none());
        assert_eq!(subs[0].tags, json!({}));
    }
}