#[cfg(test)]
mod tests {
    use crate::*;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn ac07_missing_env_tag_on_prod_subscription_stays_prod() {
        let obs = ResourceObservation {
            id: "o1".into(),
            provider: Provider::Azure,
            resource_id: ResourceId::new("/subscriptions/sub-prod/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"),
            tenant_id: TenantId::new("t1"),
            subscription_id: SubscriptionId::new("sub-prod"),
            resource_type: "Microsoft.Storage/storageAccounts".into(),
            name: "sa1".into(),
            location: Some("eastus".into()),
            resource_group: Some("rg".into()),
            tags: json!({}), // missing Environment tag
            properties: json!({}),
            scan_id: "s1".into(),
            observation_time: Utc::now(),
            evidence_available: true,
            lifecycle_epoch: 1,
        };
        let rules = vec![ClassificationRule {
            id: "prod-sub".into(),
            kind: ClassificationRuleKind::Subscription,
            subscription_id: Some(SubscriptionId::new("sub-prod")),
            resource_group: None,
            tag_key: None,
            tag_value: None,
            environment: EnvironmentClass::Prod,
            priority: 100,
        }];
        let result = classify_resource(&obs, &rules);
        assert_eq!(result.environment, EnvironmentClass::Prod);
        assert!(result.missing_tag);
    }
}