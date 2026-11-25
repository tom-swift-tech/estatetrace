#[cfg(test)]
mod tests {
    use crate::diff_observations;
    use chrono::Utc;
    use estatetrace_core::*;
    use serde_json::json;

    fn obs(id: &str, tag: &str) -> ResourceObservation {
        ResourceObservation {
            id: format!("o-{id}"),
            provider: Provider::Azure,
            resource_id: ResourceId::new(id),
            tenant_id: TenantId::new("t1"),
            subscription_id: SubscriptionId::new("s1"),
            resource_type: "Microsoft.Storage/storageAccounts".into(),
            name: id.into(),
            location: Some("eastus".into()),
            resource_group: Some("rg".into()),
            tags: json!({ "CostCenter": tag }),
            properties: json!({}),
            scan_id: "scan".into(),
            observation_time: Utc::now(),
            evidence_available: true,
            lifecycle_epoch: 1,
            arm_meta: serde_json::json!({}),
        }
    }

    #[test]
    fn ac02_no_duplicate_local_events_and_missing_not_deletion() {
        let prev = vec![obs("res-a", "CC-1"), obs("res-b", "CC-1")];
        let curr = vec![obs("res-a", "CC-2")]; // res-b missing from scan; res-a updated
        let events = diff_observations(&prev, &curr, "scan-2");
        assert!(events.iter().any(|e| e.label == ChangeLabel::Updated));
        assert!(events.iter().any(|e| e.label == ChangeLabel::MissingFromScan));
        assert!(!events.iter().any(|e| e.label == ChangeLabel::ConfirmedDeleted));
        // Stable source ids for local events support dedupe on retry
        let ids: Vec<_> = events.iter().filter_map(|e| e.source_event_id.clone()).collect();
        assert_eq!(ids.len(), ids.iter().collect::<std::collections::HashSet<_>>().len());
    }
}