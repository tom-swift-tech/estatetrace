//! Joins read only present resources: a VNet marked missing must not supply subnets.

use chrono::Utc;
use estatetrace_core::*;
use estatetrace_db as db;
use serde_json::json;

fn obs(name: &str) -> ResourceObservation {
    ResourceObservation {
        id: format!("obs-{name}"),
        provider: Provider::Azure,
        resource_id: ResourceId::new(format!(
            "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/{name}"
        )),
        tenant_id: TenantId::new("t"),
        subscription_id: SubscriptionId::new("s1"),
        resource_type: "microsoft.network/virtualnetworks".into(),
        name: name.into(),
        location: Some("eastus2".into()),
        resource_group: Some("rg".into()),
        tags: json!({}),
        properties: json!({"subnets": []}),
        scan_id: "scan-1".into(),
        observation_time: Utc::now(),
        evidence_available: true,
        lifecycle_epoch: 1,
        arm_meta: json!({}),
    }
}

#[tokio::test]
async fn missing_resources_are_excluded_from_present_list() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("p.db")).await.unwrap();
    let kept = obs("vnet-kept");
    let gone = obs("vnet-gone");
    db::insert_observation(&pool, &kept).await.unwrap();
    db::insert_observation(&pool, &gone).await.unwrap();
    db::mark_missing(&pool, gone.resource_id.as_str(), Utc::now()).await.unwrap();

    let latest = db::list_latest_resources(&pool).await.unwrap();
    assert_eq!(latest.len(), 2, "latest still lists missing resources (history/diff)");
    let present = db::list_present_resources(&pool).await.unwrap();
    assert_eq!(present.len(), 1);
    assert_eq!(present[0].name, "vnet-kept");
}
