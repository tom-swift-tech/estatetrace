use crate::az_json;
use anyhow::Result;
use chrono::Utc;
use estatetrace_core::{SubscriptionId, SubscriptionInfo, TenantId, TenantInfo};
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

#[derive(Debug, Deserialize)]
struct AzAccount {
    id: String,
    name: String,
    state: Option<String>,
    #[serde(rename = "tenantId")]
    tenant_id: String,
}

pub async fn discover_tenants_and_subscriptions() -> Result<(Vec<TenantInfo>, Vec<SubscriptionInfo>)> {
    info!("refreshing Azure tenants and subscriptions via Azure CLI");
    let now = Utc::now();

    let mut tenants: Vec<TenantInfo> = Vec::new();
    let accounts: Vec<AzAccount> = az_json(&["account", "list", "--all", "-o", "json"]).await?;
    let mut subscriptions = Vec::with_capacity(accounts.len());
    for a in accounts {
        let quota_id = None;
        let tags = Value::Object(Default::default());
        let tid = TenantId::new(a.tenant_id.clone());
        if !tenants.iter().any(|t| t.id == tid) {
            tenants.push(TenantInfo {
                id: tid.clone(),
                name: a.tenant_id.clone(),
                needs_sign_in: false,
                last_refresh: Some(now),
                access_issue: None,
            });
        }
        subscriptions.push(SubscriptionInfo {
            id: SubscriptionId::new(a.id),
            tenant_id: tid,
            name: a.name,
            state: a.state.unwrap_or_else(|| "Unknown".into()),
            quota_id,
            tags,
            access_issue: None,
            last_refresh: Some(now),
        });
    }

    tenants.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    tenants.dedup_by(|a, b| a.id == b.id);

    Ok((tenants, subscriptions))
}

/// Well-known offer / quota suggestions for exclusion rules.
pub fn suggested_offer_searches() -> Vec<Value> {
    vec![
        serde_json::json!({
            "name": "MSDN",
            "filter": { "name_contains": "MSDN", "offer_mapping": "MSDN" }
        }),
        serde_json::json!({
            "name": "Visual Studio",
            "filter": { "name_contains": "Visual Studio", "offer_mapping": "VisualStudio" }
        }),
        serde_json::json!({
            "name": "Pay-As-You-Go",
            "filter": { "quota_id": "PayAsYouGo_2014-09-01", "offer_mapping": "PayAsYouGo" }
        }),
    ]
}