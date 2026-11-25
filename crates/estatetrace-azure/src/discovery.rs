use crate::az_json;
use anyhow::Result;
use chrono::Utc;
use estatetrace_core::{SubscriptionId, SubscriptionInfo, TenantId, TenantInfo};
use serde::Deserialize;
use serde_json::Value;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct AzAccount {
    id: String,
    name: String,
    state: Option<String>,
    #[serde(rename = "tenantId")]
    tenant_id: String,
}

#[derive(Debug, Deserialize)]
struct AzTenant {
    id: Option<String>,
    #[serde(rename = "tenantId")]
    tenant_id: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    name: Option<String>,
}

pub async fn discover_tenants_and_subscriptions() -> Result<(Vec<TenantInfo>, Vec<SubscriptionInfo>)> {
    info!("refreshing Azure tenants and subscriptions via Azure CLI");
    let now = Utc::now();

    let mut tenants: Vec<TenantInfo> = Vec::new();
    if let Ok(tenant_source) =
        az_json::<Vec<AzTenant>>(&["account", "tenant", "list", "-o", "json"]).await
    {
        for t in tenant_source {
            let id = t.tenant_id.or(t.id);
            let Some(id) = id else { continue };
            let name = t.display_name.or(t.name).unwrap_or_else(|| id.clone());
            tenants.push(TenantInfo {
                id: TenantId::new(id),
                name,
                needs_sign_in: false,
                last_refresh: Some(now),
                access_issue: None,
            });
        }
    }

    // `--all` includes subscriptions from every signed-in tenant, not only the active one.
    let accounts: Vec<AzAccount> = az_json(&["account", "list", "--all", "-o", "json"]).await?;
    let mut subscriptions = Vec::with_capacity(accounts.len());
    for a in accounts {
        let (quota_id, tags, metadata_read) = match fetch_subscription_meta(&a.id).await {
            Ok((quota_id, tags)) => (quota_id, tags, true),
            Err(e) => {
                warn!("subscription metadata unavailable for {}: {e}", a.id);
                (None, Value::Object(Default::default()), false)
            }
        };
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
            metadata_read,
        });
    }

    tenants.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    tenants.dedup_by(|a, b| a.id == b.id);

    Ok((tenants, subscriptions))
}

async fn fetch_subscription_meta(sub_id: &str) -> Result<(Option<String>, Value)> {
    #[derive(Deserialize)]
    struct Sub {
        #[serde(rename = "subscriptionPolicies")]
        subscription_policies: Option<SubPolicies>,
        tags: Option<Value>,
    }
    #[derive(Deserialize)]
    struct SubPolicies {
        #[serde(rename = "quotaId")]
        quota_id: Option<String>,
    }

    let uri = format!(
        "https://management.azure.com/subscriptions/{sub_id}?api-version=2022-12-01"
    );
    let s: Sub = match az_json(&[
        "account",
        "subscription",
        "show",
        "--subscription",
        sub_id,
        "-o",
        "json",
    ])
    .await
    {
        Ok(v) => v,
        Err(_) => {
            az_json(&[
                "rest",
                "--method",
                "get",
                "--uri",
                &uri,
                "-o",
                "json",
            ])
            .await?
        }
    };

    Ok((
        s.subscription_policies.and_then(|p| p.quota_id),
        s.tags.unwrap_or(Value::Object(Default::default())),
    ))
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
