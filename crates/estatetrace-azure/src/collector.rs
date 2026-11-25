use crate::{arm_access_token, az_json_value};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use estatetrace_core::*;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::Duration;
use tracing::{info, warn};
use uuid::Uuid;

const ARG_ENDPOINT: &str = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01";
const PAGE_SIZE: usize = 1000;

pub struct InventoryBatch {
    pub resources: Vec<ResourceObservation>,
    pub changes: Vec<ChangeEvent>,
    pub checkpoint: Option<String>,
    pub complete: bool,
}

pub struct Collector {
    client: Client,
}

impl Collector {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .expect("http client"),
        }
    }

    /// Page Resource Graph inventory for a subscription in stable resource-id order.
    pub async fn collect_subscription_inventory(
        &self,
        tenant_id: &str,
        subscription_id: &str,
        scan_id: &str,
        skip_token: Option<&str>,
    ) -> Result<InventoryBatch> {
        let query = format!(
            "Resources | where subscriptionId =~ '{subscription_id}' | order by id asc | project id, name, type, location, resourceGroup, subscriptionId, tenantId, tags, properties"
        );

        let mut body = json!({
            "subscriptions": [subscription_id],
            "query": query,
            "options": { "resultFormat": "objectArray", "$top": PAGE_SIZE }
        });
        if let Some(tok) = skip_token {
            body["options"]["$skipToken"] = json!(tok);
        }

        let data = self
            .arg_query_with_retry(body)
            .await
            .context("resource graph inventory")?;

        let rows = data
            .get("data")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        let arr = rows.as_array().cloned().unwrap_or_default();
        let now = Utc::now();
        let mut resources = Vec::with_capacity(arr.len());
        for row in arr {
            let rid = row
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if rid.is_empty() {
                continue;
            }
            resources.push(ResourceObservation {
                id: Uuid::new_v4().to_string(),
                provider: Provider::Azure,
                resource_id: ResourceId::new(rid),
                tenant_id: TenantId::new(
                    row.get("tenantId")
                        .and_then(|v| v.as_str())
                        .unwrap_or(tenant_id)
                        .to_string(),
                ),
                subscription_id: SubscriptionId::new(subscription_id.to_string()),
                resource_type: row
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                name: row
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                location: row
                    .get("location")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                resource_group: row
                    .get("resourceGroup")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                tags: row.get("tags").cloned().unwrap_or(json!({})),
                properties: row.get("properties").cloned().unwrap_or(json!({})),
                scan_id: scan_id.to_string(),
                observation_time: now,
                evidence_available: true,
                lifecycle_epoch: 1,
            });
        }

        let next = data
            .get("$skipToken")
            .or_else(|| data.pointer("/options/$skipToken"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(InventoryBatch {
            resources,
            changes: vec![],
            checkpoint: next.clone(),
            complete: next.is_none(),
        })
    }

    /// Collect Azure change analysis records for a subscription (14-day provider window).
    pub async fn collect_changes(
        &self,
        subscription_id: &str,
        since: Option<&str>,
    ) -> Result<Vec<ChangeEvent>> {
        let since_clause = since
            .map(|s| format!("| where changeAttributes.timestamp >= datetime('{s}')"))
            .unwrap_or_default();
        let query = format!(
            "resourcechanges | where subscriptionId =~ '{subscription_id}' {since_clause} | order by changeAttributes.timestamp asc | project id, resourceId=properties.targetResourceId, timestamp=changeAttributes.timestamp, changeType=properties.changeType, changes=properties.changes"
        );
        let body = json!({
            "subscriptions": [subscription_id],
            "query": query,
            "options": { "resultFormat": "objectArray", "$top": PAGE_SIZE }
        });

        let data = match self.arg_query_with_retry(body).await {
            Ok(d) => d,
            Err(e) => {
                warn!("change query failed for {subscription_id}: {e}");
                return Ok(vec![]);
            }
        };

        let arr = data
            .get("data")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let now = Utc::now();
        let mut out = Vec::new();
        for row in arr {
            let source_event_id = row
                .get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let rid = row
                .get("resourceId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if rid.is_empty() {
                continue;
            }
            let event_time = row
                .get("timestamp")
                .and_then(|v| v.as_str())
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc));
            let change_type = row
                .get("changeType")
                .and_then(|v| v.as_str())
                .unwrap_or("Update");
            let label = match change_type {
                "Create" => ChangeLabel::Created,
                "Delete" => ChangeLabel::ConfirmedDeleted,
                _ => ChangeLabel::Updated,
            };
            let changes = row.get("changes").cloned().unwrap_or(json!({}));
            out.push(ChangeEvent {
                id: Uuid::new_v4().to_string(),
                resource_id: ResourceId::new(rid),
                subscription_id: SubscriptionId::new(subscription_id.to_string()),
                source_event_id,
                label,
                times: DualTime {
                    event_time,
                    observation_time: now,
                },
                before: None,
                after: Some(changes.clone()),
                property_diffs: changes,
            });
        }
        Ok(out)
    }

    /// Resource-group tags for a subscription from `resourcecontainers`, paged in stable
    /// resource-ID order with the same throttle retry as inventory (P4, spec §4.6).
    pub async fn collect_resource_group_tags(
        &self,
        subscription_id: &str,
    ) -> Result<Vec<ResourceGroupTags>> {
        let query = resource_group_tags_query(subscription_id);
        let mut out = Vec::new();
        let mut skip: Option<String> = None;
        loop {
            let mut body = json!({
                "subscriptions": [subscription_id],
                "query": query,
                "options": { "resultFormat": "objectArray", "$top": PAGE_SIZE }
            });
            if let Some(tok) = &skip {
                body["options"]["$skipToken"] = json!(tok);
            }
            let data = self
                .arg_query_with_retry(body)
                .await
                .context("resource graph resource group tags")?;
            out.extend(parse_resource_group_tag_rows(&data, subscription_id, Utc::now()));
            skip = next_skip_token(&data);
            if skip.is_none() {
                break;
            }
        }
        Ok(out)
    }

    async fn arg_query_with_retry(&self, body: Value) -> Result<Value> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self.arg_query(&body).await {
                Ok(v) => return Ok(v),
                Err(e) if attempt < 5 && is_throttle(&e) => {
                    let backoff = Duration::from_millis(200 * 2u64.pow(attempt));
                    warn!("throttled, backing off {backoff:?}: {e}");
                    tokio::time::sleep(backoff).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn arg_query(&self, body: &Value) -> Result<Value> {
        // Prefer az rest for CLI session reuse; fall back to direct HTTP with CLI token.
        match az_json_value(&[
            "rest",
            "--method",
            "post",
            "--uri",
            ARG_ENDPOINT,
            "--body",
            &body.to_string(),
            "-o",
            "json",
        ])
        .await
        {
            Ok(v) => Ok(v),
            Err(_) => {
                let token = arm_access_token().await?;
                let resp = self
                    .client
                    .post(ARG_ENDPOINT)
                    .bearer_auth(token)
                    .json(body)
                    .send()
                    .await?;
                let status = resp.status();
                let text = resp.text().await?;
                if !status.is_success() {
                    return Err(anyhow!("ARG HTTP {status}: {text}"));
                }
                Ok(serde_json::from_str(&text)?)
            }
        }
    }
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

fn resource_group_tags_query(subscription_id: &str) -> String {
    format!(
        "ResourceContainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' and subscriptionId =~ '{subscription_id}' | order by id asc | project id, name, subscriptionId, tags"
    )
}

fn next_skip_token(data: &Value) -> Option<String> {
    data.get("$skipToken")
        .or_else(|| data.pointer("/options/$skipToken"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Turn one Resource Graph page of `resourcecontainers` rows into `ResourceGroupTags`.
/// Rows without a name are skipped; missing or null tags become `{}`.
pub fn parse_resource_group_tag_rows(
    data: &Value,
    subscription_id: &str,
    observed_at: chrono::DateTime<Utc>,
) -> Vec<ResourceGroupTags> {
    data.get("data")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|row| {
                    let name = row.get("name").and_then(|v| v.as_str())?.trim();
                    if name.is_empty() {
                        return None;
                    }
                    let tags = match row.get("tags") {
                        Some(t @ Value::Object(_)) => t.clone(),
                        _ => json!({}),
                    };
                    Some(ResourceGroupTags {
                        subscription_id: SubscriptionId::new(
                            row.get("subscriptionId")
                                .and_then(|v| v.as_str())
                                .unwrap_or(subscription_id)
                                .to_string(),
                        ),
                        resource_group: name.to_string(),
                        tags,
                        observed_at,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn is_throttle(e: &anyhow::Error) -> bool {
    let s = e.to_string().to_ascii_lowercase();
    s.contains("429") || s.contains("throttl") || s.contains("too many")
}

/// Diff previous vs current observations for a subscription and emit local change labels.
pub fn diff_observations(
    previous: &[ResourceObservation],
    current: &[ResourceObservation],
    scan_id: &str,
) -> Vec<ChangeEvent> {
    let prev_map: std::collections::HashMap<&str, &ResourceObservation> = previous
        .iter()
        .map(|o| (o.resource_id.as_str(), o))
        .collect();
    let curr_ids: HashSet<&str> = current.iter().map(|o| o.resource_id.as_str()).collect();
    let now = Utc::now();
    let mut events = Vec::new();

    for obs in current {
        match prev_map.get(obs.resource_id.as_str()) {
            None => {
                events.push(ChangeEvent {
                    id: Uuid::new_v4().to_string(),
                    resource_id: obs.resource_id.clone(),
                    subscription_id: obs.subscription_id.clone(),
                    source_event_id: Some(format!("local:{scan_id}:new:{}", obs.resource_id)),
                    label: ChangeLabel::NewToInventory,
                    times: DualTime {
                        event_time: None,
                        observation_time: now,
                    },
                    before: None,
                    after: Some(json!({
                        "name": obs.name,
                        "type": obs.resource_type,
                        "tags": obs.tags,
                    })),
                    property_diffs: json!({}),
                });
            }
            Some(prev) => {
                let diffs = property_diff(prev, obs);
                if !diffs.is_empty() {
                    events.push(ChangeEvent {
                        id: Uuid::new_v4().to_string(),
                        resource_id: obs.resource_id.clone(),
                        subscription_id: obs.subscription_id.clone(),
                        source_event_id: Some(format!(
                            "local:{scan_id}:upd:{}:{}",
                            obs.resource_id, obs.observation_time
                        )),
                        label: ChangeLabel::Updated,
                        times: DualTime {
                            event_time: None,
                            observation_time: now,
                        },
                        before: Some(json!({
                            "tags": prev.tags,
                            "properties": prev.properties,
                        })),
                        after: Some(json!({
                            "tags": obs.tags,
                            "properties": obs.properties,
                        })),
                        property_diffs: Value::Object(diffs),
                    });
                }
            }
        }
    }

    for prev in previous {
        if !curr_ids.contains(prev.resource_id.as_str()) {
            events.push(ChangeEvent {
                id: Uuid::new_v4().to_string(),
                resource_id: prev.resource_id.clone(),
                subscription_id: prev.subscription_id.clone(),
                source_event_id: Some(format!("local:{scan_id}:missing:{}", prev.resource_id)),
                label: ChangeLabel::MissingFromScan,
                times: DualTime {
                    event_time: None,
                    observation_time: now,
                },
                before: Some(json!({
                    "name": prev.name,
                    "type": prev.resource_type,
                })),
                after: None,
                property_diffs: json!({}),
            });
        }
    }

    events
}

fn property_diff(
    prev: &ResourceObservation,
    curr: &ResourceObservation,
) -> serde_json::Map<String, Value> {
    let mut diffs = serde_json::Map::new();
    if prev.tags != curr.tags {
        diffs.insert(
            "tags".into(),
            json!({ "before": prev.tags, "after": curr.tags }),
        );
    }
    if prev.properties != curr.properties {
        diffs.insert(
            "properties".into(),
            json!({ "before": prev.properties, "after": curr.properties }),
        );
    }
    if prev.location != curr.location {
        diffs.insert(
            "location".into(),
            json!({ "before": prev.location, "after": curr.location }),
        );
    }
    diffs
}

pub async fn run_full_scan_for_subscription(
    collector: &Collector,
    tenant_id: &str,
    subscription_id: &str,
    scan_id: &str,
    previous: &[ResourceObservation],
    start_checkpoint: Option<&str>,
) -> Result<(Vec<ResourceObservation>, Vec<ChangeEvent>, Option<String>, bool)> {
    let mut all = Vec::new();
    let mut checkpoint = start_checkpoint.map(|s| s.to_string());
    let complete;
    loop {
        let batch = collector
            .collect_subscription_inventory(
                tenant_id,
                subscription_id,
                scan_id,
                checkpoint.as_deref(),
            )
            .await?;
        all.extend(batch.resources);
        checkpoint = batch.checkpoint.clone();
        // Persist checkpoint only after successful batch — caller commits.
        if batch.complete || checkpoint.is_none() {
            complete = true;
            break;
        }
        info!(
            "paged inventory for {subscription_id}, next checkpoint present, collected {}",
            all.len()
        );
    }

    let mut changes = diff_observations(previous, &all, scan_id);
    let provider_changes = collector.collect_changes(subscription_id, None).await?;
    changes.extend(provider_changes);
    Ok((all, changes, checkpoint, complete))
}

#[cfg(test)]
mod resource_group_tag_tests {
    use super::*;

    #[test]
    fn parses_resourcecontainers_fixture_page() {
        let page = json!({
            "totalRecords": 3,
            "count": 3,
            "data": [
                {
                    "id": "/subscriptions/sub-contoso-01/resourceGroups/rg-app",
                    "name": "rg-app",
                    "subscriptionId": "sub-contoso-01",
                    "tags": { "Environment": "prod", "app": "Payments" }
                },
                {
                    "id": "/subscriptions/sub-contoso-01/resourceGroups/rg-untagged",
                    "name": "rg-untagged",
                    "subscriptionId": "sub-contoso-01",
                    "tags": null
                },
                { "id": "/subscriptions/sub-contoso-01/resourceGroups/x", "name": "" }
            ],
            "$skipToken": "next-page"
        });
        let at = Utc::now();
        let rows = parse_resource_group_tag_rows(&page, "sub-contoso-01", at);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].resource_group, "rg-app");
        assert_eq!(rows[0].subscription_id.as_str(), "sub-contoso-01");
        assert_eq!(rows[0].tags["Environment"], "prod");
        assert_eq!(rows[1].tags, json!({}));
        assert_eq!(next_skip_token(&page).as_deref(), Some("next-page"));
        assert!(next_skip_token(&json!({ "data": [] })).is_none());
        assert!(resource_group_tags_query("sub-contoso-01").contains("resourcegroups"));
    }
}
