//! Cross-resource joins exposed to checks as `join.<name>` (spec §3.1, AC-P5-2).
//!
//! Port of the azcompliance collector's subnet join: subnets are not rows of their own in
//! Resource Graph, so the index is built from each virtual network's `properties.subnets[]`.
//! A resource that references a subnet joins it as `join.subnet`; a referenced subnet that is
//! not in the index (its VNet is outside the visible scope) leaves `join.subnet` null, and a
//! leaf with `evidence_source: join` then evaluates to unknown.
//!
//! Building and lookup are pure: no clock, no I/O, and the same observations give the same
//! index regardless of input order (invariant 1).

use estatetrace_core::ResourceObservation;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

const VNET_TYPE: &str = "microsoft.network/virtualnetworks";
const SUBNET_TYPE: &str = "microsoft.network/virtualnetworks/subnets";
const PRIVATE_ENDPOINT_TYPE: &str = "microsoft.network/privateendpoints";
const MANAGED_ENVIRONMENT_TYPE: &str = "microsoft.app/managedenvironments";
const NIC_TYPE: &str = "microsoft.network/networkinterfaces";

/// One indexed subnet, with what decides between duplicates (same subnet ID in two VNet rows).
#[derive(Debug, Clone)]
struct SubnetEntry {
    /// `(observation_time, lowercase VNet ID)`: the greater wins, so input order never matters.
    rank: (i64, String),
    subnet: Value,
}

#[derive(Debug, Clone, Default)]
pub struct JoinIndex {
    /// Lowercase subnet ID -> subnet object.
    subnets: BTreeMap<String, SubnetEntry>,
}

impl JoinIndex {
    /// An index with no joins: every referenced subnet is outside the visible scope.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Index every subnet of every virtual network in `latest` by lowercase subnet ID.
    ///
    /// The joined subnet object is the VNet's `properties.subnets[]` entry (`id`, `name`,
    /// `properties`, ...) plus `type`, `vnetId` and `vnetName`.
    pub fn build(latest: &[ResourceObservation]) -> Self {
        let mut subnets: BTreeMap<String, SubnetEntry> = BTreeMap::new();
        for obs in latest {
            if !obs.resource_type.eq_ignore_ascii_case(VNET_TYPE) {
                continue;
            }
            let Some(list) = key(&obs.properties, "subnets").and_then(Value::as_array) else {
                continue;
            };
            let vnet_id = obs.resource_id.as_str();
            let rank = (
                obs.observation_time.timestamp_micros(),
                vnet_id.to_ascii_lowercase(),
            );
            for s in list {
                let Some(obj) = s.as_object() else { continue };
                let Some(id) = key(s, "id")
                    .and_then(Value::as_str)
                    .filter(|i| !i.is_empty())
                else {
                    continue;
                };
                let mut subnet = obj.clone();
                subnet.entry("type").or_insert_with(|| SUBNET_TYPE.into());
                subnet.insert("vnetId".into(), vnet_id.into());
                subnet.insert("vnetName".into(), obs.name.clone().into());
                let entry = SubnetEntry {
                    rank: rank.clone(),
                    subnet: Value::Object(subnet),
                };
                let id = id.to_ascii_lowercase();
                match subnets.get(&id) {
                    Some(existing) if existing.rank >= entry.rank => {}
                    _ => {
                        subnets.insert(id, entry);
                    }
                }
            }
        }
        Self { subnets }
    }

    /// Number of indexed subnets.
    pub fn subnet_count(&self) -> usize {
        self.subnets.len()
    }

    /// The indexed subnet object for `subnet_id` (case-insensitive), if visible.
    pub fn subnet(&self, subnet_id: &str) -> Option<&Value> {
        self.subnets
            .get(&subnet_id.to_ascii_lowercase())
            .map(|e| &e.subnet)
    }

    /// The `join` object for one resource, or `None` when its type has no join.
    ///
    /// - private endpoints join `properties.subnet.id`;
    /// - Container Apps managed environments join `properties.vnetConfiguration.infrastructureSubnetId`
    ///   (no join when the environment is not VNet-injected);
    /// - network interfaces join `properties.ipConfigurations[0].properties.subnet.id`
    ///   (no join when that is not reported).
    ///
    /// Returns `{"subnet": null}` when the referenced subnet is not in the index.
    pub fn view_for(&self, obs: &ResourceObservation) -> Option<Value> {
        let t = obs.resource_type.as_str();
        let props = &obs.properties;
        let subnet_ref: Option<&str> = if t.eq_ignore_ascii_case(PRIVATE_ENDPOINT_TYPE) {
            // As in azcompliance, a private endpoint always carries the join, even when the
            // subnet reference is missing.
            Some(
                path(props, &["subnet", "id"])
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            )
        } else if t.eq_ignore_ascii_case(MANAGED_ENVIRONMENT_TYPE) {
            path(props, &["vnetConfiguration", "infrastructureSubnetId"])
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        } else if t.eq_ignore_ascii_case(NIC_TYPE) {
            key(props, "ipConfigurations")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(|c| path(c, &["properties", "subnet", "id"]))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        } else {
            return None;
        };
        let subnet_ref = subnet_ref?;
        let joined = if subnet_ref.is_empty() {
            Value::Null
        } else {
            self.subnet(subnet_ref).cloned().unwrap_or(Value::Null)
        };
        Some(json!({ "subnet": joined }))
    }
}

/// Observations whose subscription is in the tracked scope, compared case-insensitively.
///
/// Join evidence is limited to this set. A VNet in an excluded subscription stays in the
/// local inventory, but it is outside the visible scope and must not supply `join.subnet`
/// (AC-P5-2).
pub fn in_tracked_subscriptions(
    resources: &[ResourceObservation],
    tracked_subscription_ids: &[impl AsRef<str>],
) -> Vec<ResourceObservation> {
    let tracked: HashSet<String> = tracked_subscription_ids
        .iter()
        .map(|s| s.as_ref().to_ascii_lowercase())
        .collect();
    resources
        .iter()
        .filter(|o| tracked.contains(&o.subscription_id.as_str().to_ascii_lowercase()))
        .cloned()
        .collect()
}

/// Object key lookup: exact first, then ignoring ASCII case.
fn key<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    let map = v.as_object()?;
    map.get(k).or_else(|| {
        map.iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(k))
            .map(|(_, v)| v)
    })
}

fn path<'a>(v: &'a Value, segments: &[&str]) -> Option<&'a Value> {
    segments.iter().try_fold(v, |cur, s| key(cur, s))
}
