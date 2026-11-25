use crate::{
    DualTime, EnvironmentClass, EvalOutcome, Provider, ResourceId, Severity, SubscriptionId, TenantId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRun {
    pub id: String,
    pub source: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub completeness: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceCoverage {
    pub id: String,
    pub source: String,
    pub subscription_id: SubscriptionId,
    pub last_success: Option<DateTime<Utc>>,
    pub last_checkpoint: Option<String>,
    pub gap_start: Option<DateTime<Utc>>,
    pub gap_end: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceObservation {
    pub id: String,
    pub provider: Provider,
    pub resource_id: ResourceId,
    pub tenant_id: TenantId,
    pub subscription_id: SubscriptionId,
    pub resource_type: String,
    pub name: String,
    pub location: Option<String>,
    pub resource_group: Option<String>,
    pub tags: Value,
    pub properties: Value,
    pub scan_id: String,
    pub observation_time: DateTime<Utc>,
    pub evidence_available: bool,
    pub lifecycle_epoch: i64,
    /// Top-level Resource Graph fields outside `properties`: kind, sku, identity, plan,
    /// zones, managedBy, extendedLocation (only those present). `{}` when none.
    #[serde(default = "empty_object")]
    pub arm_meta: Value,
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeLabel {
    NewToInventory,
    Created,
    Updated,
    MissingFromScan,
    ConfirmedDeleted,
}

impl ChangeLabel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeLabel::NewToInventory => "new_to_inventory",
            ChangeLabel::Created => "created",
            ChangeLabel::Updated => "updated",
            ChangeLabel::MissingFromScan => "missing_from_scan",
            ChangeLabel::ConfirmedDeleted => "confirmed_deleted",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeEvent {
    pub id: String,
    pub resource_id: ResourceId,
    pub subscription_id: SubscriptionId,
    pub source_event_id: Option<String>,
    pub label: ChangeLabel,
    pub times: DualTime,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub property_diffs: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evaluation {
    pub id: String,
    pub observation_id: String,
    pub resource_id: ResourceId,
    pub control_id: String,
    pub control_revision: String,
    pub outcome: EvalOutcome,
    pub severity: Severity,
    pub evidence: Value,
    pub evaluated_at: DateTime<Utc>,
    /// Environment the resource was classified into when evaluated.
    #[serde(default = "unknown_environment")]
    pub environment: EnvironmentClass,
    /// Human-readable reason for the outcome (empty on pass).
    #[serde(default)]
    pub detail: String,
}

fn unknown_environment() -> EnvironmentClass {
    EnvironmentClass::Unknown
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub kind: String,
    pub id: String,
    pub times: DualTime,
    pub summary: String,
    pub detail: Value,
}