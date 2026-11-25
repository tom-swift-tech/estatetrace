use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InboxFilter {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub tenant_id: Option<String>,
    pub subscription_id: Option<String>,
    pub environment: Option<String>,
    pub resource_type: Option<String>,
    pub application: Option<String>,
    pub owner: Option<String>,
    pub severity: Option<String>,
    pub compliance: Option<String>,
    pub ticket_status: Option<String>,
    pub tracked_resources_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedView {
    pub id: String,
    pub name: String,
    pub filter: InboxFilter,
    pub group_by: Option<String>,
    pub sort_by: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorSessionMeta {
    pub last_visit: Option<DateTime<Utc>>,
    pub active_view_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsDoc {
    pub scan_interval_minutes: u64,
    pub operations_timezone: Option<String>,
    pub chat_history_enabled: bool,
    pub retention: Value,
    pub production_mappings: Value,
    pub servicenow: Option<Value>,
    pub chat: Option<Value>,
    pub theme_path: Option<String>,
    /// Ownership / routing tag names and LOB display names (P4). Operator profile only.
    #[serde(default)]
    pub ownership: Option<crate::OwnershipConfig>,
}

impl Default for SettingsDoc {
    fn default() -> Self {
        Self {
            scan_interval_minutes: 60,
            operations_timezone: None,
            chat_history_enabled: false,
            retention: serde_json::json!({}),
            production_mappings: serde_json::json!({}),
            servicenow: None,
            chat: None,
            theme_path: None,
            ownership: None,
        }
    }
}