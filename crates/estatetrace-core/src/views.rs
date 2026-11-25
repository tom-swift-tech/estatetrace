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
    /// Collection guards (P5, spec §4.6 `ScanGuards`).
    #[serde(default)]
    pub scan_guards: ScanGuards,
}

/// Guards against inferring deletions from a suspicious inventory (port of azcompliance's
/// subscription-drop preflight, applied per subscription).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanGuards {
    /// A complete pass that returns this much less than the previous inventory (percent of
    /// the previous count) does not infer deletions. 100 disables the guard.
    #[serde(default = "default_drop_tolerance")]
    pub resource_drop_tolerance_percent: u8,
    /// Drops smaller than this many resources are never blocked, so small subscriptions can
    /// still record real deletions.
    #[serde(default = "default_drop_min_count")]
    pub resource_drop_min_count: u32,
}

fn default_drop_tolerance() -> u8 {
    50
}

fn default_drop_min_count() -> u32 {
    10
}

impl Default for ScanGuards {
    fn default() -> Self {
        Self {
            resource_drop_tolerance_percent: default_drop_tolerance(),
            resource_drop_min_count: default_drop_min_count(),
        }
    }
}

/// Outcome of the resource-count drop check for one complete subscription pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropCheck {
    /// Deletions may be inferred from absence in this pass.
    pub deletions_allowed: bool,
    /// Previously known resources not seen in this pass.
    pub missing: usize,
    /// `missing` as a whole percent of the previous count (0 when there was none).
    pub drop_percent: u8,
}

impl ScanGuards {
    pub fn check_drop(&self, previous_count: usize, missing: usize) -> DropCheck {
        let drop_percent = if previous_count == 0 {
            0
        } else {
            ((missing.min(previous_count) * 100) / previous_count) as u8
        };
        let blocked = self.resource_drop_tolerance_percent < 100
            && missing as u64 >= self.resource_drop_min_count as u64
            && drop_percent > self.resource_drop_tolerance_percent;
        DropCheck {
            deletions_allowed: !blocked,
            missing,
            drop_percent,
        }
    }

    /// Coverage note for a blocked drop. The percent is `missing / previous`, so the
    /// parenthetical reports that missing count and the number seen. Seen can exceed
    /// `previous - missing` when the pass also created resources.
    pub fn note(&self, previous_count: usize, seen: usize, c: &DropCheck) -> String {
        format!(
            "resource count dropped {}% ({} of {previous_count} previous resources missing, {seen} seen); deletions not inferred (tolerance {}%)",
            c.drop_percent, c.missing, self.resource_drop_tolerance_percent
        )
    }
}

#[cfg(test)]
mod scan_guard_tests {
    use super::*;

    #[test]
    fn ac_p5_1_large_drop_blocks_deletion_inference() {
        let g = ScanGuards::default();
        let c = g.check_drop(500, 490);
        assert!(!c.deletions_allowed);
        assert_eq!(c.drop_percent, 98);
        let note = g.note(500, 10, &c);
        assert!(note.contains("dropped 98%"), "{note}");
        assert!(note.contains("490 of 500 previous resources missing"), "{note}");
        assert!(note.contains("10 seen"), "{note}");
        assert!(note.contains("deletions not inferred"), "{note}");
    }

    #[test]
    fn drop_note_reports_missing_count_when_creates_offset_deletes() {
        let g = ScanGuards::default();
        // 60 of 100 missing, but 40 new resources make the seen count 80.
        let c = g.check_drop(100, 60);
        let note = g.note(100, 80, &c);
        assert!(note.contains("dropped 60%"), "{note}");
        assert!(note.contains("60 of 100 previous resources missing, 80 seen"), "{note}");
    }

    #[test]
    fn normal_churn_and_small_subscriptions_still_infer_deletions() {
        let g = ScanGuards::default();
        assert!(g.check_drop(500, 20).deletions_allowed); // 4%
        assert!(g.check_drop(3, 3).deletions_allowed); // 100% but below min count
        assert!(g.check_drop(0, 0).deletions_allowed);
    }

    #[test]
    fn tolerance_100_disables_guard_and_settings_default_when_absent() {
        let off = ScanGuards { resource_drop_tolerance_percent: 100, resource_drop_min_count: 0 };
        assert!(off.check_drop(500, 500).deletions_allowed);
        let doc: SettingsDoc = serde_json::from_str(
            r#"{"scan_interval_minutes":60,"operations_timezone":null,"chat_history_enabled":false,
                "retention":{},"production_mappings":{},"servicenow":null,"chat":null,"theme_path":null}"#,
        )
        .unwrap();
        assert_eq!(doc.scan_guards, ScanGuards::default());
    }
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
            scan_guards: ScanGuards::default(),
        }
    }
}