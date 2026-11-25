use crate::{
    DecisionKind, DecisionSource, Provider, SubscriptionId, TenantId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantInfo {
    pub id: TenantId,
    pub name: String,
    pub needs_sign_in: bool,
    pub last_refresh: Option<DateTime<Utc>>,
    pub access_issue: Option<String>,
}

fn default_metadata_read() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    pub id: SubscriptionId,
    pub tenant_id: TenantId,
    pub name: String,
    pub state: String,
    pub quota_id: Option<String>,
    pub tags: Value,
    pub access_issue: Option<String>,
    pub last_refresh: Option<DateTime<Utc>>,
    /// False when this refresh could not read quota ID and tags. Refresh then keeps the
    /// stored values. Omitted from API JSON; missing on deserialize means the values are real.
    #[serde(default = "default_metadata_read", skip_serializing)]
    pub metadata_read: bool,
}

/// A tenant name that is only the tenant id (or blank) is not a display name.
fn tenant_name_is_placeholder(id: &TenantId, name: &str) -> bool {
    let name = name.trim();
    name.is_empty() || name.eq_ignore_ascii_case(id.as_str())
}

/// Apply a discovery refresh without erasing metadata the refresh could not read.
///
/// Tenant rows whose name is only the tenant id keep a previously stored display name.
/// Subscriptions with `metadata_read == false` keep the stored quota ID and tags.
pub fn merge_discovered_scope(
    mut tenants: Vec<TenantInfo>,
    mut subscriptions: Vec<SubscriptionInfo>,
    previous_tenants: &[TenantInfo],
    previous_subscriptions: &[SubscriptionInfo],
) -> (Vec<TenantInfo>, Vec<SubscriptionInfo>) {
    for tenant in &mut tenants {
        if !tenant_name_is_placeholder(&tenant.id, &tenant.name) {
            continue;
        }
        if let Some(prev) = previous_tenants
            .iter()
            .find(|p| p.id.as_str().eq_ignore_ascii_case(tenant.id.as_str()))
        {
            if !tenant_name_is_placeholder(&prev.id, &prev.name) {
                tenant.name = prev.name.clone();
            }
        }
    }
    for sub in &mut subscriptions {
        if sub.metadata_read {
            continue;
        }
        if let Some(prev) = previous_subscriptions
            .iter()
            .find(|p| p.id.as_str().eq_ignore_ascii_case(sub.id.as_str()))
        {
            sub.quota_id = prev.quota_id.clone();
            sub.tags = prev.tags.clone();
        }
    }
    (tenants, subscriptions)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeDecision {
    pub id: String,
    pub provider: Provider,
    pub tenant_id: TenantId,
    pub subscription_id: Option<SubscriptionId>,
    pub decision: DecisionKind,
    pub source: DecisionSource,
    pub matching_rule_id: Option<String>,
    pub reason: Option<String>,
    pub effective_from: DateTime<Utc>,
    pub effective_to: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionRule {
    pub id: String,
    pub name: String,
    pub tenant_id: Option<TenantId>,
    /// name contains, tag equals, quota_id equals
    pub filter: ExclusionFilter,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionFilter {
    pub name_contains: Option<String>,
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
    pub quota_id: Option<String>,
    pub offer_mapping: Option<String>,
}

impl ExclusionFilter {
    pub fn matches(&self, sub: &SubscriptionInfo) -> bool {
        if let Some(ref needle) = self.name_contains {
            if !sub
                .name
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
            {
                return false;
            }
        }
        if let Some(ref q) = self.quota_id {
            match &sub.quota_id {
                Some(sq) if sq.eq_ignore_ascii_case(q) => {}
                _ => return false,
            }
        }
        if let (Some(k), Some(v)) = (&self.tag_key, &self.tag_value) {
            let ok = sub
                .tags
                .as_object()
                .and_then(|o| o.get(k))
                .and_then(|x| x.as_str())
                .map(|sv| sv.eq_ignore_ascii_case(v))
                .unwrap_or(false);
            if !ok {
                return false;
            }
        }
        if self.name_contains.is_none()
            && self.quota_id.is_none()
            && self.tag_key.is_none()
            && self.offer_mapping.is_none()
        {
            return false;
        }
        true
    }

    pub fn match_reason(&self, sub: &SubscriptionInfo) -> String {
        let mut parts = Vec::new();
        if let Some(ref n) = self.name_contains {
            parts.push(format!("name contains '{n}'"));
        }
        if let Some(ref q) = self.quota_id {
            parts.push(format!("quota_id={q}"));
        }
        if let (Some(k), Some(v)) = (&self.tag_key, &self.tag_value) {
            parts.push(format!("tag {k}={v}"));
        }
        if let Some(ref o) = self.offer_mapping {
            parts.push(format!("offer mapping '{o}'"));
        }
        if parts.is_empty() {
            format!("matched subscription {}", sub.id)
        } else {
            parts.join(", ")
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantDefault {
    pub tenant_id: TenantId,
    /// When true, newly discovered unmatched subscriptions are tracked automatically.
    pub auto_track_new: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveScopeRow {
    pub subscription: SubscriptionInfo,
    pub decision: DecisionKind,
    pub source: DecisionSource,
    pub reason: Option<String>,
    pub matching_rule_id: Option<String>,
}

/// Resolve effective decision for a subscription.
/// Order: explicit subscription decision → matching saved exclusion → tenant default.
pub fn resolve_subscription_decision(
    sub: &SubscriptionInfo,
    explicit: Option<&ScopeDecision>,
    rules: &[ExclusionRule],
    tenant_default: Option<&TenantDefault>,
) -> (DecisionKind, DecisionSource, Option<String>, Option<String>) {
    if let Some(ex) = explicit {
        if ex.effective_to.is_none() {
            return (
                ex.decision.clone(),
                DecisionSource::Explicit,
                ex.reason.clone(),
                ex.matching_rule_id.clone(),
            );
        }
    }

    for rule in rules.iter().filter(|r| r.enabled) {
        if let Some(ref tid) = rule.tenant_id {
            if tid != &sub.tenant_id {
                continue;
            }
        }
        if rule.filter.matches(sub) {
            return (
                DecisionKind::Exclude,
                DecisionSource::SavedRule,
                Some(rule.filter.match_reason(sub)),
                Some(rule.id.clone()),
            );
        }
    }

    let auto = tenant_default.map(|t| t.auto_track_new).unwrap_or(false);
    if auto {
        (
            DecisionKind::Track,
            DecisionSource::TenantDefault,
            Some("tenant auto-track".into()),
            None,
        )
    } else {
        (
            DecisionKind::AwaitReview,
            DecisionSource::TenantDefault,
            Some("tenant awaits review".into()),
            None,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionPreview {
    pub match_count: usize,
    pub sample_names: Vec<String>,
    pub reasons: Vec<String>,
}