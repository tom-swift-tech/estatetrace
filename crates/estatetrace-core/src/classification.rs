use crate::{ResourceObservation, SubscriptionId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentClass {
    Prod,
    NonProd,
    Unknown,
}

impl EnvironmentClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            EnvironmentClass::Prod => "prod",
            EnvironmentClass::NonProd => "nonprod",
            EnvironmentClass::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationRuleKind {
    Subscription,
    ResourceGroup,
    Tag,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationRule {
    pub id: String,
    pub kind: ClassificationRuleKind,
    pub subscription_id: Option<SubscriptionId>,
    pub resource_group: Option<String>,
    pub tag_key: Option<String>,
    pub tag_value: Option<String>,
    pub environment: EnvironmentClass,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    pub environment: EnvironmentClass,
    pub winning_rule_id: Option<String>,
    pub conflicting: bool,
    pub missing_tag: bool,
    pub reason: String,
}

/// Classify a resource. A missing environment tag on a known production subscription
/// must still resolve to Prod (AC-07).
pub fn classify_resource(
    obs: &ResourceObservation,
    rules: &[ClassificationRule],
) -> ClassificationResult {
    let mut matches: Vec<&ClassificationRule> = rules
        .iter()
        .filter(|r| rule_matches(r, obs))
        .collect();
    matches.sort_by_key(|r| std::cmp::Reverse(r.priority));

    let missing_tag = obs
        .tags
        .as_object()
        .map(|t| !t.contains_key("Environment") && !t.contains_key("environment"))
        .unwrap_or(true);

    if matches.is_empty() {
        return ClassificationResult {
            environment: EnvironmentClass::Unknown,
            winning_rule_id: None,
            conflicting: false,
            missing_tag,
            reason: "no classification rule matched".into(),
        };
    }

    let winner = matches[0];
    let conflicting = matches
        .iter()
        .any(|r| r.environment != winner.environment);

    // AC-07: known Prod subscription keeps Prod even if env tag missing.
    let environment = if winner.environment == EnvironmentClass::Prod {
        EnvironmentClass::Prod
    } else {
        winner.environment.clone()
    };

    ClassificationResult {
        environment,
        winning_rule_id: Some(winner.id.clone()),
        conflicting,
        missing_tag,
        reason: format!("rule {}", winner.id),
    }
}

fn rule_matches(rule: &ClassificationRule, obs: &ResourceObservation) -> bool {
    match rule.kind {
        ClassificationRuleKind::Subscription => rule
            .subscription_id
            .as_ref()
            .map(|s| s == &obs.subscription_id)
            .unwrap_or(false),
        ClassificationRuleKind::ResourceGroup => {
            let sub_ok = rule
                .subscription_id
                .as_ref()
                .map(|s| s == &obs.subscription_id)
                .unwrap_or(true);
            let rg_ok = rule
                .resource_group
                .as_ref()
                .zip(obs.resource_group.as_ref())
                .map(|(a, b)| a.eq_ignore_ascii_case(b))
                .unwrap_or(false);
            sub_ok && rg_ok
        }
        ClassificationRuleKind::Tag => {
            let Some(k) = &rule.tag_key else {
                return false;
            };
            let Some(v) = &rule.tag_value else {
                return false;
            };
            obs.tags
                .as_object()
                .and_then(|o| o.get(k).or_else(|| {
                    // case-insensitive common keys
                    o.iter().find(|(ak, _)| ak.eq_ignore_ascii_case(k)).map(|(_, v)| v)
                }))
                .and_then(|x| x.as_str())
                .map(|sv| sv.eq_ignore_ascii_case(v))
                .unwrap_or(false)
        }
    }
}