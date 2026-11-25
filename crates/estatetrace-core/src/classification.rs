use crate::{ResourceObservation, SubscriptionId};
use chrono::{DateTime, Utc};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentClass {
    #[serde(alias = "Prod", alias = "production")]
    Prod,
    #[serde(rename = "nonprod", alias = "non_prod", alias = "NonProd", alias = "non-prod")]
    NonProd,
    #[serde(alias = "Dev", alias = "development")]
    Dev,
    #[serde(alias = "Sandbox", alias = "sbx")]
    Sandbox,
    #[serde(alias = "Unknown")]
    Unknown,
}

impl EnvironmentClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            EnvironmentClass::Prod => "prod",
            EnvironmentClass::NonProd => "nonprod",
            EnvironmentClass::Dev => "dev",
            EnvironmentClass::Sandbox => "sandbox",
            EnvironmentClass::Unknown => "unknown",
        }
    }

    /// Case-insensitive parse of the canonical names and common aliases.
    /// Spaces, hyphens and underscores are ignored ("Non-Prod" == "nonprod").
    pub fn parse(s: &str) -> Option<Self> {
        let key: String = s
            .chars()
            .filter(|c| !matches!(c, ' ' | '-' | '_'))
            .collect::<String>()
            .to_ascii_lowercase();
        match key.as_str() {
            "prod" | "production" => Some(Self::Prod),
            "nonprod" | "nonproduction" => Some(Self::NonProd),
            "dev" | "development" => Some(Self::Dev),
            "sandbox" | "sbx" => Some(Self::Sandbox),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationRuleKind {
    /// Explicit subscription ID.
    Subscription,
    /// Resource group name (optionally within one subscription).
    ResourceGroup,
    /// Resource tag. With `tag_value` it is an equality match that yields `environment`.
    /// Without `tag_value` the tag's value is mapped (via `segment_map` or the built-in aliases).
    Tag,
    /// Regex (`pattern`) against the subscription's display name.
    SubscriptionNamePattern,
    /// Resource tag such as `1183.DEV` or `272.PROD.TX`: the first segment after the ID that
    /// is in `segment_map` gives the environment.
    TagSegment,
    /// Like `Tag`, but read from the resource group's tags. With a `segment_map` and no
    /// `tag_value`, the value is read segment-wise like `TagSegment`.
    ResourceGroupTag,
    /// Tokens of the resource name (split on `[^a-z0-9]+`), mapped via `segment_map` or the
    /// built-in aliases. With `pattern`, a token matching the regex yields `environment`.
    NameToken,
}

impl ClassificationRuleKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Subscription => "subscription",
            Self::ResourceGroup => "resource_group",
            Self::Tag => "tag",
            Self::SubscriptionNamePattern => "subscription_name_pattern",
            Self::TagSegment => "tag_segment",
            Self::ResourceGroupTag => "resource_group_tag",
            Self::NameToken => "name_token",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "subscription" => Self::Subscription,
            "resource_group" => Self::ResourceGroup,
            "tag" => Self::Tag,
            "subscription_name_pattern" => Self::SubscriptionNamePattern,
            "tag_segment" => Self::TagSegment,
            "resource_group_tag" => Self::ResourceGroupTag,
            "name_token" => Self::NameToken,
            _ => return None,
        })
    }
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
    /// Regex for `subscription_name_pattern` and `name_token`. Compiled case-insensitively.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Segment / value -> environment for `tag_segment`, `resource_group_tag`, `tag`, `name_token`.
    /// Keys are normalised (lowercase; spaces, `-` and `_` removed); values parse as environments.
    #[serde(default)]
    pub segment_map: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationSource {
    Subscription,
    SubscriptionName,
    ResourceGroup,
    ResourceTag,
    ResourceGroupTag,
    TagSegment,
    NameToken,
    #[default]
    None,
}

impl ClassificationSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Subscription => "subscription",
            Self::SubscriptionName => "subscription_name",
            Self::ResourceGroup => "resource_group",
            Self::ResourceTag => "resource_tag",
            Self::ResourceGroupTag => "resource_group_tag",
            Self::TagSegment => "tag_segment",
            Self::NameToken => "name_token",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    pub environment: EnvironmentClass,
    pub winning_rule_id: Option<String>,
    pub conflicting: bool,
    pub missing_tag: bool,
    pub reason: String,
    #[serde(default)]
    pub source: ClassificationSource,
}

impl ClassificationResult {
    /// Unknown environment with no winning rule.
    pub fn unclassified(reason: impl Into<String>, missing_tag: bool) -> Self {
        Self {
            environment: EnvironmentClass::Unknown,
            winning_rule_id: None,
            conflicting: false,
            missing_tag,
            reason: reason.into(),
            source: ClassificationSource::None,
        }
    }
}

/// Everything the classifier may read for one resource.
#[derive(Debug, Clone, Copy)]
pub struct ClassifyInput<'a> {
    pub obs: &'a ResourceObservation,
    /// Display name of the resource's subscription (from the `subscriptions` table).
    pub subscription_name: Option<&'a str>,
    /// Tags of the resource's resource group (from `resource_group_tags`).
    pub rg_tags: Option<&'a Value>,
}

impl<'a> ClassifyInput<'a> {
    pub fn resource_only(obs: &'a ResourceObservation) -> Self {
        Self {
            obs,
            subscription_name: None,
            rg_tags: None,
        }
    }
}

/// Resource-group tags captured from `resourcecontainers` (spec §4.6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceGroupTags {
    pub subscription_id: SubscriptionId,
    pub resource_group: String,
    pub tags: Value,
    pub observed_at: DateTime<Utc>,
}

/// Compatibility wrapper: classify from the resource observation alone (no subscription name,
/// no resource-group tags). Rules that need those inputs simply do not match.
/// A missing environment tag on a known production subscription must still resolve to Prod (AC-07).
pub fn classify_resource(
    obs: &ResourceObservation,
    rules: &[ClassificationRule],
) -> ClassificationResult {
    classify(&ClassifyInput::resource_only(obs), rules)
}

/// Full classification. Precedence is by `priority` (highest wins; ties keep rule order).
/// `conflicting` is set when matching rules disagree on the environment. Subscription-name
/// patterns are an ordered list (port of `Resolve-SubscriptionEnvironment`, first match wins),
/// so only the highest-priority matching name pattern takes part in the conflict check:
/// "Corp-Non-Prod" matching both the nonprod and the prod pattern is not a conflict.
pub fn classify(input: &ClassifyInput, rules: &[ClassificationRule]) -> ClassificationResult {
    let obs = input.obs;
    let missing_tag = obs
        .tags
        .as_object()
        .map(|t| !t.contains_key("Environment") && !t.contains_key("environment"))
        .unwrap_or(true);

    let mut matches: Vec<(&ClassificationRule, RuleMatch)> = rules
        .iter()
        .filter_map(|r| rule_match(r, input).map(|m| (r, m)))
        .collect();
    matches.sort_by_key(|(r, _)| std::cmp::Reverse(r.priority));

    // Keep only the first subscription-name pattern match (ordered-list semantics).
    let mut seen_name_pattern = false;
    matches.retain(|(r, _)| {
        if r.kind != ClassificationRuleKind::SubscriptionNamePattern {
            return true;
        }
        let keep = !seen_name_pattern;
        seen_name_pattern = true;
        keep
    });

    let Some((winner, wm)) = matches.first() else {
        return ClassificationResult::unclassified("no classification rule matched", missing_tag);
    };
    let conflicting = matches
        .iter()
        .any(|(_, m)| m.environment != wm.environment);

    ClassificationResult {
        // AC-07: a known Prod subscription keeps Prod even when the env tag is missing.
        environment: wm.environment.clone(),
        winning_rule_id: Some(winner.id.clone()),
        conflicting,
        missing_tag,
        reason: format!("rule {}: {}", winner.id, wm.detail),
        source: wm.source,
    }
}

/// Port of `Resolve-SubscriptionEnvironment` (patterns only): the environment of the
/// highest-priority `subscription_name_pattern` rule matching `name`, or None when the name
/// carries no environment token. Other rule kinds are ignored.
pub fn subscription_name_environment(
    name: &str,
    rules: &[ClassificationRule],
) -> Option<EnvironmentClass> {
    let mut candidates: Vec<&ClassificationRule> = rules
        .iter()
        .filter(|r| r.kind == ClassificationRuleKind::SubscriptionNamePattern)
        .collect();
    candidates.sort_by_key(|r| std::cmp::Reverse(r.priority));
    candidates.into_iter().find_map(|r| {
        let re = cached_regex(r.pattern.as_deref()?)?;
        re.is_match(name).then(|| r.environment.clone())
    })
}

struct RuleMatch {
    environment: EnvironmentClass,
    source: ClassificationSource,
    detail: String,
}

fn rule_match(rule: &ClassificationRule, input: &ClassifyInput) -> Option<RuleMatch> {
    let obs = input.obs;
    let fixed = |source, detail: String| {
        Some(RuleMatch {
            environment: rule.environment.clone(),
            source,
            detail,
        })
    };
    match rule.kind {
        ClassificationRuleKind::Subscription => {
            let sid = rule.subscription_id.as_ref()?;
            if sid != &obs.subscription_id {
                return None;
            }
            fixed(
                ClassificationSource::Subscription,
                format!("subscription {}", sid.as_str()),
            )
        }
        ClassificationRuleKind::ResourceGroup => {
            if let Some(s) = &rule.subscription_id {
                if s != &obs.subscription_id {
                    return None;
                }
            }
            let (want, have) = rule.resource_group.as_ref().zip(obs.resource_group.as_ref())?;
            if !want.eq_ignore_ascii_case(have) {
                return None;
            }
            fixed(
                ClassificationSource::ResourceGroup,
                format!("resource group {have}"),
            )
        }
        ClassificationRuleKind::Tag => tag_value_match(
            rule,
            &obs.tags,
            ClassificationSource::ResourceTag,
            "tag",
        ),
        ClassificationRuleKind::ResourceGroupTag => {
            let tags = input.rg_tags?;
            if rule.tag_value.is_none() && rule.segment_map.is_some() {
                let key = rule.tag_key.as_deref()?;
                let value = tag_str(tags, key)?;
                let (env, seg) = resolve_segments(value, rule.segment_map.as_ref())?;
                return Some(RuleMatch {
                    environment: env,
                    source: ClassificationSource::ResourceGroupTag,
                    detail: format!("resource group tag {key}={value} (segment {seg})"),
                });
            }
            tag_value_match(
                rule,
                tags,
                ClassificationSource::ResourceGroupTag,
                "resource group tag",
            )
        }
        ClassificationRuleKind::SubscriptionNamePattern => {
            let name = input.subscription_name?;
            let re = cached_regex(rule.pattern.as_deref()?)?;
            if !re.is_match(name) {
                return None;
            }
            fixed(
                ClassificationSource::SubscriptionName,
                format!("subscription name \"{name}\" matches pattern"),
            )
        }
        ClassificationRuleKind::TagSegment => {
            let key = rule.tag_key.as_deref()?;
            let value = tag_str(&obs.tags, key)?;
            let (env, seg) = resolve_segments(value, rule.segment_map.as_ref())?;
            Some(RuleMatch {
                environment: env,
                source: ClassificationSource::TagSegment,
                detail: format!("tag {key}={value} (segment {seg})"),
            })
        }
        ClassificationRuleKind::NameToken => {
            let lowered = obs.name.to_ascii_lowercase();
            let tokens = lowered
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|t| !t.is_empty());
            if let Some(p) = rule.pattern.as_deref() {
                let re = cached_regex(p)?;
                for t in tokens {
                    if re.is_match(t) {
                        return fixed(
                            ClassificationSource::NameToken,
                            format!("name token \"{t}\""),
                        );
                    }
                }
                return None;
            }
            for t in tokens {
                if let Some(env) = map_value(t, rule.segment_map.as_ref()) {
                    return Some(RuleMatch {
                        environment: env,
                        source: ClassificationSource::NameToken,
                        detail: format!("name token \"{t}\""),
                    });
                }
            }
            None
        }
    }
}

/// `tag` / `resource_group_tag` without segments: equality with `tag_value` gives the rule's
/// environment; without `tag_value` the value itself is mapped.
fn tag_value_match(
    rule: &ClassificationRule,
    tags: &Value,
    source: ClassificationSource,
    label: &str,
) -> Option<RuleMatch> {
    let key = rule.tag_key.as_deref()?;
    let value = tag_str(tags, key)?;
    match &rule.tag_value {
        Some(want) => {
            if !value.eq_ignore_ascii_case(want) {
                return None;
            }
            Some(RuleMatch {
                environment: rule.environment.clone(),
                source,
                detail: format!("{label} {key}={value}"),
            })
        }
        None => {
            let env = map_value(value.trim(), rule.segment_map.as_ref())?;
            Some(RuleMatch {
                environment: env,
                source,
                detail: format!("{label} {key}={value}"),
            })
        }
    }
}

/// Case-insensitive tag lookup (Azure tag names are case-insensitive). Exact key first.
pub fn tag_lookup<'v>(tags: &'v Value, name: &str) -> Option<&'v Value> {
    let o = tags.as_object()?;
    o.get(name)
        .or_else(|| o.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v))
}

fn tag_str<'v>(tags: &'v Value, name: &str) -> Option<&'v str> {
    tag_lookup(tags, name).and_then(|v| v.as_str())
}

fn normalise_key(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '_'))
        .collect::<String>()
        .to_lowercase()
}

/// Map a value through `map` (normalised keys) or, with no map, the built-in aliases.
fn map_value(value: &str, map: Option<&BTreeMap<String, String>>) -> Option<EnvironmentClass> {
    match map {
        Some(m) if !m.is_empty() => {
            let key = normalise_key(value);
            if key.is_empty() {
                return None;
            }
            m.iter()
                .find(|(k, _)| normalise_key(k) == key)
                .and_then(|(_, v)| EnvironmentClass::parse(v))
        }
        _ => EnvironmentClass::parse(value).filter(|e| *e != EnvironmentClass::Unknown),
    }
}

/// Port of `Resolve-BusinessServiceEnvironment`: split on `.`, skip segment 0 (the ID); for
/// each later segment try the normalised segment, then its first word. First hit wins.
fn resolve_segments(
    value: &str,
    map: Option<&BTreeMap<String, String>>,
) -> Option<(EnvironmentClass, String)> {
    for seg in value.split('.').skip(1) {
        if let Some(env) = map_value(seg, map) {
            return Some((env, seg.trim().to_string()));
        }
        let lowered = seg.trim().to_lowercase();
        if let Some(first) = lowered.split_whitespace().next() {
            if let Some(env) = map_value(first, map) {
                return Some((env, first.to_string()));
            }
        }
    }
    None
}

/// Compile a rule pattern the way the classifier does (case-insensitive, Rust `regex` syntax;
/// no lookarounds). Use this to validate on save.
pub fn compile_rule_pattern(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(1 << 20)
        .build()
        .map_err(|e| e.to_string())
}

fn cached_regex(pattern: &str) -> Option<Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(hit) = guard.get(pattern) {
        return hit.clone();
    }
    let compiled = compile_rule_pattern(pattern).ok();
    if guard.len() > 512 {
        guard.clear();
    }
    guard.insert(pattern.to_string(), compiled.clone());
    compiled
}

/// Validate a rule before it is saved. Returns a human-readable reason on failure.
pub fn validate_rule(rule: &ClassificationRule) -> Result<(), String> {
    if rule.id.trim().is_empty() {
        return Err("rule id is required".into());
    }
    if let Some(p) = &rule.pattern {
        compile_rule_pattern(p).map_err(|e| format!("rule {}: invalid pattern: {e}", rule.id))?;
    }
    if let Some(m) = &rule.segment_map {
        for (k, v) in m {
            if EnvironmentClass::parse(v).is_none() {
                return Err(format!(
                    "rule {}: segment_map value for '{k}' is not an environment: {v}",
                    rule.id
                ));
            }
        }
    }
    let need = |ok: bool, what: &str| -> Result<(), String> {
        if ok {
            Ok(())
        } else {
            Err(format!("rule {}: {} requires {what}", rule.id, rule.kind.as_str()))
        }
    };
    match rule.kind {
        ClassificationRuleKind::Subscription => need(rule.subscription_id.is_some(), "subscription_id"),
        ClassificationRuleKind::ResourceGroup => need(rule.resource_group.is_some(), "resource_group"),
        ClassificationRuleKind::Tag
        | ClassificationRuleKind::TagSegment
        | ClassificationRuleKind::ResourceGroupTag => {
            need(rule.tag_key.as_deref().is_some_and(|k| !k.trim().is_empty()), "tag_key")
        }
        ClassificationRuleKind::SubscriptionNamePattern => need(rule.pattern.is_some(), "pattern"),
        ClassificationRuleKind::NameToken => Ok(()),
    }
}

/// Default environment map for tag values and name tokens (port of `environment_map`).
pub fn default_environment_map() -> BTreeMap<String, String> {
    [
        ("dev", "dev"),
        ("development", "dev"),
        ("test", "nonprod"),
        ("staging", "nonprod"),
        ("stage", "nonprod"),
        ("uat", "nonprod"),
        ("qa", "nonprod"),
        ("nonprod", "nonprod"),
        ("prod", "prod"),
        ("production", "prod"),
        ("sandbox", "sandbox"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// Suggested default rules, highest priority first. Returned by
/// `GET /api/classification/suggested-rules` for the operator to review; never saved
/// automatically. Tag names are generic placeholders; org-specific names belong in the
/// operator profile (see docs/azcompliance-port/private-config.md).
pub fn suggested_rules() -> Vec<ClassificationRule> {
    let b = |pat: &str| format!("(?i)(^|[^a-z0-9]){pat}([^a-z0-9]|$)");
    let name_rule = |id: &str, pat: &str, env: EnvironmentClass, priority: i32| ClassificationRule {
        id: id.into(),
        kind: ClassificationRuleKind::SubscriptionNamePattern,
        subscription_id: None,
        resource_group: None,
        tag_key: None,
        tag_value: None,
        environment: env,
        priority,
        pattern: Some(b(pat)),
        segment_map: None,
    };
    let service_map: BTreeMap<String, String> = [
        ("prod", "prod"),
        ("production", "prod"),
        ("dr", "prod"),
        ("nonprod", "nonprod"),
        ("np", "nonprod"),
        ("test", "nonprod"),
        ("uat", "nonprod"),
        ("qa", "nonprod"),
        ("stage", "nonprod"),
        ("dev", "dev"),
        ("sandbox", "sandbox"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let tag_rule = |id: &str,
                    kind: ClassificationRuleKind,
                    key: &str,
                    map: BTreeMap<String, String>,
                    priority: i32| ClassificationRule {
        id: id.into(),
        kind,
        subscription_id: None,
        resource_group: None,
        tag_key: Some(key.into()),
        tag_value: None,
        environment: EnvironmentClass::Unknown,
        priority,
        pattern: None,
        segment_map: Some(map),
    };
    vec![
        name_rule("suggested-subname-nonprod", "non[-_ ]?prod(uction)?", EnvironmentClass::NonProd, 500),
        name_rule("suggested-subname-prod", "prod(uction)?", EnvironmentClass::Prod, 490),
        name_rule("suggested-subname-dev", "dev(elopment)?", EnvironmentClass::Dev, 480),
        name_rule(
            "suggested-subname-test",
            "(uat|stage|staging|test|qa|perf|performance)",
            EnvironmentClass::NonProd,
            470,
        ),
        name_rule("suggested-subname-sandbox", "sandbox", EnvironmentClass::Sandbox, 460),
        tag_rule(
            "suggested-tag-business-service",
            ClassificationRuleKind::TagSegment,
            "business-service",
            service_map.clone(),
            300,
        ),
        tag_rule(
            "suggested-rgtag-business-service",
            ClassificationRuleKind::ResourceGroupTag,
            "business-service",
            service_map,
            290,
        ),
        tag_rule(
            "suggested-tag-environment",
            ClassificationRuleKind::Tag,
            "Environment",
            default_environment_map(),
            280,
        ),
        tag_rule(
            "suggested-rgtag-environment",
            ClassificationRuleKind::ResourceGroupTag,
            "Environment",
            default_environment_map(),
            270,
        ),
        ClassificationRule {
            id: "suggested-name-token".into(),
            kind: ClassificationRuleKind::NameToken,
            subscription_id: None,
            resource_group: None,
            tag_key: None,
            tag_value: None,
            environment: EnvironmentClass::Unknown,
            priority: 100,
            pattern: None,
            segment_map: Some(default_environment_map()),
        },
    ]
}

/// Ownership / routing tag names (operator profile settings; spec §4.6).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct OwnershipConfig {
    #[serde(default)]
    pub application_tag: Option<String>,
    #[serde(default)]
    pub application_id_tag: Option<String>,
    #[serde(default)]
    pub owner_tag: Option<String>,
    #[serde(default)]
    pub line_of_business_tag: Option<String>,
    /// Regex whose first match is the rolled-up LOB ID, e.g. `^\d+` turns `11.3` into `11`.
    #[serde(default)]
    pub lob_rollup_pattern: Option<String>,
    /// Rolled-up LOB ID -> display name.
    #[serde(default)]
    pub lob_names: BTreeMap<String, String>,
    /// Values treated as empty in addition to `undefined` (case-insensitive).
    #[serde(default)]
    pub placeholder_values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Ownership {
    pub application: Option<String>,
    pub application_id: Option<String>,
    pub owner: Option<String>,
    pub line_of_business: Option<String>,
    pub line_of_business_name: Option<String>,
    /// True when any value came from the resource group's tags.
    pub from_resource_group: bool,
}

/// Validate an ownership config before it is saved (the rollup pattern must compile).
pub fn validate_ownership_config(cfg: &OwnershipConfig) -> Result<(), String> {
    if let Some(p) = &cfg.lob_rollup_pattern {
        Regex::new(p).map_err(|e| format!("lob_rollup_pattern: {e}"))?;
    }
    Ok(())
}

/// Port of `Get-CleanTagValue`: trim; `undefined` and configured placeholders count as empty.
fn clean_tag_value(v: Option<&Value>, cfg: &OwnershipConfig) -> Option<String> {
    let text = match v? {
        Value::String(s) => s.trim().to_string(),
        Value::Null => return None,
        other => other.to_string().trim().to_string(),
    };
    if text.is_empty()
        || text.eq_ignore_ascii_case("undefined")
        || cfg
            .placeholder_values
            .iter()
            .any(|p| p.trim().eq_ignore_ascii_case(&text))
    {
        return None;
    }
    Some(text)
}

/// Port of `Get-OwnershipValue`: the resource's tag, else the resource group's tag.
fn ownership_value(
    input: &ClassifyInput,
    tag: Option<&str>,
    cfg: &OwnershipConfig,
) -> (Option<String>, bool) {
    let Some(tag) = tag.map(str::trim).filter(|t| !t.is_empty()) else {
        return (None, false);
    };
    if let Some(v) = clean_tag_value(tag_lookup(&input.obs.tags, tag), cfg) {
        return (Some(v), false);
    }
    let from_rg = input
        .rg_tags
        .and_then(|t| clean_tag_value(tag_lookup(t, tag), cfg));
    let hit = from_rg.is_some();
    (from_rg, hit)
}

/// Routing values for a resource. Applied at read time, so a config change needs no rescan.
pub fn derive_ownership(input: &ClassifyInput, cfg: &OwnershipConfig) -> Ownership {
    let (application, a_rg) = ownership_value(input, cfg.application_tag.as_deref(), cfg);
    let (application_id, i_rg) = ownership_value(input, cfg.application_id_tag.as_deref(), cfg);
    let (owner, o_rg) = ownership_value(input, cfg.owner_tag.as_deref(), cfg);
    let (lob_raw, l_rg) = ownership_value(input, cfg.line_of_business_tag.as_deref(), cfg);

    let line_of_business = lob_raw.map(|raw| {
        cfg.lob_rollup_pattern
            .as_deref()
            .and_then(|p| Regex::new(p).ok())
            .and_then(|re| re.find(&raw).map(|m| m.as_str().to_string()))
            .filter(|s| !s.is_empty())
            .unwrap_or(raw)
    });
    let line_of_business_name = line_of_business
        .as_ref()
        .and_then(|id| cfg.lob_names.get(id).cloned());

    Ownership {
        application,
        application_id,
        owner,
        line_of_business,
        line_of_business_name,
        from_resource_group: a_rg || i_rg || o_rg || l_rg,
    }
}
