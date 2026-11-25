use crate::evaluator::{compile_pattern, judge_control, ControlJudgement};
use crate::kinds::{builtin_resource_kinds, ResourceKinds};
use anyhow::{anyhow, Result};
use estatetrace_core::{EnvironmentClass, GapCategory, Severity};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

// ---------------------------------------------------------------------------
// Pack schema (spec §4.1; additive, schema_version stays 1)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPack {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub revision: String,
    pub owner: Option<String>,
    pub controls: Vec<Control>,
    #[serde(default)]
    pub example_cases: Vec<ExampleCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub source: ControlSource,
    pub owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_from: Option<String>,
    pub severity: String,
    #[serde(default)]
    pub applies_to: AppliesTo,
    /// Legacy single check: one target with `resource_type: "*"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<Check>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<Target>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_evaluated: Option<NotEvaluated>,
    #[serde(default)]
    pub mode: ControlMode,
    #[serde(default)]
    pub lane: Lane,
    #[serde(default)]
    pub status: ControlStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_remediation: Option<AzureRemediation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_requirements: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_period_hours: Option<u64>,
    /// Kept for older packs; treated as `not_evaluated: {category: outside_azure}`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub manual: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judges: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlSource {
    pub document: String,
    pub revision: String,
    pub clause: String,
}

/// Where a control applies. Accepts the legacy `environment: prod` and `environments: [..]`.
/// `None` means every environment. An `Unknown` resource environment is always in scope.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "AppliesToRaw")]
pub struct AppliesTo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environments: Option<Vec<EnvironmentClass>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
}

#[derive(Deserialize)]
struct AppliesToRaw {
    #[serde(default)]
    environment: Option<OneOrMany>,
    #[serde(default)]
    environments: Option<OneOrMany>,
    #[serde(default)]
    capability: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl TryFrom<AppliesToRaw> for AppliesTo {
    type Error = String;

    fn try_from(raw: AppliesToRaw) -> std::result::Result<Self, Self::Error> {
        let mut names: Vec<String> = Vec::new();
        let mut any_given = false;
        for v in [raw.environment, raw.environments].into_iter().flatten() {
            any_given = true;
            match v {
                OneOrMany::One(s) => names.push(s),
                OneOrMany::Many(list) => names.extend(list),
            }
        }
        let mut envs: Vec<EnvironmentClass> = Vec::new();
        let mut all = false;
        for n in &names {
            let key = n.trim().to_ascii_lowercase();
            if key == "all" || key == "any" || key == "*" {
                all = true;
                continue;
            }
            let env = EnvironmentClass::parse(n)
                .ok_or_else(|| format!("unknown environment '{n}' in applies_to"))?;
            if !envs.contains(&env) {
                envs.push(env);
            }
        }
        let environments = if !any_given || all || envs.is_empty() {
            None
        } else {
            Some(envs)
        };
        Ok(AppliesTo {
            environments,
            capability: raw.capability,
        })
    }
}

impl AppliesTo {
    /// Invariant 3: outside the list is inapplicable; `Unknown` is always in scope.
    pub fn includes(&self, env: &EnvironmentClass) -> bool {
        match &self.environments {
            None => true,
            Some(_) if *env == EnvironmentClass::Unknown => true,
            Some(list) => list.contains(env),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<Leaf>,
    pub check: Check,
}

/// One leaf, or `all_of` several. Serialized untagged: `{all_of: [...]}` or a leaf map.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
// Shape fixed by spec §4.1; checks are few and long-lived, so the unboxed leaf costs nothing.
#[allow(clippy::large_enum_variant)]
pub enum Check {
    AllOf { all_of: Vec<Leaf> },
    Leaf(Leaf),
}

impl<'de> Deserialize<'de> for Check {
    // Hand-rolled instead of `untagged` so a bad leaf reports its real error
    // (for example the unknown operator) rather than "did not match any variant".
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        if let Some(parts) = v.get("all_of") {
            let all_of: Vec<Leaf> =
                serde_json::from_value(parts.clone()).map_err(serde::de::Error::custom)?;
            return Ok(Check::AllOf { all_of });
        }
        let leaf: Leaf = serde_json::from_value(v).map_err(serde::de::Error::custom)?;
        Ok(Check::Leaf(leaf))
    }
}

impl Check {
    pub fn leaves(&self) -> &[Leaf] {
        match self {
            Check::AllOf { all_of } => all_of,
            Check::Leaf(l) => std::slice::from_ref(l),
        }
    }

    /// True when every leaf needs the deep tier (invariant 4).
    pub fn is_deep_only(&self) -> bool {
        let leaves = self.leaves();
        !leaves.is_empty()
            && leaves
                .iter()
                .all(|l| l.evidence_source == EvidenceSource::Deep)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Leaf {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub field: String,
    pub operator: Operator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_absent: Option<Value>,
    /// `ordinal_gte`: allowed values, weakest first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<Vec<String>>,
    /// `length_between` bounds (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,
    /// `count_where_*`: which array items to count.
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<WhereClause>,
    /// `matches`: patterns ignore case unless this is true.
    #[serde(default, skip_serializing_if = "is_false")]
    pub case_sensitive: bool,
    /// Values reported beside a failure, e.g. `[firewall default action: Deny]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<ContextField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "EvidenceSource::is_arg")]
    pub evidence_source: EvidenceSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Exists,
    Nonempty,
    Equals,
    NotEquals,
    In,
    NotIn,
    Matches,
    LengthBetween,
    CountEq,
    CountGte,
    CountWhereEq,
    CountWhereGte,
    OrdinalGte,
    Gte,
    Lte,
}

impl Operator {
    pub fn as_str(&self) -> &'static str {
        match self {
            Operator::Exists => "exists",
            Operator::Nonempty => "nonempty",
            Operator::Equals => "equals",
            Operator::NotEquals => "not_equals",
            Operator::In => "in",
            Operator::NotIn => "not_in",
            Operator::Matches => "matches",
            Operator::LengthBetween => "length_between",
            Operator::CountEq => "count_eq",
            Operator::CountGte => "count_gte",
            Operator::CountWhereEq => "count_where_eq",
            Operator::CountWhereGte => "count_where_gte",
            Operator::OrdinalGte => "ordinal_gte",
            Operator::Gte => "gte",
            Operator::Lte => "lte",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// The resource's own Resource Graph row.
    #[default]
    Arg,
    /// A joined object under `join.<name>` (Phase 5).
    #[serde(alias = "arg-join", alias = "arg_join")]
    Join,
    /// Per-resource ARM calls, not collected: such leaves are coverage gaps.
    Deep,
}

impl EvidenceSource {
    fn is_arg(&self) -> bool {
        *self == EvidenceSource::Arg
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhereClause {
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextField {
    pub label: String,
    pub field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotEvaluated {
    pub category: GapCategory,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlMode {
    #[default]
    Scored,
    Flag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    #[default]
    Security,
    Hygiene,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    #[default]
    Provisional,
    Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureRemediation {
    pub effect: String,
    #[serde(default)]
    pub when: Option<String>,
    #[serde(default)]
    pub inherit_from: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleCase {
    pub control_id: String,
    pub name: String,
    pub resource: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentClass>,
    pub expected: String,
}

/// A borrowed view of one target; a legacy `check` becomes `resource_type: "*"`.
#[derive(Debug, Clone, Copy)]
pub struct TargetRef<'a> {
    pub resource_kind: Option<&'a str>,
    pub resource_type: Option<&'a str>,
    pub filter: Option<&'a Leaf>,
    pub check: &'a Check,
}

impl Control {
    /// Targets to evaluate: explicit `targets`, else the legacy `check` on every type.
    pub fn effective_targets(&self) -> Vec<TargetRef<'_>> {
        if !self.targets.is_empty() {
            return self
                .targets
                .iter()
                .map(|t| TargetRef {
                    resource_kind: t.resource_kind.as_deref(),
                    resource_type: t.resource_type.as_deref(),
                    filter: t.filter.as_ref(),
                    check: &t.check,
                })
                .collect();
        }
        match &self.check {
            Some(check) => vec![TargetRef {
                resource_kind: None,
                resource_type: Some("*"),
                filter: None,
                check,
            }],
            None => Vec::new(),
        }
    }

    /// `not_evaluated`, or the equivalent for a legacy `manual: true` control.
    pub fn effective_not_evaluated(&self) -> Option<NotEvaluated> {
        if let Some(ne) = &self.not_evaluated {
            return Some(ne.clone());
        }
        if self.manual {
            let note = if self.evidence_requirements.is_empty() {
                "Requires human evidence; Azure may only supply partial data.".to_string()
            } else {
                self.evidence_requirements.join("; ")
            };
            return Some(NotEvaluated {
                category: GapCategory::OutsideAzure,
                note,
            });
        }
        None
    }

    /// False when the control yields only coverage gaps: `not_evaluated`/`manual`, or every
    /// target deep-only.
    pub fn is_evaluable(&self) -> bool {
        if self.effective_not_evaluated().is_some() {
            return false;
        }
        let targets = self.effective_targets();
        !targets.is_empty() && targets.iter().any(|t| !t.check.is_deep_only())
    }

    /// Field of the first leaf (used by export to find the tag a `modify` control targets).
    pub fn primary_field(&self) -> Option<&str> {
        self.effective_targets()
            .first()
            .and_then(|t| t.check.leaves().first())
            .map(|l| l.field.as_str())
    }
}

// ---------------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LintSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintIssue {
    pub severity: LintSeverity,
    pub control_id: Option<String>,
    pub message: String,
}

impl std::fmt::Display for LintIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.control_id {
            Some(id) => write!(f, "control {id}: {}", self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

pub fn parse_pack_yaml(text: &str) -> Result<PolicyPack> {
    let raw: Value = serde_yaml::from_str(text)?;
    let pack = pack_from_value(raw)?;
    validate_pack(&pack, builtin_resource_kinds())?;
    Ok(pack)
}

pub fn parse_pack_json(text: &str) -> Result<PolicyPack> {
    let raw: Value = serde_json::from_str(text)?;
    let pack = pack_from_value(raw)?;
    validate_pack(&pack, builtin_resource_kinds())?;
    Ok(pack)
}

/// Deserialize a pack; when one control is malformed, the error names it.
fn pack_from_value(raw: Value) -> Result<PolicyPack> {
    match serde_json::from_value::<PolicyPack>(raw.clone()) {
        Ok(p) => Ok(p),
        Err(e) => {
            if let Some(controls) = raw.get("controls").and_then(|c| c.as_array()) {
                for (i, c) in controls.iter().enumerate() {
                    if let Err(ce) = serde_json::from_value::<Control>(c.clone()) {
                        let id = c
                            .get("id")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                            .unwrap_or_else(|| format!("#{}", i + 1));
                        return Err(anyhow!("control {id}: {ce}"));
                    }
                }
            }
            Err(anyhow!("policy pack: {e}"))
        }
    }
}

/// Check a parsed pack. Error issues make this return `Err` (naming each control);
/// otherwise the warnings are returned.
pub fn validate_pack(pack: &PolicyPack, kinds: &ResourceKinds) -> Result<Vec<LintIssue>> {
    let issues = lint_pack(pack, kinds);
    let errors: Vec<String> = issues
        .iter()
        .filter(|i| i.severity == LintSeverity::Error)
        .map(|i| i.to_string())
        .collect();
    if !errors.is_empty() {
        return Err(anyhow!(errors.join("; ")));
    }
    Ok(issues)
}

/// Every lint issue (errors and warnings) without failing.
pub fn lint_pack(pack: &PolicyPack, kinds: &ResourceKinds) -> Vec<LintIssue> {
    let mut out = Vec::new();
    let mut err = |cid: Option<&str>, msg: String| {
        out.push(LintIssue {
            severity: LintSeverity::Error,
            control_id: cid.map(str::to_string),
            message: msg,
        })
    };
    if pack.schema_version != 1 {
        err(None, format!("unsupported schema_version {}", pack.schema_version));
    }
    if pack.id.is_empty() || pack.revision.is_empty() {
        err(None, "pack id and revision are required".into());
    }
    let mut seen = HashSet::new();
    let mut warnings = Vec::new();
    for c in &pack.controls {
        let cid = Some(c.id.as_str());
        if c.id.is_empty() {
            err(None, "control id required".into());
            continue;
        }
        if !seen.insert(c.id.as_str()) {
            err(cid, "duplicate control id".into());
        }
        if c.owner.is_empty() {
            err(cid, "missing owner".into());
        }
        if Severity::parse(&c.severity).is_none() {
            err(cid, format!("invalid severity '{}'", c.severity));
        }
        if c.check.is_some() && !c.targets.is_empty() {
            err(cid, "set either check or targets, not both".into());
        }
        let gap = c.effective_not_evaluated();
        if c.check.is_none() && c.targets.is_empty() && gap.is_none() {
            err(cid, "needs targets, check or not_evaluated".into());
        }
        if let Some(ne) = &c.not_evaluated {
            if ne.note.trim().is_empty() {
                warnings.push((c.id.clone(), "not_evaluated has no note".to_string()));
            }
        }
        let leaf_field_optional = gap.is_some();
        if let Some(check) = &c.check {
            for l in check.leaves() {
                for m in lint_leaf(l, leaf_field_optional) {
                    err(cid, m);
                }
            }
        }
        for (i, t) in c.targets.iter().enumerate() {
            let tn = i + 1;
            match (&t.resource_kind, &t.resource_type) {
                (Some(_), Some(_)) => err(
                    cid,
                    format!("target {tn}: set resource_kind or resource_type, not both"),
                ),
                (None, None) => err(cid, format!("target {tn}: needs resource_kind or resource_type")),
                (Some(k), None) => {
                    if kinds.resolve(k).is_none() {
                        err(cid, format!("target {tn}: unknown resource_kind '{k}'"));
                    }
                }
                (None, Some(rt)) => {
                    if rt.trim().is_empty() {
                        err(cid, format!("target {tn}: empty resource_type"));
                    }
                }
            }
            if let Some(f) = &t.filter {
                for m in lint_leaf(f, false) {
                    err(cid, format!("target {tn} filter: {m}"));
                }
            }
            if let Check::AllOf { all_of } = &t.check {
                if all_of.is_empty() {
                    err(cid, format!("target {tn}: all_of is empty"));
                }
            }
            for l in t.check.leaves() {
                for m in lint_leaf(l, leaf_field_optional) {
                    err(cid, format!("target {tn}: {m}"));
                }
            }
        }
    }
    for ex in &pack.example_cases {
        if !pack.controls.iter().any(|c| c.id == ex.control_id) {
            err(
                None,
                format!("example '{}' references missing control {}", ex.name, ex.control_id),
            );
        }
        if !matches!(
            ex.expected.as_str(),
            "pass" | "fail" | "unknown" | "inapplicable"
        ) {
            err(
                Some(ex.control_id.as_str()),
                format!("example '{}' has invalid expected '{}'", ex.name, ex.expected),
            );
        }
    }
    for (cid, msg) in warnings {
        out.push(LintIssue {
            severity: LintSeverity::Warning,
            control_id: Some(cid),
            message: msg,
        });
    }
    out
}

/// Operator-argument checks for one leaf. Every pattern must compile (invariant 16).
fn lint_leaf(l: &Leaf, field_optional: bool) -> Vec<String> {
    let mut m = Vec::new();
    let op = l.operator.as_str();
    if l.field.trim().is_empty() && !field_optional {
        m.push(format!("{op} check has no field"));
    }
    let is_count = |v: &Option<Value>| v.as_ref().and_then(|v| v.as_u64()).is_some();
    match l.operator {
        Operator::Exists | Operator::Nonempty => {}
        Operator::Equals | Operator::NotEquals => {
            if l.value.is_none() {
                m.push(format!("{} on {} needs a value", op, l.field));
            }
        }
        Operator::In | Operator::NotIn => {
            if !matches!(l.value, Some(Value::Array(_))) {
                m.push(format!("{} on {} needs a list value", op, l.field));
            }
        }
        Operator::Matches => match l.value.as_ref().and_then(|v| v.as_str()) {
            None => m.push(format!("matches on {} needs a pattern value", l.field)),
            Some(p) => {
                if let Err(e) = compile_pattern(p, l.case_sensitive) {
                    m.push(format!(
                        "pattern '{p}' on {} is not a supported regular expression: {}",
                        l.field,
                        first_line(&e.to_string())
                    ));
                }
            }
        },
        Operator::LengthBetween => match (l.min, l.max) {
            (Some(a), Some(b)) if a <= b => {}
            (Some(_), Some(_)) => m.push(format!("length_between on {}: min exceeds max", l.field)),
            _ => m.push(format!("length_between on {} needs min and max", l.field)),
        },
        Operator::CountEq | Operator::CountGte => {
            if !is_count(&l.value) {
                m.push(format!("{} on {} needs a whole-number value", op, l.field));
            }
        }
        Operator::CountWhereEq | Operator::CountWhereGte => {
            if !is_count(&l.value) {
                m.push(format!("{} on {} needs a whole-number value", op, l.field));
            }
            match &l.where_ {
                None => m.push(format!("{} on {} needs a where clause", op, l.field)),
                Some(w) => {
                    let set = [w.equals.is_some(), w.empty.is_some(), w.matches.is_some()]
                        .iter()
                        .filter(|b| **b)
                        .count();
                    if w.field.trim().is_empty() {
                        m.push(format!("{} on {}: where has no field", op, l.field));
                    }
                    if set != 1 {
                        m.push(format!(
                            "{} on {}: where needs exactly one of equals, empty, matches",
                            op, l.field
                        ));
                    }
                    if let Some(p) = &w.matches {
                        if let Err(e) = compile_pattern(p, false) {
                            m.push(format!(
                                "where pattern '{p}' on {} is not a supported regular expression: {}",
                                l.field,
                                first_line(&e.to_string())
                            ));
                        }
                    }
                }
            }
        }
        Operator::OrdinalGte => {
            let order: Vec<String> = l
                .order
                .clone()
                .unwrap_or_default()
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect();
            if order.is_empty() {
                m.push(format!("ordinal_gte on {} needs an order list", l.field));
            }
            let in_order = |v: &Value| order.contains(&crate::evaluator::display(v).to_ascii_lowercase());
            match &l.value {
                None => m.push(format!("ordinal_gte on {} needs a value", l.field)),
                Some(v) if !order.is_empty() && !in_order(v) => m.push(format!(
                    "ordinal_gte on {}: value '{}' is not in order",
                    l.field,
                    crate::evaluator::display(v)
                )),
                _ => {}
            }
            if let Some(d) = &l.when_absent {
                if !order.is_empty() && !in_order(d) {
                    m.push(format!(
                        "ordinal_gte on {}: when_absent '{}' is not in order",
                        l.field,
                        crate::evaluator::display(d)
                    ));
                }
            }
        }
        Operator::Gte | Operator::Lte => {
            if crate::evaluator::as_number(l.value.as_ref()).is_none() {
                m.push(format!("{} on {} needs a numeric value", op, l.field));
            }
        }
    }
    for c in &l.context {
        if c.label.trim().is_empty() || c.field.trim().is_empty() {
            m.push(format!("context on {} needs a label and a field", l.field));
        }
    }
    m
}

fn first_line(s: &str) -> String {
    // regex errors are multi-line with a caret diagram; keep the summary.
    s.lines()
        .rev()
        .find(|l| l.trim_start().starts_with("error:"))
        .map(|l| l.trim().trim_start_matches("error:").trim().to_string())
        .unwrap_or_else(|| s.lines().next().unwrap_or("").to_string())
}

// ---------------------------------------------------------------------------
// Coverage report and example cases
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub pack_id: String,
    pub revision: String,
    pub clauses: Vec<ClauseCoverage>,
    /// Controls not evaluated per resource, counted by gap category.
    #[serde(default)]
    pub not_evaluated: BTreeMap<GapCategory, usize>,
    #[serde(default)]
    pub controls_evaluated: usize,
    #[serde(default)]
    pub controls_total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClauseCoverage {
    pub control_id: String,
    pub clause: String,
    /// `automated_check`, `manual_evidence` (outside Azure) or `not_evaluated`.
    pub automation: String,
    pub notes: String,
    #[serde(default)]
    pub category: Option<GapCategory>,
    #[serde(default)]
    pub status: ControlStatus,
    #[serde(default)]
    pub lane: Lane,
}

pub fn coverage_report(pack: &PolicyPack) -> CoverageReport {
    let mut not_evaluated: BTreeMap<GapCategory, usize> = BTreeMap::new();
    let mut evaluated = 0;
    let clauses = pack
        .controls
        .iter()
        .map(|c| {
            let gap = c.effective_not_evaluated();
            let (automation, notes, category) = if let Some(ne) = gap {
                let automation = if c.manual || ne.category == GapCategory::OutsideAzure {
                    "manual_evidence"
                } else {
                    "not_evaluated"
                };
                (automation.to_string(), ne.note, Some(ne.category))
            } else if !c.is_evaluable() {
                (
                    "not_evaluated".to_string(),
                    "Needs the deep collection tier, which is not collected yet".to_string(),
                    Some(GapCategory::DeepCollection),
                )
            } else {
                ("automated_check".to_string(), describe_targets(c), None)
            };
            match category {
                Some(cat) => *not_evaluated.entry(cat).or_default() += 1,
                None => evaluated += 1,
            }
            ClauseCoverage {
                control_id: c.id.clone(),
                clause: format!(
                    "{} {} §{}",
                    c.source.document, c.source.revision, c.source.clause
                ),
                automation,
                notes,
                category,
                status: c.status,
                lane: c.lane,
            }
        })
        .collect();
    CoverageReport {
        pack_id: pack.id.clone(),
        revision: pack.revision.clone(),
        clauses,
        not_evaluated,
        controls_evaluated: evaluated,
        controls_total: pack.controls.len(),
    }
}

fn describe_targets(c: &Control) -> String {
    if c.targets.is_empty() {
        if let Some(Check::Leaf(l)) = &c.check {
            return format!("operator={} field={}", l.operator.as_str(), l.field);
        }
    }
    c.effective_targets()
        .iter()
        .map(|t| {
            let on = t.resource_kind.or(t.resource_type).unwrap_or("*");
            let what = match t.check {
                Check::Leaf(l) => format!("{} {}", l.operator.as_str(), l.field),
                Check::AllOf { all_of } => format!("all_of {} checks", all_of.len()),
            };
            format!("{on}: {what}")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleResult {
    pub control_id: String,
    pub name: String,
    pub ok: bool,
    pub expected: String,
    /// `pass|fail|unknown|inapplicable`, or `not_selected` when no target selects the example.
    pub got: String,
    pub detail: String,
    pub assumed_default: bool,
}

/// Run every example case. An example for a control that is not evaluated per resource
/// (`not_evaluated` or `manual`) yields `unknown`.
pub fn run_example_cases(pack: &PolicyPack, kinds: &ResourceKinds) -> Result<Vec<ExampleResult>> {
    let mut results = Vec::new();
    for ex in &pack.example_cases {
        let control = pack
            .controls
            .iter()
            .find(|c| c.id == ex.control_id)
            .ok_or_else(|| anyhow!("example references missing control {}", ex.control_id))?;
        let env = ex.environment.clone().unwrap_or(EnvironmentClass::Unknown);
        let (got, detail, assumed) = match judge_control(control, &ex.resource, &env, kinds) {
            ControlJudgement::NotEvaluated(ne) => (
                "unknown".to_string(),
                format!("not evaluated ({}): {}", ne.category.as_str(), ne.note),
                false,
            ),
            ControlJudgement::NotSelected => (
                "not_selected".to_string(),
                "no target of the control selects this resource".to_string(),
                false,
            ),
            ControlJudgement::Evaluated { result, .. } => (
                result.outcome.as_str().to_string(),
                result.detail,
                result.assumed_default,
            ),
        };
        results.push(ExampleResult {
            control_id: ex.control_id.clone(),
            name: ex.name.clone(),
            ok: got == ex.expected,
            expected: ex.expected.clone(),
            got,
            detail,
            assumed_default: assumed,
        });
    }
    Ok(results)
}

pub fn pilot_pack() -> PolicyPack {
    parse_pack_yaml(include_str!("../../../kits/policy-authoring/examples/pilot_pack.yaml"))
        .expect("pilot pack")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_to_accepts_legacy_and_list() {
        let legacy: AppliesTo = serde_yaml::from_str("{ environment: prod, capability: supports_tags }").unwrap();
        assert_eq!(legacy.environments, Some(vec![EnvironmentClass::Prod]));
        assert_eq!(legacy.capability.as_deref(), Some("supports_tags"));
        let list: AppliesTo = serde_yaml::from_str("{ environments: [prod, Non-Prod] }").unwrap();
        assert_eq!(
            list.environments,
            Some(vec![EnvironmentClass::Prod, EnvironmentClass::NonProd])
        );
        let empty: AppliesTo = serde_yaml::from_str("{}").unwrap();
        assert_eq!(empty.environments, None);
        assert!(serde_yaml::from_str::<AppliesTo>("{ environment: moon }").is_err());
        // Round trip through JSON (how activated packs are stored).
        let json = serde_json::to_value(&list).unwrap();
        let back: AppliesTo = serde_json::from_value(json).unwrap();
        assert_eq!(back, list);
    }

    #[test]
    fn pilot_pack_round_trips_through_json() {
        let pack = pilot_pack();
        let json = serde_json::to_value(&pack).unwrap();
        let back: PolicyPack = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(&back).unwrap(), json);
        assert!(pack.controls.iter().all(|c| c.status == ControlStatus::Verified));
    }

    #[test]
    fn unknown_operator_names_the_control() {
        let yaml = r#"
schema_version: 1
id: T
name: T
revision: "1"
controls:
  - id: BAD-OP
    source: { document: d, revision: "1", clause: "1" }
    owner: o
    severity: low
    applies_to: {}
    check: { field: location, operator: sounds_like, value: x }
"#;
        let err = parse_pack_yaml(yaml).unwrap_err().to_string();
        assert!(err.contains("BAD-OP"), "{err}");
        assert!(err.contains("sounds_like"), "{err}");
    }
}
