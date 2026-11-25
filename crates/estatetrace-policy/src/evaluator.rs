//! Evaluator v2: kind-targeted controls, the azcompliance operator set, `when_absent`,
//! `context`, `all_of` and coverage gaps (spec §3.1, §4.3; port of AzCompliance.Evaluate.psm1).

use crate::joins::JoinIndex;
use crate::kinds::{builtin_resource_kinds, ResourceKinds};
use crate::pack::{Check, Control, EvidenceSource, Leaf, NotEvaluated, Operator, PolicyPack, TargetRef, WhereClause};
use estatetrace_core::{
    CoverageGap, EnvironmentClass, EvalOutcome, Evaluation, GapCategory, ResourceObservation, Severity,
};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

const ASSUMED_SUFFIX: &str = " (property absent; Azure default assumed)";
const DEEP_GAP_NOTE: &str = "Needs the deep collection tier, which is not collected yet";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub outcome: EvalOutcome,
    pub detail: String,
    pub assumed_default: bool,
}

impl CheckResult {
    fn pass() -> Self {
        Self {
            outcome: EvalOutcome::Pass,
            detail: String::new(),
            assumed_default: false,
        }
    }
    fn fail(detail: String) -> Self {
        Self {
            outcome: EvalOutcome::Fail,
            detail,
            assumed_default: false,
        }
    }
    fn unknown(detail: String) -> Self {
        Self {
            outcome: EvalOutcome::Unknown,
            detail,
            assumed_default: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackEvaluation {
    pub evaluations: Vec<Evaluation>,
    pub coverage_gaps: Vec<CoverageGap>,
}

pub struct EvalContext<'a> {
    pub environment: &'a EnvironmentClass,
    pub kinds: &'a ResourceKinds,
    pub joins: &'a JoinIndex,
}

// ---------------------------------------------------------------------------
// Resource view and field access
// ---------------------------------------------------------------------------

/// The JSON object checks read: ARG row fields plus `join.*` when joins supply them.
pub fn resource_view(obs: &ResourceObservation, joins: &JoinIndex) -> Value {
    let mut view = json!({
        "id": obs.resource_id.as_str(),
        "subscriptionId": obs.subscription_id.as_str(),
        "tags": obs.tags,
        "properties": obs.properties,
        "location": obs.location,
        "type": obs.resource_type,
        "resourceGroup": obs.resource_group,
        "name": obs.name,
    });
    // Top-level ARG fields (kind, sku, identity, ...) sit beside `properties`, as in Resource Graph.
    if let (Some(meta), Some(v)) = (obs.arm_meta.as_object(), view.as_object_mut()) {
        for (k, val) in meta {
            v.entry(k.clone()).or_insert_with(|| val.clone());
        }
    }
    if let Some(j) = joins.view_for(obs) {
        view["join"] = j;
    }
    view
}

/// Look up a dotted path. Keys match exactly first, then case-insensitively.
/// `tags.<rest>` treats `<rest>` as one key, because tag names may contain dots.
/// A segment that crosses a non-object is missing (never panics).
pub fn field_value<'a>(resource: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(tag) = path.strip_prefix("tags.") {
        let tags = get_key(resource, "tags")?;
        return get_key(tags, tag);
    }
    let mut cur = resource;
    for part in path.split('.') {
        cur = get_key(cur, part)?;
    }
    Some(cur)
}

fn get_key<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Object(map) => map.get(key).or_else(|| {
            map.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v)
        }),
        _ => None,
    }
}

/// How a value reads in detail text (PowerShell `[string]` semantics, lowercase booleans).
pub(crate) fn display(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

fn shown(v: &Value) -> String {
    let s = display(v);
    if s.is_empty() {
        "(empty)".into()
    } else {
        s
    }
}

pub(crate) fn as_number(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

/// Strings compare case-insensitively; numbers compare by value (1 == 1.0); otherwise exact.
fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) => x.eq_ignore_ascii_case(y),
        (Value::Number(x), Value::Number(y)) => match (x.as_f64(), y.as_f64()) {
            (Some(p), Some(q)) => p == q,
            _ => x == y,
        },
        _ => a == b,
    }
}

// ---------------------------------------------------------------------------
// Regex cache
// ---------------------------------------------------------------------------

/// Compile a `matches` pattern with the Rust `regex` dialect. Lookaround and backreferences are
/// rejected with an error, never a panic.
pub fn compile_pattern(pattern: &str, case_sensitive: bool) -> Result<Regex, regex::Error> {
    static CACHE: OnceLock<Mutex<HashMap<(bool, String), Regex>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (case_sensitive, pattern.to_string());
    if let Ok(guard) = cache.lock() {
        if let Some(r) = guard.get(&key) {
            return Ok(r.clone());
        }
    }
    let re = RegexBuilder::new(pattern)
        .case_insensitive(!case_sensitive)
        .size_limit(1 << 20)
        .build()?;
    if let Ok(mut guard) = cache.lock() {
        if guard.len() < 4096 {
            guard.insert(key, re.clone());
        }
    }
    Ok(re)
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/// Evaluate a check against a resource view: one leaf, or `all_of` several
/// (fail wins over unknown; details deduplicated and joined with "; ").
pub fn evaluate_check(check: &Check, view: &Value) -> CheckResult {
    match check {
        Check::Leaf(l) => evaluate_leaf(l, view),
        Check::AllOf { all_of } => {
            let mut failed: Vec<String> = Vec::new();
            let mut unknown: Vec<String> = Vec::new();
            let mut assumed = false;
            for leaf in all_of {
                let r = evaluate_leaf(leaf, view);
                assumed |= r.assumed_default;
                match r.outcome {
                    EvalOutcome::Fail if !failed.contains(&r.detail) => failed.push(r.detail),
                    EvalOutcome::Unknown if !unknown.contains(&r.detail) => {
                        unknown.push(r.detail)
                    }
                    _ => {}
                }
            }
            let mut r = if !failed.is_empty() {
                CheckResult::fail(failed.join("; "))
            } else if !unknown.is_empty() {
                CheckResult::unknown(unknown.join("; "))
            } else {
                CheckResult::pass()
            };
            r.assumed_default = assumed;
            r
        }
    }
}

/// One leaf, with `context` values appended to a failure: `detail [label: value]`.
pub fn evaluate_leaf(leaf: &Leaf, view: &Value) -> CheckResult {
    let mut r = leaf_core(leaf, view);
    if r.outcome == EvalOutcome::Fail {
        for c in &leaf.context {
            let value = match field_value(view, &c.field) {
                None | Some(Value::Null) => "not set".to_string(),
                Some(v) => display(v),
            };
            r.detail = format!("{} [{}: {}]", r.detail, c.label, value);
        }
    }
    r
}

fn leaf_core(leaf: &Leaf, view: &Value) -> CheckResult {
    let field = leaf.field.as_str();
    match leaf.evidence_source {
        EvidenceSource::Deep => {
            return CheckResult::unknown(format!(
                "{field} needs deep collection, which is not collected yet"
            ))
        }
        EvidenceSource::Join => {
            let segment = field.split('.').nth(1).unwrap_or("");
            let joined = view.get("join").and_then(|j| get_key(j, segment));
            if matches!(joined, None | Some(Value::Null)) {
                return CheckResult::unknown(format!(
                    "joined {segment} is outside the visible scope"
                ));
            }
        }
        EvidenceSource::Arg => {}
    }

    let raw = field_value(view, field);
    let absent = matches!(raw, None | Some(Value::Null));
    let (actual, assumed) = match (&leaf.when_absent, absent) {
        (Some(default), true) => (Some(default), true),
        _ => (raw, false),
    };
    // `present` treats JSON null as missing (the azcompliance rule for the new operators).
    let present = matches!(actual, Some(v) if !v.is_null());
    let suffix = if assumed { ASSUMED_SUFFIX } else { "" };
    let label = leaf
        .name
        .as_deref()
        .filter(|n| !n.is_empty())
        .unwrap_or(field);

    let mut r = match leaf.operator {
        // ---- the six original operators: outcomes unchanged (invariant 6) ----
        Operator::Exists => {
            if present {
                CheckResult::pass()
            } else {
                CheckResult::fail(format!("{field} is missing"))
            }
        }
        Operator::Nonempty => match actual {
            None => not_present(field),
            Some(Value::Null) => CheckResult::fail(format!("{label} is empty{suffix}")),
            Some(Value::String(s)) if s.trim().is_empty() => {
                CheckResult::fail(format!("{label} is empty{suffix}"))
            }
            Some(Value::Array(a)) if a.is_empty() => {
                CheckResult::fail(format!("{label} is empty{suffix}"))
            }
            Some(_) => CheckResult::pass(),
        },
        Operator::Equals => match (actual, leaf.value.as_ref()) {
            (None, _) => not_present(field),
            (Some(_), None) => CheckResult::unknown(format!("{field}: no expected value")),
            (Some(a), Some(e)) => {
                if values_equal(a, e) {
                    CheckResult::pass()
                } else {
                    CheckResult::fail(format!("{label} is {}; expected {}{suffix}", shown(a), shown(e)))
                }
            }
        },
        Operator::NotEquals => match (actual, leaf.value.as_ref()) {
            // Null counts as missing here so a missing value never passes (invariant 5).
            (None, _) | (Some(Value::Null), _) => not_present(field),
            (Some(_), None) => CheckResult::unknown(format!("{field}: no expected value")),
            (Some(a), Some(e)) => {
                if values_equal(a, e) {
                    CheckResult::fail(format!(
                        "{label} is {}; must not be {}{suffix}",
                        shown(a),
                        shown(e)
                    ))
                } else {
                    CheckResult::pass()
                }
            }
        },
        Operator::In => match (actual, leaf.value.as_ref()) {
            (None, _) => not_present(field),
            (Some(a), Some(Value::Array(list))) => {
                if list.iter().any(|v| values_equal(a, v)) {
                    CheckResult::pass()
                } else {
                    CheckResult::fail(format!(
                        "{label} is {}; allowed: {}{suffix}",
                        shown(a),
                        join_display(list)
                    ))
                }
            }
            _ => CheckResult::unknown(format!("{field}: expected a list of allowed values")),
        },
        Operator::NotIn => match (actual, leaf.value.as_ref()) {
            (None, _) | (Some(Value::Null), _) => not_present(field),
            (Some(a), Some(Value::Array(list))) => {
                if list.iter().any(|v| values_equal(a, v)) {
                    CheckResult::fail(format!(
                        "{label} is {}; not allowed: {}{suffix}",
                        shown(a),
                        join_display(list)
                    ))
                } else {
                    CheckResult::pass()
                }
            }
            _ => CheckResult::unknown(format!("{field}: expected a list of disallowed values")),
        },

        // ---- operators ported from azcompliance ----
        Operator::Matches => {
            if !present {
                CheckResult::fail(format!("{field} is missing"))
            } else {
                let a = display(actual.unwrap_or(&Value::Null));
                let pattern = leaf.value.as_ref().map(display).unwrap_or_default();
                match compile_pattern(&pattern, leaf.case_sensitive) {
                    Err(_) => CheckResult::unknown(format!(
                        "{field}: pattern '{pattern}' is not a supported regular expression"
                    )),
                    Ok(re) if re.is_match(&a) => CheckResult::pass(),
                    Ok(_) => {
                        let rule = leaf
                            .name
                            .as_deref()
                            .filter(|n| !n.is_empty())
                            .unwrap_or("pattern");
                        CheckResult::fail(format!("{field} '{a}' fails the {rule} rule{suffix}"))
                    }
                }
            }
        }
        Operator::LengthBetween => {
            if !present {
                CheckResult::fail(format!("{field} is missing"))
            } else {
                let len = display(actual.unwrap_or(&Value::Null)).chars().count();
                let min = leaf.min.unwrap_or(0);
                let max = leaf.max.unwrap_or(usize::MAX);
                if len >= min && len <= max {
                    CheckResult::pass()
                } else {
                    CheckResult::fail(format!(
                        "{field} length {len}; allowed {min} to {max}{suffix}"
                    ))
                }
            }
        }
        Operator::CountEq | Operator::CountGte => match leaf.value.as_ref().and_then(|v| v.as_u64()) {
            None => CheckResult::unknown(format!("{field}: expected count is not a whole number")),
            Some(want) => {
                let count = match actual {
                    Some(Value::Array(a)) => a.len() as u64,
                    Some(v) if !v.is_null() => 1,
                    _ => 0,
                };
                if leaf.operator == Operator::CountEq {
                    if count == want {
                        CheckResult::pass()
                    } else {
                        CheckResult::fail(format!(
                            "{field}: {count} found; expected exactly {want}{suffix}"
                        ))
                    }
                } else if count >= want {
                    CheckResult::pass()
                } else {
                    CheckResult::fail(format!(
                        "{field}: {count} found; at least {want} required{suffix}"
                    ))
                }
            }
        },
        Operator::CountWhereEq | Operator::CountWhereGte => {
            match (leaf.value.as_ref().and_then(|v| v.as_u64()), &leaf.where_) {
                (None, _) => {
                    CheckResult::unknown(format!("{field}: expected count is not a whole number"))
                }
                (_, None) => CheckResult::unknown(format!("{field}: count has no where clause")),
                (Some(want), Some(w)) => {
                    let items: Vec<&Value> = match actual {
                        Some(Value::Array(a)) => a.iter().collect(),
                        Some(v) if !v.is_null() => vec![v],
                        _ => Vec::new(),
                    };
                    let count = items
                        .into_iter()
                        .filter(|i| i.is_object() && where_item_matches(i, w))
                        .count() as u64;
                    let note = leaf
                        .note
                        .as_deref()
                        .filter(|n| !n.is_empty())
                        .map(|n| format!(": {n}"))
                        .unwrap_or_default();
                    if leaf.operator == Operator::CountWhereEq {
                        if count == want {
                            CheckResult::pass()
                        } else {
                            CheckResult::fail(format!("{count} found, {want} allowed{note}{suffix}"))
                        }
                    } else if count >= want {
                        CheckResult::pass()
                    } else {
                        CheckResult::fail(format!("{count} found, {want} required{note}{suffix}"))
                    }
                }
            }
        }
        Operator::OrdinalGte => {
            if !present {
                not_present(field)
            } else {
                let a = display(actual.unwrap_or(&Value::Null));
                let expected = leaf.value.as_ref().map(display).unwrap_or_default();
                let order: Vec<String> = leaf
                    .order
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(|s| s.to_lowercase())
                    .collect();
                let have = order.iter().position(|o| *o == a.to_lowercase());
                let need = order.iter().position(|o| *o == expected.to_lowercase());
                match (have, need) {
                    (None, _) => CheckResult::unknown(format!(
                        "{field} is {a}, which is not a recognised value"
                    )),
                    (_, None) => CheckResult::unknown(format!(
                        "{field}: minimum {expected} is not in the order list"
                    )),
                    (Some(h), Some(n)) if h >= n => CheckResult::pass(),
                    _ => CheckResult::fail(format!("{field} is {a}; minimum {expected}{suffix}")),
                }
            }
        }
        Operator::Gte | Operator::Lte => {
            if !present {
                not_present(field)
            } else {
                let a = display(actual.unwrap_or(&Value::Null));
                match (as_number(actual), as_number(leaf.value.as_ref())) {
                    (None, _) => {
                        CheckResult::unknown(format!("{field} is {a}, which is not a number"))
                    }
                    (_, None) => CheckResult::unknown(format!("{field}: limit is not a number")),
                    (Some(n), Some(limit)) => {
                        let shown_limit = leaf.value.as_ref().map(display).unwrap_or_default();
                        if leaf.operator == Operator::Gte {
                            if n >= limit {
                                CheckResult::pass()
                            } else {
                                CheckResult::fail(format!(
                                    "{field} is {a}; minimum {shown_limit}{suffix}"
                                ))
                            }
                        } else if n <= limit {
                            CheckResult::pass()
                        } else {
                            CheckResult::fail(format!("{field} is {a}; maximum {shown_limit}{suffix}"))
                        }
                    }
                }
            }
        }
    };
    r.assumed_default = assumed;
    r
}

fn not_present(field: &str) -> CheckResult {
    CheckResult::unknown(format!("{field} is not present in the evidence"))
}

fn join_display(list: &[Value]) -> String {
    list.iter().map(display).collect::<Vec<_>>().join(", ")
}

/// Does one array item satisfy a where clause (`equals`, `empty` or `matches`, ignoring case)?
fn where_item_matches(item: &Value, w: &WhereClause) -> bool {
    let v = field_value(item, &w.field).filter(|v| !v.is_null());
    if let Some(want_empty) = w.empty {
        let is_empty = match v {
            None => true,
            Some(Value::String(s)) => s.is_empty(),
            Some(Value::Array(a)) => a.is_empty(),
            Some(Value::Object(o)) => o.is_empty(),
            Some(_) => false,
        };
        return is_empty == want_empty;
    }
    if let Some(p) = &w.matches {
        return match (v, compile_pattern(p, false)) {
            (Some(v), Ok(re)) => re.is_match(&display(v)),
            _ => false,
        };
    }
    match (v, &w.equals) {
        (Some(v), Some(e)) => values_equal(v, e),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

/// Outcome of judging one control against one resource view.
pub(crate) enum ControlJudgement<'a> {
    /// The control is a coverage gap; it never evaluates per resource.
    NotEvaluated(NotEvaluated),
    /// No target selects the resource (type, kind filter or target filter).
    NotSelected,
    Evaluated {
        target: TargetRef<'a>,
        result: CheckResult,
    },
}

fn target_selects(t: &TargetRef<'_>, view: &Value, kinds: &ResourceKinds) -> bool {
    let type_ok = match (t.resource_kind, t.resource_type) {
        (Some(k), _) => kinds.resolve(k).is_some_and(|kind| kinds.matches(kind, view)),
        (None, Some("*")) => true,
        (None, Some(rt)) => view
            .get("type")
            .and_then(|v| v.as_str())
            .is_some_and(|ty| ty.eq_ignore_ascii_case(rt)),
        (None, None) => false,
    };
    type_ok
        && t
            .filter
            .is_none_or(|f| evaluate_leaf(f, view).outcome == EvalOutcome::Pass)
}

fn target_type_label(t: &TargetRef<'_>, kinds: &ResourceKinds) -> String {
    match (t.resource_kind, t.resource_type) {
        (Some(k), _) => kinds
            .resolve(k)
            .map(|kind| kind.arm_type.clone())
            .unwrap_or_else(|| k.to_string()),
        (None, Some(rt)) => rt.to_ascii_lowercase(),
        (None, None) => String::new(),
    }
}

pub(crate) fn judge_control<'a>(
    control: &'a Control,
    view: &Value,
    env: &EnvironmentClass,
    kinds: &ResourceKinds,
) -> ControlJudgement<'a> {
    if let Some(ne) = control.effective_not_evaluated() {
        return ControlJudgement::NotEvaluated(ne);
    }
    let target = control
        .effective_targets()
        .into_iter()
        .filter(|t| !t.check.is_deep_only())
        .find(|t| target_selects(t, view, kinds));
    let Some(target) = target else {
        return ControlJudgement::NotSelected;
    };
    if !control.applies_to.includes(env) {
        let list = control
            .applies_to
            .environments
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|e| e.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return ControlJudgement::Evaluated {
            target,
            result: CheckResult {
                outcome: EvalOutcome::Inapplicable,
                detail: format!("applies to {list} only"),
                assumed_default: false,
            },
        };
    }
    let result = evaluate_check(target.check, view);
    ControlJudgement::Evaluated { target, result }
}

/// Evaluate one control on one resource. `None` when no target of the control selects the
/// resource, or when the control is a coverage gap.
pub fn evaluate_control(
    control: &Control,
    obs: &ResourceObservation,
    ctx: &EvalContext,
) -> Option<Evaluation> {
    let view = resource_view(obs, ctx.joins);
    evaluate_control_on_view(control, obs, &view, ctx.environment, ctx.kinds)
}

fn evaluate_control_on_view(
    control: &Control,
    obs: &ResourceObservation,
    view: &Value,
    env: &EnvironmentClass,
    kinds: &ResourceKinds,
) -> Option<Evaluation> {
    let ControlJudgement::Evaluated { target, result } = judge_control(control, view, env, kinds)
    else {
        return None;
    };
    let leaves = target.check.leaves();
    let first = leaves.first();
    let mut context = Map::new();
    for l in leaves {
        for c in &l.context {
            context.insert(
                c.label.clone(),
                field_value(view, &c.field).cloned().unwrap_or(Value::Null),
            );
        }
    }
    let mut evidence = json!({
        "field": first.map(|l| l.field.as_str()),
        "operator": first.map(|l| l.operator.as_str()),
        "observed": first.and_then(|l| field_value(view, &l.field)),
        "manual": false,
        "grace_period_hours": control.grace_period_hours,
        "detail": result.detail,
        "assumed_default": result.assumed_default,
        "context": context,
        "target_resource_type": target_type_label(&target, kinds),
        "environment": env.as_str(),
        "lane": control.lane,
        "mode": control.mode,
        "status": control.status,
    });
    if leaves.len() > 1 {
        evidence["leaves"] = Value::Array(
            leaves
                .iter()
                .map(|l| {
                    json!({
                        "name": l.name,
                        "field": l.field,
                        "operator": l.operator.as_str(),
                        "observed": field_value(view, &l.field),
                    })
                })
                .collect(),
        );
    }
    Some(Evaluation {
        id: Uuid::new_v4().to_string(),
        observation_id: obs.id.clone(),
        resource_id: obs.resource_id.clone(),
        control_id: control.id.clone(),
        control_revision: control.source.revision.clone(),
        outcome: result.outcome,
        severity: Severity::parse(&control.severity).unwrap_or(Severity::Medium),
        evidence,
        // Evidence time, not a clock read, so evaluation stays deterministic (invariant 1).
        evaluated_at: obs.observation_time,
        environment: env.clone(),
        detail: result.detail,
    })
}

/// Evaluate every control of a pack against `resources`.
/// Gap controls (`not_evaluated`, `manual`) and deep-only targets produce `coverage_gaps`
/// instead of per-resource evaluations (invariant 4).
pub fn evaluate_pack(
    pack: &PolicyPack,
    resources: &[ResourceObservation],
    env_of: &dyn Fn(&ResourceObservation) -> EnvironmentClass,
    kinds: &ResourceKinds,
    joins: &JoinIndex,
) -> PackEvaluation {
    let views: Vec<Value> = resources.iter().map(|o| resource_view(o, joins)).collect();
    let envs: Vec<EnvironmentClass> = resources.iter().map(env_of).collect();

    let mut out = PackEvaluation::default();
    for control in &pack.controls {
        if let Some(ne) = control.effective_not_evaluated() {
            out.coverage_gaps.push(CoverageGap {
                pack_id: pack.id.clone(),
                control_id: control.id.clone(),
                category: ne.category,
                note: ne.note,
                resource_type: None,
                resource_count: 0,
            });
            continue;
        }
        let mut deep_types: Vec<(String, u64)> = Vec::new();
        for t in control.effective_targets() {
            if !t.check.is_deep_only() {
                continue;
            }
            let label = target_type_label(&t, kinds);
            let count = views.iter().filter(|v| target_selects(&t, v, kinds)).count() as u64;
            match deep_types.iter_mut().find(|(l, _)| *l == label) {
                Some(entry) => entry.1 += count,
                None => deep_types.push((label, count)),
            }
        }
        for (label, count) in deep_types {
            out.coverage_gaps.push(CoverageGap {
                pack_id: pack.id.clone(),
                control_id: control.id.clone(),
                category: GapCategory::DeepCollection,
                note: DEEP_GAP_NOTE.into(),
                resource_type: Some(label),
                resource_count: count,
            });
        }
    }

    for (i, obs) in resources.iter().enumerate() {
        for control in &pack.controls {
            if let Some(mut ev) =
                evaluate_control_on_view(control, obs, &views[i], &envs[i], kinds)
            {
                ev.control_revision = pack.revision.clone();
                if let Some(m) = ev.evidence.as_object_mut() {
                    m.insert(
                        "clause_revision".into(),
                        control.source.revision.clone().into(),
                    );
                }
                out.evaluations.push(ev);
            }
        }
    }
    out
}

/// Pre-v2 entry point: every control on every resource with an `Unknown` environment.
/// Coverage gaps are dropped. Use [`evaluate_pack`].
#[deprecated(note = "use evaluate_pack, which also returns coverage gaps")]
pub fn evaluate_pack_on_resources(
    controls: &[Control],
    pack_revision: &str,
    resources: &[ResourceObservation],
) -> Vec<Evaluation> {
    let kinds = builtin_resource_kinds();
    let joins = JoinIndex::empty();
    let mut out = Vec::new();
    for obs in resources {
        let view = resource_view(obs, &joins);
        for control in controls {
            if let Some(mut ev) =
                evaluate_control_on_view(control, obs, &view, &EnvironmentClass::Unknown, kinds)
            {
                ev.control_revision = pack_revision.to_string();
                if let Some(m) = ev.evidence.as_object_mut() {
                    m.insert(
                        "clause_revision".into(),
                        control.source.revision.clone().into(),
                    );
                }
                out.push(ev);
            }
        }
    }
    out
}
