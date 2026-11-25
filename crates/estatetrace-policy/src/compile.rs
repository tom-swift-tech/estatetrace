//! Check-map compile (spec §4.8, Phase 7).
//!
//! A policy *catalog* states controls in prose (`control_id`, `name`, `requirement_level`,
//! `policy_statement`, ...) and carries no rule logic. A *check map* binds each control to
//! Azure evidence: resource kinds, leaf checks and filters, or a `not_evaluated` reason.
//! [`compile_check_map`] joins the two (plus operator settings) into an EstateTrace
//! [`PolicyPack`] and returns every lint issue found on the way.
//!
//! Port of azcompliance `ConvertFrom-PolicyCatalog`, `ConvertTo-PolicyTargets` and
//! `ConvertTo-CheckLeaf`, plus the suppress / override handling of `Build-ComplianceCatalog`.
//! Differences from the source, by design:
//! - A control in neither `checks` nor `not_evaluated` is an **error** (AC-P7-1), not a warning
//!   plus an `unbound` gap.
//! - `expected_setting` resolves from `settings.named_values`, not from top-level settings keys.
//! - `check_overrides` select one leaf of a check-map control by `leaf` (name or path).
//!
//! Catalog level / severity mapping onto EstateTrace severities ([`map_level`]):
//!
//! | catalog value                         | EstateTrace severity |
//! | ------------------------------------- | -------------------- |
//! | `low` / `medium` / `high` / `critical`| same                 |
//! | `must`, `must_*` (e.g. conditional)   | `high`               |
//! | `error` (tf-factory)                  | `high`               |
//! | `should`, `should_*`                  | `medium`             |
//! | `warning` (tf-factory)                | `medium`             |
//! | `may`                                 | `low`                |
//!
//! A control's explicit `severity` wins over its `requirement_level`. A variant's `severity`
//! (or `level`) uses the same table.

use crate::kinds::ResourceKinds;
use crate::pack::{
    lint_pack, AppliesTo, Check, ContextField, Control, ControlSource, ControlStatus,
    EvidenceSource, Lane, Leaf, LintIssue, LintSeverity, NotEvaluated, Operator, PolicyPack,
    Target, WhereClause,
};
use anyhow::{anyhow, Context as _, Result};
use estatetrace_core::Severity;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Check-map types (spec §4.8). Leaves use azcompliance names (`path`, `expected`);
// the EstateTrace names (`field`, `value`) are accepted as aliases.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckMap {
    /// Optional document marker (`kind: CheckMap`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub catalog_id: String,
    /// True once the bindings were checked against real resources; sets `status: verified`.
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub checks: BTreeMap<String, CheckBinding>,
    #[serde(default)]
    pub not_evaluated: BTreeMap<String, NotEvaluated>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckBinding {
    /// What the check actually judges (and what it does not), in plain words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judges: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    #[serde(default)]
    pub targets: Vec<MapTarget>,
    /// Compile the control once per variant, as `<control_id>/<suffix>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variants: Vec<Variant>,
    /// Optional environment applicability (azcompliance `applies_when`).
    #[serde(default, alias = "applies_when", skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<AppliesTo>,
    /// Optional lane; security when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<Lane>,
}

/// One target of a binding: a resource kind plus a single leaf (flattened) or `all_of`.
#[derive(Debug, Clone, Serialize)]
pub struct MapTarget {
    pub resource_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<MapLeaf>,
    #[serde(flatten)]
    pub check: MapCheck,
    /// Name in `settings.named_values` that supplies the expected value of a single-leaf target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_setting: Option<String>,
}

impl<'de> Deserialize<'de> for MapTarget {
    // Hand-rolled: the leaf is flattened into the target map, and a typo in a leaf key should
    // report the key instead of "did not match any variant".
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        let v = Value::deserialize(d)?;
        let Value::Object(mut obj) = v else {
            return Err(D::Error::custom("target is not a map"));
        };
        let resource_kind = match obj.remove("resource_kind") {
            Some(Value::String(s)) => s,
            Some(_) => return Err(D::Error::custom("resource_kind must be a string")),
            None => return Err(D::Error::custom("target has no resource_kind")),
        };
        let filter = obj
            .remove("filter")
            .map(serde_json::from_value::<MapLeaf>)
            .transpose()
            .map_err(|e| D::Error::custom(format!("filter: {e}")))?;
        let expected_setting = match obj.remove("expected_setting") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s),
            Some(_) => return Err(D::Error::custom("expected_setting must be a string")),
        };
        let check = if let Some(parts) = obj.remove("all_of") {
            if let Some(extra) = obj.keys().next() {
                return Err(D::Error::custom(format!(
                    "target with all_of cannot also set '{extra}'; put it on a leaf"
                )));
            }
            let all_of: Vec<MapLeaf> =
                serde_json::from_value(parts).map_err(|e| D::Error::custom(format!("all_of: {e}")))?;
            MapCheck::AllOf { all_of }
        } else {
            let leaf: MapLeaf =
                serde_json::from_value(Value::Object(obj)).map_err(D::Error::custom)?;
            MapCheck::Leaf(leaf)
        };
        Ok(MapTarget {
            resource_kind,
            filter,
            check,
            expected_setting,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum MapCheck {
    AllOf { all_of: Vec<MapLeaf> },
    Leaf(MapLeaf),
}

impl MapCheck {
    pub fn leaves(&self) -> &[MapLeaf] {
        match self {
            MapCheck::AllOf { all_of } => all_of,
            MapCheck::Leaf(l) => std::slice::from_ref(l),
        }
    }
}

/// A check-map leaf in azcompliance names. Converted to [`Leaf`] by the compile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapLeaf {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, alias = "field")]
    pub path: String,
    /// `equals` when unset (azcompliance default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<Operator>,
    #[serde(default, alias = "value", skip_serializing_if = "Option::is_none")]
    pub expected: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_setting: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_absent: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub where_: Option<MapWhere>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<MapContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_source: Option<EvidenceSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapWhere {
    #[serde(alias = "field")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapContext {
    pub label: String,
    #[serde(alias = "field")]
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Variant {
    pub suffix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title_suffix: Option<String>,
    /// Severity or level of this variant (`must`, `should`, `high`, ...); the control's when unset.
    #[serde(default, alias = "level", skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    pub filter: MapLeaf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompileSettings {
    /// Values referenced by `expected_setting` (e.g. an approved region list).
    #[serde(default)]
    pub named_values: BTreeMap<String, Value>,
    /// Controls dropped from the compiled pack (for example duplicates of another catalog).
    #[serde(default)]
    pub suppress: Vec<Suppression>,
    /// Per control ID (or variant ID): `{ leaf, reason, <leaf fields to replace> }`.
    #[serde(default)]
    pub check_overrides: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    pub control: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub duplicate_of: Option<String>,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a check map from YAML or JSON text.
pub fn parse_check_map_yaml(text: &str) -> Result<CheckMap> {
    let raw = parse_text(text).context("check map")?;
    serde_json::from_value(raw).map_err(|e| anyhow!("check map: {e}"))
}

/// Parse a policy catalog from YAML or JSON text. It must be a map with a `controls` list.
pub fn parse_catalog(text: &str) -> Result<Value> {
    let raw = parse_text(text).context("catalog")?;
    if !raw.is_object() {
        return Err(anyhow!("catalog: document is not a map"));
    }
    if !raw.get("controls").map(Value::is_array).unwrap_or(false) {
        return Err(anyhow!("catalog: needs a controls list"));
    }
    Ok(raw)
}

/// Parse compile settings from YAML or JSON text. Blank text gives the defaults.
pub fn parse_compile_settings(text: &str) -> Result<CompileSettings> {
    if text.trim().is_empty() {
        return Ok(CompileSettings::default());
    }
    let raw = parse_text(text).context("settings")?;
    if raw.is_null() {
        return Ok(CompileSettings::default());
    }
    serde_json::from_value(raw).map_err(|e| anyhow!("settings: {e}"))
}

fn parse_text(text: &str) -> Result<Value> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Value>(text) {
            return Ok(v);
        }
    }
    Ok(serde_yaml::from_str::<Value>(text)?)
}

// ---------------------------------------------------------------------------
// Compile
// ---------------------------------------------------------------------------

/// Map a catalog level or severity onto an EstateTrace severity (table in the module docs).
pub fn map_level(raw: &str) -> Option<Severity> {
    let k = raw.trim().to_ascii_lowercase();
    if let Some(s) = Severity::parse(&k) {
        return Some(s);
    }
    match k.as_str() {
        "error" => Some(Severity::High),
        "warning" => Some(Severity::Medium),
        "may" => Some(Severity::Low),
        _ if k == "must" || k.starts_with("must_") => Some(Severity::High),
        _ if k == "should" || k.starts_with("should_") => Some(Severity::Medium),
        _ => None,
    }
}

struct Issues(Vec<LintIssue>);

impl Issues {
    fn error(&mut self, cid: Option<&str>, msg: impl Into<String>) {
        self.push(LintSeverity::Error, cid, msg.into());
    }
    fn warn(&mut self, cid: Option<&str>, msg: impl Into<String>) {
        self.push(LintSeverity::Warning, cid, msg.into());
    }
    fn push(&mut self, severity: LintSeverity, cid: Option<&str>, message: String) {
        // lint_pack can repeat an issue the compile already reported.
        if self
            .0
            .iter()
            .any(|i| i.severity == severity && i.control_id.as_deref() == cid && i.message == message)
        {
            return;
        }
        self.0.push(LintIssue {
            severity,
            control_id: cid.map(str::to_string),
            message,
        });
    }
}

/// Collapse runs of whitespace (azcompliance `Format-Title`).
fn tidy(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn scalar_at(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Deterministic 64-bit FNV-1a, used as a content fingerprint when the catalog has no version.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Compile a catalog and its check map into a policy pack.
///
/// Returns `Err` only when the catalog is not a catalog at all (not a map, no `controls`).
/// Everything else is reported as a [`LintIssue`]; the caller rejects the pack when any issue
/// is an error. The returned pack has been through [`lint_pack`] (what `validate_pack` runs),
/// and its issues are included.
pub fn compile_check_map(
    catalog: &Value,
    map: &CheckMap,
    settings: &CompileSettings,
    kinds: &ResourceKinds,
) -> Result<(PolicyPack, Vec<LintIssue>)> {
    let controls_raw = catalog
        .get("controls")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("catalog needs a controls list"))?;
    let header = catalog.get("catalog").cloned().unwrap_or(Value::Null);
    let mut issues = Issues(Vec::new());

    // Pack identity.
    let catalog_id = str_at(&header, "catalog_id").or_else(|| str_at(catalog, "catalog_id"));
    if let Some(cid) = catalog_id {
        if cid != map.catalog_id {
            issues.error(
                None,
                format!(
                    "check map is for catalog '{}', but the catalog is '{cid}'",
                    map.catalog_id
                ),
            );
        }
    }
    if map.catalog_id.trim().is_empty() {
        issues.error(None, "check map has no catalog_id");
    }
    let version = ["catalog_version", "version", "revision"]
        .iter()
        .find_map(|k| scalar_at(&header, k).or_else(|| scalar_at(catalog, k)));
    let revision = match version {
        Some(v) => v,
        None => {
            let text = serde_json::to_string(&(catalog, map, settings))?;
            format!("c-{:016x}", fnv1a64(text.as_bytes()))
        }
    };
    let title = str_at(&header, "title")
        .or_else(|| str_at(catalog, "title"))
        .map(tidy)
        .unwrap_or_else(|| map.catalog_id.clone());
    let pack_owner = ["owner", "issuing_department"]
        .iter()
        .find_map(|k| str_at(&header, k).or_else(|| str_at(catalog, k)))
        .map(str::to_string);
    let catalog_document = str_at(&header, "authoritative_document")
        .map(str::to_string)
        .unwrap_or_else(|| title.clone());

    if !map.verified {
        issues.warn(
            None,
            format!(
                "check map for {} is not verified against real evidence (verified: false); every control is provisional",
                map.catalog_id
            ),
        );
    }
    let status = if map.verified {
        ControlStatus::Verified
    } else {
        ControlStatus::Provisional
    };

    // Suppressions.
    let mut suppress: BTreeMap<&str, &Suppression> = BTreeMap::new();
    for s in &settings.suppress {
        suppress.insert(s.control.as_str(), s);
    }

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut used_overrides: BTreeSet<String> = BTreeSet::new();
    let mut owner_missing = false;
    let mut controls: Vec<Control> = Vec::new();

    for (i, raw) in controls_raw.iter().enumerate() {
        if !raw.is_object() {
            issues.error(None, format!("controls entry #{} is not a map", i + 1));
            continue;
        }
        let Some(control_id) = str_at(raw, "control_id").or_else(|| str_at(raw, "id")) else {
            issues.error(None, format!("controls entry #{} has no control_id", i + 1));
            continue;
        };
        let cid = Some(control_id);
        if !seen.insert(control_id.to_string()) {
            issues.error(cid, "control_id appears twice in the catalog");
            continue;
        }

        let in_checks = map.checks.get(control_id);
        let in_skipped = map.not_evaluated.get(control_id);

        if let Some(s) = suppress.get(control_id) {
            let mut msg = "suppressed by settings".to_string();
            if let Some(d) = s.duplicate_of.as_deref().filter(|d| !d.trim().is_empty()) {
                msg.push_str(&format!("; duplicate of {d}"));
            }
            if let Some(r) = s.reason.as_deref().filter(|r| !r.trim().is_empty()) {
                msg.push_str(&format!(": {}", tidy(r)));
            }
            issues.warn(cid, msg);
            continue;
        }

        // Coverage lint (AC-P7-1): every control is bound or explicitly not evaluated.
        match (in_checks, in_skipped) {
            (None, None) => {
                issues.error(
                    cid,
                    "control is in neither checks nor not_evaluated in the check map",
                );
                continue;
            }
            (Some(_), Some(_)) => {
                issues.error(cid, "control is in both checks and not_evaluated");
                continue;
            }
            _ => {}
        }

        // Severity: explicit severity, else requirement level.
        let level_raw = ["severity", "requirement_level", "level"]
            .iter()
            .filter_map(|k| str_at(raw, k))
            .find(|v| map_level(v).is_some());
        let severity = match level_raw.and_then(map_level) {
            Some(s) => s,
            None => {
                let shown = str_at(raw, "requirement_level")
                    .or_else(|| str_at(raw, "severity"))
                    .unwrap_or("");
                issues.error(
                    cid,
                    format!("requirement_level '{shown}' is not must, should or may (or a severity)"),
                );
                continue;
            }
        };

        // Source.
        let (mut src_doc, mut src_section) = (None::<String>, None::<String>);
        let sources: Vec<&Value> = match raw.get("source") {
            Some(Value::Array(list)) => list.iter().collect(),
            Some(v @ Value::Object(_)) => vec![v],
            _ => Vec::new(),
        };
        for s in sources {
            if let Some(d) = str_at(s, "document") {
                src_doc = Some(d.to_string());
            }
            if let Some(sec) = str_at(s, "section").or_else(|| str_at(s, "clause")) {
                src_section = Some(sec.to_string());
            }
        }
        let source = ControlSource {
            document: src_doc.unwrap_or_else(|| catalog_document.clone()),
            revision: revision.clone(),
            clause: src_section.unwrap_or_else(|| control_id.to_string()),
        };

        let owner = match str_at(raw, "owner").map(str::to_string).or_else(|| pack_owner.clone()) {
            Some(o) => o,
            None => {
                owner_missing = true;
                "unassigned".to_string()
            }
        };
        let control_title = str_at(raw, "name")
            .or_else(|| str_at(raw, "title"))
            .or_else(|| str_at(raw, "policy_statement"))
            .or_else(|| str_at(raw, "statement"))
            .map(tidy)
            .unwrap_or_else(|| control_id.to_string());
        let evidence_requirements: Vec<String> = raw
            .get("minimum_evidence")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|v| match v {
                        Value::String(s) => tidy(s),
                        other => other.to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let base = Control {
            id: control_id.to_string(),
            source,
            owner,
            effective_from: None,
            severity: severity.as_str().to_string(),
            applies_to: AppliesTo::default(),
            check: None,
            targets: Vec::new(),
            not_evaluated: None,
            mode: Default::default(),
            lane: Lane::default(),
            status,
            azure_remediation: None,
            evidence_requirements,
            grace_period_hours: None,
            manual: false,
            fix: None,
            judges: None,
        };

        if let Some(ne) = in_skipped {
            let mut c = base;
            c.not_evaluated = Some(NotEvaluated {
                category: ne.category,
                note: tidy(&ne.note),
            });
            c.judges = Some(control_title);
            controls.push(c);
            continue;
        }

        let binding = in_checks.expect("bound");
        let variants: Vec<Option<&Variant>> = if binding.variants.is_empty() {
            vec![None]
        } else {
            binding.variants.iter().map(Some).collect()
        };
        for variant in variants {
            let mut c = base.clone();
            c.fix = binding.fix.as_deref().map(tidy);
            c.applies_to = binding.applies_to.clone().unwrap_or_default();
            c.lane = binding.lane.unwrap_or_default();
            let mut title = control_title.clone();
            let mut extra_filter: Option<&MapLeaf> = None;
            let mut variant_note: Option<String> = None;
            if let Some(v) = variant {
                let suffix = v.suffix.trim();
                if suffix.is_empty() {
                    issues.error(cid, "a variant in the check map has no suffix");
                    continue;
                }
                c.id = format!("{control_id}/{suffix}");
                if let Some(ts) = v.title_suffix.as_deref().filter(|s| !s.trim().is_empty()) {
                    title = format!("{title} ({})", tidy(ts));
                }
                if let Some(sv) = &v.severity {
                    match map_level(sv) {
                        Some(s) => c.severity = s.as_str().to_string(),
                        None => {
                            issues.error(
                                Some(&c.id),
                                format!("variant severity '{sv}' is not must, should, may or a severity"),
                            );
                            continue;
                        }
                    }
                }
                variant_note = v.note.as_deref().map(tidy);
                extra_filter = Some(&v.filter);
            }
            let item_id = c.id.clone();
            let iid = Some(item_id.as_str());

            if binding.targets.is_empty() {
                issues.error(iid, "check map entry has no targets");
                continue;
            }
            let mut targets: Vec<Target> = Vec::new();
            for (ti, t) in binding.targets.iter().enumerate() {
                if let Some(tg) = compile_target(t, ti + 1, extra_filter, settings, kinds, iid, &mut issues) {
                    targets.push(tg);
                }
            }
            if targets.len() != binding.targets.len() {
                // The failing target was already reported; do not emit a half-compiled control.
                if targets.is_empty() {
                    issues.error(iid, "check map entry produced no usable target");
                }
                continue;
            }

            // check_overrides: base ID applies to every variant, variant ID to that variant.
            let mut override_notes: Vec<String> = Vec::new();
            let mut keys = vec![control_id.to_string()];
            if item_id != control_id {
                keys.push(item_id.clone());
            }
            let mut override_failed = false;
            for key in keys {
                if let Some(ov) = settings.check_overrides.get(&key) {
                    used_overrides.insert(key.clone());
                    match apply_override(binding, &mut targets, ov, settings, iid, &mut issues) {
                        Some(reason) => override_notes.push(reason),
                        None => override_failed = true,
                    }
                }
            }
            if override_failed {
                continue;
            }

            let mut judges = binding.judges.as_deref().map(tidy).unwrap_or(title);
            if let Some(n) = variant_note {
                judges = format!("{judges} Variant: {n}");
            }
            for r in override_notes {
                judges = format!("{judges} (override: {r})");
            }
            c.judges = Some(judges);
            c.targets = targets;
            controls.push(c);
        }
    }

    if owner_missing {
        issues.warn(
            None,
            "catalog names no owner (catalog.owner, catalog.issuing_department or control owner); controls use 'unassigned'",
        );
    }
    for section in [
        map.checks.keys().collect::<Vec<_>>(),
        map.not_evaluated.keys().collect::<Vec<_>>(),
    ] {
        for k in section {
            if !seen.contains(k.as_str()) {
                issues.warn(Some(k), "check map names a control that is not in the catalog");
            }
        }
    }
    for s in &settings.suppress {
        if !seen.contains(&s.control) {
            issues.warn(Some(&s.control), "suppress names a control that is not in the catalog");
        }
    }
    for k in settings.check_overrides.keys() {
        if !used_overrides.contains(k) {
            issues.warn(
                Some(k),
                "check_overrides names a control that is not a compiled check-map control",
            );
        }
    }

    let pack = PolicyPack {
        schema_version: 1,
        id: map.catalog_id.clone(),
        name: title,
        revision,
        owner: pack_owner,
        controls,
        example_cases: Vec::new(),
    };
    // AC-P7-4: the same lint `validate_pack` runs; its errors are compile errors.
    for i in lint_pack(&pack, kinds) {
        issues.push(i.severity, i.control_id.as_deref(), i.message);
    }
    Ok((pack, issues.0))
}

fn compile_target(
    t: &MapTarget,
    tn: usize,
    extra_filter: Option<&MapLeaf>,
    settings: &CompileSettings,
    kinds: &ResourceKinds,
    cid: Option<&str>,
    issues: &mut Issues,
) -> Option<Target> {
    let mut ok = true;
    if kinds.resolve(&t.resource_kind).is_none() {
        issues.error(
            cid,
            format!(
                "target {tn}: resource_kind '{}' is not in resource_kinds.yaml",
                t.resource_kind
            ),
        );
        ok = false;
    }
    let filter_spec = match (&t.filter, extra_filter) {
        (Some(_), Some(_)) => {
            issues.error(
                cid,
                format!("target {tn}: a target with its own filter cannot be used with a variant filter"),
            );
            return None;
        }
        (Some(f), None) => Some(f),
        (None, f) => f,
    };
    let filter = match filter_spec {
        Some(f) => match to_leaf(f, None, settings, tn, cid, issues) {
            Some(l) => Some(l),
            None => {
                ok = false;
                None
            }
        },
        None => None,
    };
    let check = match &t.check {
        MapCheck::Leaf(l) => to_leaf(l, t.expected_setting.as_deref(), settings, tn, cid, issues).map(Check::Leaf),
        MapCheck::AllOf { all_of } => {
            if t.expected_setting.is_some() {
                issues.error(
                    cid,
                    format!("target {tn}: expected_setting on an all_of target is ambiguous; set it on the leaf"),
                );
                ok = false;
            }
            if all_of.is_empty() {
                issues.error(cid, format!("target {tn}: all_of is empty"));
                ok = false;
            }
            let mut leaves = Vec::new();
            for l in all_of {
                match to_leaf(l, None, settings, tn, cid, issues) {
                    Some(x) => leaves.push(x),
                    None => ok = false,
                }
            }
            Some(Check::AllOf { all_of: leaves })
        }
    };
    let check = check?;
    if !ok {
        return None;
    }
    Some(Target {
        resource_kind: Some(t.resource_kind.clone()),
        resource_type: None,
        filter,
        check,
    })
}

/// Convert one check-map leaf (port of `ConvertTo-CheckLeaf`).
fn to_leaf(
    m: &MapLeaf,
    target_setting: Option<&str>,
    settings: &CompileSettings,
    tn: usize,
    cid: Option<&str>,
    issues: &mut Issues,
) -> Option<Leaf> {
    if m.path.trim().is_empty() {
        issues.error(cid, format!("target {tn}: check map entry has no path"));
        return None;
    }
    let operator = m.operator.unwrap_or(Operator::Equals);
    let setting = m.expected_setting.as_deref().or(target_setting);
    let value = match setting {
        Some(name) => match settings.named_values.get(name) {
            None => {
                issues.error(
                    cid,
                    format!("target {tn}: expected_setting '{name}' is not in settings named_values"),
                );
                return None;
            }
            Some(v) => {
                // azcompliance makes a setting a list; a list operator needs one.
                let list_op = matches!(operator, Operator::In | Operator::NotIn);
                Some(match v {
                    Value::Array(_) => v.clone(),
                    other if list_op => Value::Array(vec![other.clone()]),
                    other => other.clone(),
                })
            }
        },
        None => m.expected.clone(),
    };
    Some(Leaf {
        name: m.name.clone(),
        field: m.path.trim().to_string(),
        operator,
        value,
        when_absent: m.when_absent.clone(),
        order: m.order.clone(),
        min: m.min,
        max: m.max,
        where_: m.where_.as_ref().map(|w| WhereClause {
            field: w.path.clone(),
            equals: w.equals.clone(),
            empty: w.empty,
            matches: w.matches.clone(),
        }),
        case_sensitive: m.case_sensitive.unwrap_or(false),
        context: m
            .context
            .iter()
            .map(|c| ContextField {
                label: c.label.clone(),
                field: c.path.clone(),
            })
            .collect(),
        note: m.note.as_deref().map(tidy),
        evidence_source: m.evidence_source.unwrap_or_default(),
    })
}

/// Apply one `check_overrides` entry: `{ leaf: <name or path>, reason, <leaf fields> }`.
/// The selected leaf (every leaf with that name or path across the targets) is rebuilt from
/// the check-map leaf with the given fields replaced. Returns the reason, or `None` on error.
fn apply_override(
    binding: &CheckBinding,
    targets: &mut [Target],
    ov: &Value,
    settings: &CompileSettings,
    cid: Option<&str>,
    issues: &mut Issues,
) -> Option<String> {
    let Some(obj) = ov.as_object() else {
        issues.error(cid, "check_overrides entry is not a map");
        return None;
    };
    let reason = match obj.get("reason").and_then(Value::as_str).map(tidy) {
        Some(r) if !r.is_empty() => r,
        _ => {
            issues.error(cid, "check_overrides entry needs a reason");
            return None;
        }
    };
    let selector = obj.get("leaf").and_then(Value::as_str).map(str::trim);
    let total: usize = binding.targets.iter().map(|t| t.check.leaves().len()).sum();
    let selects = |l: &MapLeaf| match selector {
        Some(s) => l.name.as_deref() == Some(s) || l.path == s,
        None => total == 1,
    };
    if selector.is_none() && total != 1 {
        issues.error(
            cid,
            format!("check_overrides entry needs `leaf` (a leaf name or path) to pick one of {total} leaves"),
        );
        return None;
    }
    let mut patch: Map<String, Value> = obj.clone();
    patch.remove("leaf");
    patch.remove("reason");
    let mut hits = 0;
    for (ti, (mt, target)) in binding.targets.iter().zip(targets.iter_mut()).enumerate() {
        let tn = ti + 1;
        let leaves: Vec<&mut Leaf> = match &mut target.check {
            Check::Leaf(l) => vec![l],
            Check::AllOf { all_of } => all_of.iter_mut().collect(),
        };
        for (ml, leaf) in mt.check.leaves().iter().zip(leaves) {
            if !selects(ml) {
                continue;
            }
            hits += 1;
            let mut base = match serde_json::to_value(ml) {
                Ok(Value::Object(m)) => m,
                _ => Map::new(),
            };
            // The target-level expected_setting of a single-leaf target belongs to this leaf.
            if let (MapCheck::Leaf(_), Some(s)) = (&mt.check, &mt.expected_setting) {
                base.entry("expected_setting").or_insert(Value::String(s.clone()));
            }
            // A replacement expected value wins over a setting reference, and vice versa.
            if patch.contains_key("expected") || patch.contains_key("value") {
                base.remove("expected_setting");
                base.remove("value");
            }
            if patch.contains_key("expected_setting") {
                base.remove("expected");
            }
            for (k, v) in &patch {
                base.insert(k.clone(), v.clone());
            }
            base.insert("note".into(), Value::String(reason.clone()));
            let merged: MapLeaf = match serde_json::from_value(Value::Object(base)) {
                Ok(m) => m,
                Err(e) => {
                    issues.error(cid, format!("check_overrides: {e}"));
                    return None;
                }
            };
            *leaf = to_leaf(&merged, None, settings, tn, cid, issues)?;
        }
    }
    if hits == 0 {
        issues.error(
            cid,
            format!(
                "check_overrides leaf '{}' matches no leaf name or path of the control",
                selector.unwrap_or("")
            ),
        );
        return None;
    }
    Some(reason)
}
