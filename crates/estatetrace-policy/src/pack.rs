use anyhow::{anyhow, Result};
use estatetrace_core::Severity;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    pub effective_from: Option<String>,
    pub severity: String,
    pub applies_to: Value,
    pub check: Check,
    #[serde(default)]
    pub azure_remediation: Option<AzureRemediation>,
    #[serde(default)]
    pub evidence_requirements: Vec<String>,
    #[serde(default)]
    pub grace_period_hours: Option<u64>,
    #[serde(default)]
    pub manual: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlSource {
    pub document: String,
    pub revision: String,
    pub clause: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub field: String,
    pub operator: String,
    #[serde(default)]
    pub value: Option<Value>,
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
    pub expected: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub pack_id: String,
    pub revision: String,
    pub clauses: Vec<ClauseCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClauseCoverage {
    pub control_id: String,
    pub clause: String,
    pub automation: String,
    pub notes: String,
}

const ALLOWED_OPS: &[&str] = &[
    "exists",
    "nonempty",
    "equals",
    "not_equals",
    "in",
    "not_in",
];

pub fn parse_pack_yaml(text: &str) -> Result<PolicyPack> {
    let pack: PolicyPack = serde_yaml::from_str(text)?;
    validate_pack(&pack)?;
    Ok(pack)
}

pub fn parse_pack_json(text: &str) -> Result<PolicyPack> {
    let pack: PolicyPack = serde_json::from_str(text)?;
    validate_pack(&pack)?;
    Ok(pack)
}

pub fn validate_pack(pack: &PolicyPack) -> Result<()> {
    if pack.schema_version != 1 {
        return Err(anyhow!("unsupported schema_version {}", pack.schema_version));
    }
    if pack.id.is_empty() || pack.revision.is_empty() {
        return Err(anyhow!("pack id and revision are required"));
    }
    for c in &pack.controls {
        if c.id.is_empty() {
            return Err(anyhow!("control id required"));
        }
        if c.owner.is_empty() {
            return Err(anyhow!("control {} missing owner", c.id));
        }
        if Severity::parse(&c.severity).is_none() {
            return Err(anyhow!("control {} invalid severity", c.id));
        }
        if !ALLOWED_OPS.contains(&c.check.operator.as_str()) {
            return Err(anyhow!(
                "control {} unsupported operator {}",
                c.id,
                c.check.operator
            ));
        }
        if c.check.field.is_empty() && !c.manual {
            return Err(anyhow!("control {} missing check field", c.id));
        }
    }
    Ok(())
}

pub fn coverage_report(pack: &PolicyPack) -> CoverageReport {
    let clauses = pack
        .controls
        .iter()
        .map(|c| {
            let automation = if c.manual {
                "manual_evidence".into()
            } else {
                "automated_check".into()
            };
            let notes = if c.manual {
                "Requires human evidence; Azure may only supply partial enrollment data.".into()
            } else {
                format!("operator={} field={}", c.check.operator, c.check.field)
            };
            ClauseCoverage {
                control_id: c.id.clone(),
                clause: format!(
                    "{} {} §{}",
                    c.source.document, c.source.revision, c.source.clause
                ),
                automation,
                notes,
            }
        })
        .collect();
    CoverageReport {
        pack_id: pack.id.clone(),
        revision: pack.revision.clone(),
        clauses,
    }
}

pub fn run_example_cases(pack: &PolicyPack) -> Result<Vec<(String, bool, String)>> {
    use crate::evaluator::evaluate_control_on_value;
    let mut results = Vec::new();
    for ex in &pack.example_cases {
        let control = pack
            .controls
            .iter()
            .find(|c| c.id == ex.control_id)
            .ok_or_else(|| anyhow!("example references missing control {}", ex.control_id))?;
        let outcome = evaluate_control_on_value(control, &ex.resource);
        let ok = outcome.as_str() == ex.expected;
        results.push((
            ex.name.clone(),
            ok,
            format!("expected={} got={}", ex.expected, outcome.as_str()),
        ));
    }
    Ok(results)
}

pub fn pilot_pack() -> PolicyPack {
    parse_pack_yaml(include_str!("../../../kits/policy-authoring/examples/pilot_pack.yaml"))
        .expect("pilot pack")
}