use crate::pack::Control;
use chrono::Utc;
use estatetrace_core::{EvalOutcome, Evaluation, ResourceId, ResourceObservation, Severity};
use serde_json::Value;
use uuid::Uuid;

pub fn evaluate_control(control: &Control, obs: &ResourceObservation) -> Evaluation {
    let resource_view = serde_json::json!({
        "tags": obs.tags,
        "properties": obs.properties,
        "location": obs.location,
        "type": obs.resource_type,
        "resourceGroup": obs.resource_group,
        "name": obs.name,
    });
    let outcome = if control.manual {
        EvalOutcome::Unknown
    } else if !applies(control, obs) {
        EvalOutcome::Inapplicable
    } else {
        evaluate_control_on_value(control, &resource_view)
    };

    Evaluation {
        id: Uuid::new_v4().to_string(),
        observation_id: obs.id.clone(),
        resource_id: obs.resource_id.clone(),
        control_id: control.id.clone(),
        control_revision: control.source.revision.clone(),
        outcome,
        severity: Severity::parse(&control.severity).unwrap_or(Severity::Medium),
        evidence: serde_json::json!({
            "field": control.check.field,
            "operator": control.check.operator,
            "observed": field_value(&resource_view, &control.check.field),
            "manual": control.manual,
            "grace_period_hours": control.grace_period_hours,
        }),
        evaluated_at: Utc::now(),
    }
}

pub fn evaluate_control_on_value(control: &Control, resource: &Value) -> EvalOutcome {
    if control.manual {
        return EvalOutcome::Unknown;
    }
    let observed = field_value(resource, &control.check.field);
    match control.check.operator.as_str() {
        "exists" => match observed {
            None => EvalOutcome::Fail,
            Some(Value::Null) => EvalOutcome::Fail,
            Some(_) => EvalOutcome::Pass,
        },
        "nonempty" => match observed {
            None => EvalOutcome::Unknown,
            Some(Value::Null) => EvalOutcome::Fail,
            Some(Value::String(s)) if s.trim().is_empty() => EvalOutcome::Fail,
            Some(Value::String(_)) => EvalOutcome::Pass,
            Some(Value::Array(a)) if a.is_empty() => EvalOutcome::Fail,
            Some(_) => EvalOutcome::Pass,
        },
        "equals" => match (observed, control.check.value.as_ref()) {
            (None, _) => EvalOutcome::Unknown,
            (Some(obs), Some(expected)) => {
                if values_equal(obs, expected) {
                    EvalOutcome::Pass
                } else {
                    EvalOutcome::Fail
                }
            }
            _ => EvalOutcome::Unknown,
        },
        "not_equals" => match (observed, control.check.value.as_ref()) {
            (None, _) => EvalOutcome::Unknown,
            (Some(obs), Some(expected)) => {
                if values_equal(obs, expected) {
                    EvalOutcome::Fail
                } else {
                    EvalOutcome::Pass
                }
            }
            _ => EvalOutcome::Unknown,
        },
        "in" => match (observed, control.check.value.as_ref()) {
            (None, _) => EvalOutcome::Unknown,
            (Some(obs), Some(Value::Array(arr))) => {
                if arr.iter().any(|v| values_equal(obs, v)) {
                    EvalOutcome::Pass
                } else {
                    EvalOutcome::Fail
                }
            }
            _ => EvalOutcome::Unknown,
        },
        "not_in" => match (observed, control.check.value.as_ref()) {
            (None, _) => EvalOutcome::Unknown,
            (Some(obs), Some(Value::Array(arr))) => {
                if arr.iter().any(|v| values_equal(obs, v)) {
                    EvalOutcome::Fail
                } else {
                    EvalOutcome::Pass
                }
            }
            _ => EvalOutcome::Unknown,
        },
        _ => EvalOutcome::Unknown,
    }
}

fn applies(control: &Control, obs: &ResourceObservation) -> bool {
    let env = control
        .applies_to
        .get("environment")
        .and_then(|v| v.as_str());
    if let Some(env) = env {
        if env.eq_ignore_ascii_case("prod") {
            // Applicability is refined by classification at inbox layer; evaluator still runs.
            let _ = obs;
        }
    }
    if let Some(cap) = control.applies_to.get("capability").and_then(|v| v.as_str()) {
        if cap == "supports_tags" {
            // Most ARM resources support tags; treat missing tags object as readable empty.
            return true;
        }
    }
    true
}

pub fn field_value<'a>(resource: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = resource;
    for part in path.split('.') {
        match cur {
            Value::Object(map) => {
                cur = map.get(part).or_else(|| {
                    map.iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(part))
                        .map(|(_, v)| v)
                })?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) => x.eq_ignore_ascii_case(y),
        _ => a == b,
    }
}

pub fn evaluate_pack_on_resources(
    controls: &[Control],
    pack_revision: &str,
    resources: &[ResourceObservation],
) -> Vec<Evaluation> {
    let mut out = Vec::new();
    for obs in resources {
        for control in controls {
            let mut ev = evaluate_control(control, obs);
            // Ensure evaluation records the pack revision under review.
            ev.control_revision = pack_revision.to_string();
            // Keep clause revision in evidence as well.
            ev.evidence
                .as_object_mut()
                .map(|m| m.insert("clause_revision".into(), control.source.revision.clone().into()));
            let _ = ResourceId::new(obs.resource_id.as_str());
            out.push(ev);
        }
    }
    out
}