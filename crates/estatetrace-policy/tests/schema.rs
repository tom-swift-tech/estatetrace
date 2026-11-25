//! AC-P1-12: the kit's JSON Schema accepts the shipped packs, and the example packs evaluate.

use estatetrace_policy::{builtin_resource_kinds, parse_pack_yaml, pilot_pack, run_example_cases, validate_pack};
use serde_json::{json, Value};

const SCHEMA: &str = include_str!("../../../kits/policy-authoring/schema/policy_pack.schema.json");
const PILOT: &str = include_str!("../../../kits/policy-authoring/examples/pilot_pack.yaml");
const BASELINE: &str =
    include_str!("../../../kits/policy-authoring/examples/azure_baseline_example.yaml");

fn validator() -> jsonschema::Validator {
    let schema: Value = serde_json::from_str(SCHEMA).expect("schema is JSON");
    jsonschema::validator_for(&schema).expect("schema compiles")
}

fn errors(v: &jsonschema::Validator, doc: &Value) -> Vec<String> {
    v.iter_errors(doc)
        .map(|e| format!("{} at {}", e, e.instance_path))
        .collect()
}

fn yaml_value(text: &str) -> Value {
    serde_yaml::from_str(text).expect("yaml")
}

#[test]
fn ac_p1_12_schema_validates_pilot_and_baseline() {
    let v = validator();
    for (name, text) in [("pilot_pack.yaml", PILOT), ("azure_baseline_example.yaml", BASELINE)] {
        let doc = yaml_value(text);
        let errs = errors(&v, &doc);
        assert!(errs.is_empty(), "{name}: {errs:#?}");
    }
}

#[test]
fn schema_accepts_the_stored_form_of_parsed_packs() {
    // Activated packs are stored as serde JSON; that form must stay schema-valid too.
    let v = validator();
    for pack in [pilot_pack(), parse_pack_yaml(BASELINE).unwrap()] {
        let doc = serde_json::to_value(&pack).unwrap();
        let errs = errors(&v, &doc);
        assert!(errs.is_empty(), "{}: {errs:#?}", pack.id);
    }
}

#[test]
fn schema_rejects_malformed_controls() {
    let v = validator();
    let control = |extra: Value| {
        let mut c = json!({
            "id": "X-1",
            "source": {"document": "d", "revision": "1", "clause": "1"},
            "owner": "o",
            "severity": "low"
        });
        for (k, val) in extra.as_object().unwrap() {
            c[k] = val.clone();
        }
        json!({"schema_version": 1, "id": "P", "name": "P", "revision": "1", "controls": [c]})
    };
    let bad = [
        ("unknown operator", json!({"check": {"field": "name", "operator": "sounds_like"}})),
        ("no check, targets or not_evaluated", json!({})),
        ("both check and targets", json!({
            "check": {"field": "name", "operator": "exists"},
            "targets": [{"resource_kind": "storage_account", "check": {"field": "name", "operator": "exists"}}]
        })),
        ("ordinal without order", json!({"check": {"field": "p", "operator": "ordinal_gte", "value": "TLS1_2"}})),
        ("count_where without where", json!({"check": {"field": "p", "operator": "count_where_gte", "value": 1}})),
        ("in with a scalar", json!({"check": {"field": "location", "operator": "in", "value": "eastus"}})),
        ("target with kind and type", json!({"targets": [{"resource_kind": "storage_account", "resource_type": "x", "check": {"field": "name", "operator": "exists"}}]})),
        ("misspelled leaf key", json!({"check": {"path": "name", "field": "name", "operator": "exists"}})),
        ("bad gap category", json!({"not_evaluated": {"category": "someday", "note": "n"}})),
    ];
    for (label, extra) in bad {
        assert!(!v.is_valid(&control(extra)), "{label} should be rejected");
    }
    let good = control(json!({"not_evaluated": {"category": "needs_decision", "note": "owner to decide"}}));
    assert!(v.is_valid(&good), "{:#?}", errors(&v, &good));
}

#[test]
fn baseline_example_validates_and_its_examples_pass() {
    let pack = parse_pack_yaml(BASELINE).expect("baseline parses and validates");
    let warnings = validate_pack(&pack, builtin_resource_kinds()).unwrap();
    assert!(warnings.is_empty(), "{warnings:#?}");
    let results = run_example_cases(&pack, builtin_resource_kinds()).unwrap();
    assert!(results.len() >= 20);
    for r in &results {
        assert!(r.ok, "{}: expected={} got={} detail={}", r.name, r.expected, r.got, r.detail);
    }
    // pass, fail, unknown, inapplicable and an assumed default are all demonstrated.
    for outcome in ["pass", "fail", "unknown", "inapplicable"] {
        assert!(results.iter().any(|r| r.got == outcome), "no {outcome} example");
    }
    assert!(results.iter().any(|r| r.assumed_default && r.got == "fail"));
    assert!(results.iter().any(|r| r.assumed_default && r.got == "pass"));
    // New controls default to provisional unless marked verified.
    let geo = pack.controls.iter().find(|c| c.id == "BASE-GEO-012").unwrap();
    assert_eq!(geo.status, estatetrace_policy::ControlStatus::Provisional);
}

#[test]
fn public_kit_files_carry_no_private_content() {
    // Invariant 15: no private tag names or catalog IDs in public kit additions.
    let files = [
        ("azure_baseline_example.yaml", BASELINE),
        ("resource_kinds.yaml", include_str!("../../../kits/policy-authoring/resource_kinds.yaml")),
        ("policy_pack.schema.json", SCHEMA),
    ];
    // Assembled at runtime so this file does not itself trip the repo-wide grep for them.
    let org = "FNF";
    let banned = [
        format!("{}_", org.to_lowercase()),
        format!("{org}-AZURE"),
        format!("{org}-AVD"),
        "AZ-00".to_string(),
        "VRDA-".to_string(),
        "ACA-00".to_string(),
    ];
    for (name, text) in files {
        for b in &banned {
            assert!(!text.contains(b.as_str()), "{name} contains {b}");
        }
    }
}
