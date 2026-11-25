use chrono::Utc;
use estatetrace_core::*;
use estatetrace_policy::{builtin_resource_kinds, evaluate_pack, parse_pack_yaml, JoinIndex};
use serde_json::json;

#[test]
fn ac03_pack_revision_appears_on_finding() {
    let yaml = r#"
schema_version: 1
id: TEST
name: Test
revision: "9"
owner: QA
controls:
  - id: T-1
    source: { document: "Std", revision: "9", clause: "1.1" }
    owner: QA
    severity: low
    applies_to: {}
    check: { field: tags.CostCenter, operator: nonempty }
example_cases: []
"#;
    let pack = parse_pack_yaml(yaml).unwrap();
    let obs = ResourceObservation {
        id: "o1".into(),
        provider: Provider::Azure,
        resource_id: ResourceId::new("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa"),
        tenant_id: TenantId::new("t"),
        subscription_id: SubscriptionId::new("s"),
        resource_type: "Microsoft.Storage/storageAccounts".into(),
        name: "sa".into(),
        location: Some("eastus".into()),
        resource_group: Some("rg".into()),
        tags: json!({ "CostCenter": "" }),
        properties: json!({}),
        scan_id: "scan".into(),
        observation_time: Utc::now(),
        evidence_available: true,
        lifecycle_epoch: 1,
    };
    let result = evaluate_pack(
        &pack,
        &[obs],
        &|_| EnvironmentClass::Unknown,
        builtin_resource_kinds(),
        &JoinIndex::empty(),
    );
    let evals = result.evaluations;
    assert_eq!(evals.len(), 1);
    assert_eq!(evals[0].control_revision, "9");
    assert_eq!(evals[0].outcome, EvalOutcome::Fail);
    assert_eq!(evals[0].evidence["clause_revision"], "9");
}
