//! Top-level ARG fields (kind, identity, ...) collected into `arm_meta` reach the evaluator,
//! so kind filters such as `function_app` select real resources, not only synthetic views.

use chrono::Utc;
use estatetrace_core::*;
use estatetrace_policy::{builtin_resource_kinds, evaluate_pack, parse_pack_yaml, JoinIndex};
use serde_json::{json, Value};

fn site(name: &str, arm_meta: Value) -> ResourceObservation {
    ResourceObservation {
        id: format!("obs-{name}"),
        provider: Provider::Azure,
        resource_id: ResourceId::new(format!(
            "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/{name}"
        )),
        tenant_id: TenantId::new("t"),
        subscription_id: SubscriptionId::new("s"),
        resource_type: "microsoft.web/sites".into(),
        name: name.into(),
        location: Some("eastus2".into()),
        resource_group: Some("rg".into()),
        tags: json!({}),
        properties: json!({}),
        scan_id: "scan".into(),
        observation_time: Utc::now(),
        evidence_available: true,
        lifecycle_epoch: 1,
        arm_meta,
    }
}

#[test]
fn function_app_kind_filter_and_identity_read_from_arm_meta() {
    let pack = parse_pack_yaml(
        r#"
schema_version: 1
id: T
name: T
revision: "1"
controls:
  - id: FA-ID
    source: { document: "Std", revision: "1", clause: "1" }
    owner: QA
    severity: medium
    applies_to: {}
    targets:
      - resource_kind: function_app
        check: { field: identity.type, operator: matches, value: "SystemAssigned" }
"#,
    )
    .unwrap();
    let resources = vec![
        site("fa-ok", json!({"kind": "functionapp,linux", "identity": {"type": "SystemAssigned"}})),
        site("fa-bad", json!({"kind": "functionapp"})),
        site("web-1", json!({"kind": "app,linux"})),
    ];
    let result = evaluate_pack(
        &pack,
        &resources,
        &|_| EnvironmentClass::Unknown,
        builtin_resource_kinds(),
        &JoinIndex::empty(),
    );
    let outcome = |n: &str| {
        result
            .evaluations
            .iter()
            .find(|e| e.resource_id.as_str().ends_with(n))
            .map(|e| e.outcome.clone())
    };
    assert_eq!(result.evaluations.len(), 2, "web app is not a function app");
    assert_eq!(outcome("fa-ok"), Some(EvalOutcome::Pass));
    assert_eq!(outcome("fa-bad"), Some(EvalOutcome::Fail));
    assert_eq!(outcome("web-1"), None);
}
