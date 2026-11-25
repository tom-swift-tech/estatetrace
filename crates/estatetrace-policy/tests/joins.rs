//! Evaluation-time joins (Phase 5 task 5.2, AC-P5-2). All IDs are fictional.

use chrono::{TimeZone, Utc};
use estatetrace_core::*;
use estatetrace_policy::{
    builtin_resource_kinds, evaluate_pack, in_tracked_subscriptions, parse_pack_yaml, resource_view,
    JoinIndex, PolicyPack,
};
use serde_json::{json, Value};

const SUB: &str = "00000000-0000-0000-0000-000000000000";

fn obs(resource_type: &str, name: &str, id: &str, properties: Value) -> ResourceObservation {
    ResourceObservation {
        id: format!("obs-{name}"),
        provider: Provider::Azure,
        resource_id: ResourceId::new(id.to_string()),
        tenant_id: TenantId::new("tenant-example"),
        subscription_id: SubscriptionId::new(SUB),
        resource_type: resource_type.into(),
        name: name.into(),
        location: Some("eastus2".into()),
        resource_group: Some("rg-example".into()),
        tags: json!({}),
        properties,
        scan_id: "scan-example".into(),
        observation_time: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        evidence_available: true,
        lifecycle_epoch: 1,
        arm_meta: json!({}),
    }
}

fn vnet_id() -> String {
    format!("/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.Network/virtualNetworks/vnet-example")
}

fn subnet_id(name: &str) -> String {
    format!("{}/subnets/{name}", vnet_id())
}

fn vnet() -> ResourceObservation {
    obs(
        "microsoft.network/virtualnetworks",
        "vnet-example",
        &vnet_id(),
        json!({
            "addressSpace": { "addressPrefixes": ["10.0.0.0/16"] },
            "subnets": [
                {
                    "id": subnet_id("snet-guarded"),
                    "name": "snet-guarded",
                    "properties": {
                        "addressPrefix": "10.0.1.0/24",
                        "networkSecurityGroup": { "id": format!("/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.Network/networkSecurityGroups/nsg-example") }
                    }
                },
                {
                    "id": subnet_id("snet-open"),
                    "name": "snet-open",
                    "properties": { "addressPrefix": "10.0.2.0/24" }
                }
            ]
        }),
    )
}

fn private_endpoint(name: &str, subnet: &str) -> ResourceObservation {
    obs(
        "microsoft.network/privateendpoints",
        name,
        &format!("/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.Network/privateEndpoints/{name}"),
        json!({ "subnet": { "id": subnet } }),
    )
}

fn pe_nsg_pack() -> PolicyPack {
    parse_pack_yaml(
        r#"
schema_version: 1
id: JOIN-TEST
name: Join test
revision: "1"
controls:
  - id: JOIN-PE-NSG
    source: { document: "Std", revision: "1", clause: "1" }
    owner: QA
    severity: high
    applies_to: {}
    targets:
      - resource_kind: private_endpoint
        check: { name: subnet NSG, field: join.subnet.properties.networkSecurityGroup.id, operator: exists, evidence_source: join }
      - resource_kind: container_app_environment
        check: { name: subnet NSG, field: join.subnet.properties.networkSecurityGroup.id, operator: exists, evidence_source: join }
  - id: JOIN-TAG
    source: { document: "Std", revision: "1", clause: "2" }
    owner: QA
    severity: low
    applies_to: {}
    check: { field: location, operator: equals, value: eastus2 }
"#,
    )
    .expect("pack parses")
}

fn run(resources: &[ResourceObservation], joins: &JoinIndex) -> Vec<Evaluation> {
    evaluate_pack(
        &pe_nsg_pack(),
        resources,
        &|_| EnvironmentClass::Unknown,
        builtin_resource_kinds(),
        joins,
    )
    .evaluations
}

fn outcome_for<'a>(evs: &'a [Evaluation], name: &str, control: &str) -> &'a Evaluation {
    evs.iter()
        .find(|e| e.resource_id.as_str().ends_with(&format!("/{name}")) && e.control_id == control)
        .unwrap_or_else(|| panic!("no {control} evaluation for {name}"))
}

#[test]
fn private_endpoint_in_tracked_vnet_joins_subnet_and_check_evaluates() {
    let pe_ok = private_endpoint("pe-guarded", &subnet_id("snet-guarded"));
    let pe_bad = private_endpoint("pe-open", &subnet_id("snet-open"));
    let latest = vec![vnet(), pe_ok.clone(), pe_bad.clone()];
    let joins = JoinIndex::build(&latest);
    assert_eq!(joins.subnet_count(), 2);

    let view = resource_view(&pe_ok, &joins);
    let subnet = &view["join"]["subnet"];
    assert_eq!(subnet["name"], "snet-guarded");
    assert_eq!(subnet["id"], subnet_id("snet-guarded"));
    assert_eq!(subnet["vnetId"], vnet_id());
    assert_eq!(subnet["vnetName"], "vnet-example");
    assert_eq!(subnet["properties"]["addressPrefix"], "10.0.1.0/24");

    let evs = run(&latest, &joins);
    assert_eq!(
        outcome_for(&evs, "pe-guarded", "JOIN-PE-NSG").outcome,
        EvalOutcome::Pass
    );
    let bad = outcome_for(&evs, "pe-open", "JOIN-PE-NSG");
    assert_eq!(bad.outcome, EvalOutcome::Fail);
    assert_eq!(
        bad.detail,
        "join.subnet.properties.networkSecurityGroup.id is missing"
    );
}

#[test]
fn private_endpoint_with_subnet_outside_scope_is_unknown() {
    // AC-P5-2: the PE names a subnet in a VNet that is not tracked.
    let foreign = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-other/providers/Microsoft.Network/virtualNetworks/vnet-other/subnets/snet-x";
    let pe = private_endpoint("pe-foreign", foreign);
    let latest = vec![vnet(), pe.clone()];
    let joins = JoinIndex::build(&latest);

    assert_eq!(joins.view_for(&pe), Some(json!({ "subnet": null })));
    let evs = run(&latest, &joins);
    let ev = outcome_for(&evs, "pe-foreign", "JOIN-PE-NSG");
    assert_eq!(ev.outcome, EvalOutcome::Unknown);
    assert_eq!(ev.detail, "joined subnet is outside the visible scope");

    // Never `fail` (spec §7): the same holds with the empty index and with no subnet reference.
    let evs = run(&latest, &JoinIndex::empty());
    let ev = outcome_for(&evs, "pe-foreign", "JOIN-PE-NSG");
    assert_eq!(ev.outcome, EvalOutcome::Unknown);
    assert_eq!(ev.detail, "joined subnet is outside the visible scope");

    let mut no_ref = private_endpoint("pe-noref", "");
    no_ref.properties = json!({});
    assert_eq!(joins.view_for(&no_ref), Some(json!({ "subnet": null })));
    let evs = run(&[no_ref], &joins);
    assert_eq!(evs[0].outcome, EvalOutcome::Unknown);
    assert_eq!(evs[0].detail, "joined subnet is outside the visible scope");
}

#[test]
fn container_apps_environment_joins_infrastructure_subnet() {
    let env_id = |n: &str| {
        format!("/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.App/managedEnvironments/{n}")
    };
    let injected = obs(
        "microsoft.app/managedenvironments",
        "cae-injected",
        &env_id("cae-injected"),
        json!({ "vnetConfiguration": { "infrastructureSubnetId": subnet_id("snet-guarded"), "internal": true } }),
    );
    let not_injected = obs(
        "microsoft.app/managedenvironments",
        "cae-public",
        &env_id("cae-public"),
        json!({ "vnetConfiguration": { "internal": false } }),
    );
    let joins = JoinIndex::build(&[vnet()]);

    let j = joins
        .view_for(&injected)
        .expect("managed environment joins its subnet");
    assert_eq!(j["subnet"]["name"], "snet-guarded");
    // Not VNet-injected: no join at all (as in azcompliance), so the leaf reports outside scope.
    assert_eq!(joins.view_for(&not_injected), None);

    let evs = run(&[injected, not_injected], &joins);
    assert_eq!(
        outcome_for(&evs, "cae-injected", "JOIN-PE-NSG").outcome,
        EvalOutcome::Pass
    );
    let public = outcome_for(&evs, "cae-public", "JOIN-PE-NSG");
    assert_eq!(public.outcome, EvalOutcome::Unknown);
    assert_eq!(public.detail, "joined subnet is outside the visible scope");
}

#[test]
fn network_interface_joins_first_ip_configuration_subnet() {
    let nic = obs(
        "microsoft.network/networkinterfaces",
        "nic-example",
        &format!("/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.Network/networkInterfaces/nic-example"),
        json!({ "ipConfigurations": [ { "name": "ipconfig1", "properties": { "subnet": { "id": subnet_id("snet-open") } } } ] }),
    );
    let joins = JoinIndex::build(&[vnet()]);
    assert_eq!(joins.view_for(&nic).unwrap()["subnet"]["name"], "snet-open");
}

#[test]
fn subnet_ids_match_case_insensitively() {
    let upper = subnet_id("snet-guarded").to_ascii_uppercase();
    let pe = private_endpoint("pe-upper", &upper);
    // The VNet row reports the subnet in lower case; the PE in upper case.
    let mut v = vnet();
    let lowered = v.properties.to_string().to_ascii_lowercase();
    v.properties = serde_json::from_str(&lowered).unwrap();
    v.resource_type = "Microsoft.Network/virtualNetworks".into();
    let mut pe_mixed_type = pe.clone();
    pe_mixed_type.resource_type = "Microsoft.Network/privateEndpoints".into();

    let joins = JoinIndex::build(&[v]);
    assert!(joins.subnet(&upper).is_some());
    let j = joins.view_for(&pe_mixed_type).unwrap();
    assert_eq!(j["subnet"]["name"], "snet-guarded");
    let evs = run(&[pe_mixed_type], &joins);
    assert_eq!(
        evs.iter()
            .find(|e| e.control_id == "JOIN-PE-NSG")
            .unwrap()
            .outcome,
        EvalOutcome::Pass
    );
}

#[test]
fn types_without_a_join_are_unaffected() {
    let site = obs(
        "microsoft.web/sites",
        "app-example",
        &format!("/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.Web/sites/app-example"),
        json!({ "subnet": { "id": subnet_id("snet-guarded") } }),
    );
    let joins = JoinIndex::build(&[vnet()]);
    assert_eq!(joins.view_for(&site), None);
    assert_eq!(joins.view_for(&vnet()), None);
    let with = resource_view(&site, &joins);
    let without = resource_view(&site, &JoinIndex::empty());
    assert_eq!(with, without);
    assert!(with.get("join").is_none());

    let with_evs = run(&[site.clone()], &joins);
    let without_evs = run(&[site], &JoinIndex::empty());
    assert_eq!(
        with_evs.len(),
        1,
        "only the location control selects a web app"
    );
    assert_eq!(with_evs[0].outcome, without_evs[0].outcome);
    assert_eq!(with_evs[0].detail, without_evs[0].detail);
}

#[test]
fn build_is_deterministic_regardless_of_input_order() {
    // Two rows for the same VNet: the later observation wins, whatever the input order.
    let older = vnet();
    let mut newer = vnet();
    newer.id = "obs-vnet-newer".into();
    newer.observation_time = Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap();
    newer.properties["subnets"][1]["properties"]["networkSecurityGroup"] =
        json!({ "id": "nsg-added" });

    let pe = private_endpoint("pe-open", &subnet_id("snet-open"));
    let a = JoinIndex::build(&[older.clone(), newer.clone()]);
    let b = JoinIndex::build(&[newer, older]);
    assert_eq!(a.view_for(&pe), b.view_for(&pe));
    assert_eq!(
        a.view_for(&pe).unwrap()["subnet"]["properties"]["networkSecurityGroup"]["id"],
        "nsg-added"
    );
}

#[test]
fn baseline_example_join_control_cases() {
    // Example cases use `resource` as the view, so they carry the joined object directly.
    let pack = parse_pack_yaml(include_str!(
        "../../../kits/policy-authoring/examples/azure_baseline_example.yaml"
    ))
    .expect("baseline parses");
    let results = estatetrace_policy::run_example_cases(&pack, builtin_resource_kinds()).unwrap();
    let ours: Vec<_> = results
        .iter()
        .filter(|r| r.control_id == "BASE-NET-016")
        .collect();
    assert_eq!(ours.len(), 3);
    for r in &ours {
        assert!(
            r.ok,
            "{}: expected={} got={} detail={}",
            r.name, r.expected, r.got, r.detail
        );
    }
    let unknown = ours.iter().find(|r| r.got == "unknown").unwrap();
    assert_eq!(unknown.detail, "joined subnet is outside the visible scope");
    assert!(ours.iter().any(|r| r.got == "pass"));
    assert!(ours.iter().any(|r| r.got == "fail"));
}

#[test]
fn excluded_subscription_vnet_is_not_indexed() {
    let tracked = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let excluded = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    let mut kept = vnet();
    kept.subscription_id = SubscriptionId::new(tracked);
    let mut dropped_vnet = vnet();
    dropped_vnet.id = "obs-vnet-excluded".into();
    dropped_vnet.subscription_id = SubscriptionId::new(excluded);
    let visible = in_tracked_subscriptions(&[kept, dropped_vnet], &[tracked]);
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].subscription_id.as_str(), tracked);
    assert!(JoinIndex::build(&visible).subnet(&subnet_id("snet-guarded")).is_some());

    let mut only_excluded = vnet();
    only_excluded.subscription_id = SubscriptionId::new(excluded);
    let hidden = JoinIndex::build(&in_tracked_subscriptions(&[only_excluded], &[tracked]));
    assert!(hidden.subnet(&subnet_id("snet-guarded")).is_none());

    let mut upper = vnet();
    upper.subscription_id = SubscriptionId::new(tracked.to_ascii_uppercase());
    assert_eq!(in_tracked_subscriptions(&[upper], &[tracked]).len(), 1);
}
