//! Evaluator v2 acceptance tests (spec §6, AC-P1-1, 3..11) and operator tables (invariants 5, 6).
//! Fixture resources follow the shape Resource Graph returns; all IDs are fictional.

use chrono::{TimeZone, Utc};
use estatetrace_core::*;
use estatetrace_policy::*;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn obs(name: &str, rtype: &str, properties: Value, tags: Value) -> ResourceObservation {
    ResourceObservation {
        id: format!("obs-{name}"),
        provider: Provider::Azure,
        resource_id: ResourceId::new(format!(
            "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/{rtype}/{name}"
        )),
        tenant_id: TenantId::new("tenant-demo"),
        subscription_id: SubscriptionId::new("00000000-0000-0000-0000-000000000001"),
        resource_type: rtype.into(),
        name: name.into(),
        location: Some("eastus".into()),
        resource_group: Some("rg-demo".into()),
        tags,
        properties,
        scan_id: "scan-1".into(),
        observation_time: Utc.with_ymd_and_hms(2026, 11, 1, 12, 0, 0).unwrap(),
        evidence_available: true,
        lifecycle_epoch: 1,
    }
}

fn pack(controls_yaml: &str) -> PolicyPack {
    let yaml = format!(
        "schema_version: 1\nid: TEST-PACK\nname: Test\nrevision: \"4\"\nowner: QA\ncontrols:\n{controls_yaml}"
    );
    parse_pack_yaml(&yaml).unwrap_or_else(|e| panic!("pack parses: {e}\n{yaml}"))
}

fn run(p: &PolicyPack, resources: &[ResourceObservation]) -> PackEvaluation {
    evaluate_pack(
        p,
        resources,
        &|_| EnvironmentClass::Unknown,
        builtin_resource_kinds(),
        &JoinIndex::empty(),
    )
}

fn leaf(v: Value) -> Check {
    serde_json::from_value(v).expect("check parses")
}

/// One row of an operator table: resource view, expected outcome, assumed_default.
fn assert_rows(check: &Check, rows: &[(&str, Value, EvalOutcome, bool)]) {
    for (label, view, want, assumed) in rows {
        let r = evaluate_check(check, view);
        assert_eq!(r.outcome, *want, "{label}: {r:?}");
        assert_eq!(r.assumed_default, *assumed, "{label}: {r:?}");
        if r.outcome == EvalOutcome::Pass {
            assert!(r.detail.is_empty(), "{label}: pass has no detail");
        } else {
            assert!(!r.detail.is_empty(), "{label}: non-pass explains itself");
        }
    }
}

use EvalOutcome::{Fail, Inapplicable, Pass, Unknown};

// ---------------------------------------------------------------------------
// AC-P1-1: kind targeting
// ---------------------------------------------------------------------------

#[test]
fn ac_p1_1_kind_target_selects_only_its_type() {
    let p = pack(
        r#"
  - id: SA-1
    source: { document: d, revision: "1", clause: "1" }
    owner: o
    severity: high
    targets:
      - resource_kind: storage_account
        check: { field: properties.minimumTlsVersion, operator: equals, value: TLS1_2 }
"#,
    );
    let sa = obs("sa1", "Microsoft.Storage/storageAccounts", json!({"minimumTlsVersion": "TLS1_2"}), json!({}));
    let vm = obs("vm1", "Microsoft.Compute/virtualMachines", json!({}), json!({}));
    let out = run(&p, &[sa.clone(), vm]);
    assert_eq!(out.evaluations.len(), 1);
    assert_eq!(out.evaluations[0].resource_id, sa.resource_id);
    assert_eq!(out.evaluations[0].outcome, Pass);
    assert_eq!(out.evaluations[0].evidence["target_resource_type"], "microsoft.storage/storageaccounts");
    assert!(out.coverage_gaps.is_empty());
}

#[test]
fn ac_p1_1_resource_type_target_and_legacy_check_select_all() {
    let p = pack(
        r#"
  - id: BY-TYPE
    source: { document: d, revision: "1", clause: "1" }
    owner: o
    severity: low
    targets:
      - resource_type: Microsoft.Compute/virtualMachines
        check: { field: location, operator: exists }
  - id: LEGACY
    source: { document: d, revision: "1", clause: "2" }
    owner: o
    severity: low
    applies_to: { environment: prod }
    check: { field: location, operator: in, value: [eastus] }
"#,
    );
    let sa = obs("sa1", "Microsoft.Storage/storageAccounts", json!({}), json!({}));
    let vm = obs("vm1", "Microsoft.Compute/virtualMachines", json!({}), json!({}));
    let out = run(&p, &[sa, vm]);
    let by_type: Vec<_> = out.evaluations.iter().filter(|e| e.control_id == "BY-TYPE").collect();
    let legacy: Vec<_> = out.evaluations.iter().filter(|e| e.control_id == "LEGACY").collect();
    assert_eq!(by_type.len(), 1);
    assert_eq!(legacy.len(), 2, "legacy check selects every type (invariant 2)");
}

// ---------------------------------------------------------------------------
// AC-P1-2: the pilot's legacy GEO-001 still behaves (pilot_examples_pass covers the pack)
// ---------------------------------------------------------------------------

#[test]
fn ac_p1_2_geo_001_legacy_check_unchanged() {
    let p = pilot_pack();
    let geo = p.controls.iter().find(|c| c.id == "GEO-001").unwrap();
    assert!(geo.check.is_some() && geo.targets.is_empty());
    let mut west = obs("vm2", "Microsoft.Compute/virtualMachines", json!({}), json!({}));
    west.location = Some("westus".into());
    let east = obs("vm3", "Microsoft.Compute/virtualMachines", json!({}), json!({}));
    let out = evaluate_pack(&p, &[east, west], &|_| EnvironmentClass::Prod, builtin_resource_kinds(), &JoinIndex::empty());
    let geo: Vec<_> = out.evaluations.iter().filter(|e| e.control_id == "GEO-001").collect();
    assert_eq!(geo.len(), 2);
    assert_eq!(geo[0].outcome, Pass);
    assert_eq!(geo[1].outcome, Fail);
    assert_eq!(geo[1].detail, "location is westus; allowed: eastus, eastus2, centralus");
    // BCP-200 is manual: a coverage gap, never per-resource Unknown rows.
    assert!(out.evaluations.iter().all(|e| e.control_id != "BCP-200"));
    assert!(out.coverage_gaps.iter().any(|g| g.control_id == "BCP-200" && g.category == GapCategory::OutsideAzure));
}

// ---------------------------------------------------------------------------
// AC-P1-3: environment applicability
// ---------------------------------------------------------------------------

#[test]
fn ac_p1_3_environment_applicability() {
    let p = pack(
        r#"
  - id: PROD-ONLY
    source: { document: d, revision: "1", clause: "1" }
    owner: o
    severity: high
    applies_to: { environments: [prod] }
    targets:
      - resource_kind: key_vault
        check: { field: properties.enablePurgeProtection, operator: equals, value: true, when_absent: false }
"#,
    );
    let kv = |n: &str| obs(n, "Microsoft.KeyVault/vaults", json!({"enablePurgeProtection": true}), json!({}));
    let resources = [kv("kv-prod"), kv("kv-nonprod"), kv("kv-unknown")];
    let env_of = |o: &ResourceObservation| match o.name.as_str() {
        "kv-prod" => EnvironmentClass::Prod,
        "kv-nonprod" => EnvironmentClass::NonProd,
        _ => EnvironmentClass::Unknown,
    };
    let out = evaluate_pack(&p, &resources, &env_of, builtin_resource_kinds(), &JoinIndex::empty());
    let by = |n: &str| out.evaluations.iter().find(|e| e.resource_id.as_str().ends_with(n)).unwrap();
    assert_eq!(by("kv-prod").outcome, Pass);
    assert_eq!(by("kv-prod").environment, EnvironmentClass::Prod);
    assert_eq!(by("kv-nonprod").outcome, Inapplicable);
    assert_eq!(by("kv-nonprod").detail, "applies to prod only");
    assert_eq!(by("kv-unknown").outcome, Pass, "Unknown environment stays in scope");
    assert_eq!(by("kv-unknown").evidence["environment"], "unknown");
}

#[test]
fn ac_p1_3_legacy_environment_key_still_parses() {
    let p = pilot_pack();
    let fin = p.controls.iter().find(|c| c.id == "FIN-014").unwrap();
    assert_eq!(fin.applies_to.environments, Some(vec![EnvironmentClass::Prod]));
    assert!(fin.applies_to.includes(&EnvironmentClass::Unknown));
    assert!(!fin.applies_to.includes(&EnvironmentClass::Dev));
}

// ---------------------------------------------------------------------------
// AC-P1-4: operator tables (invariant 5) and the original six (invariant 6)
// ---------------------------------------------------------------------------

#[test]
fn ac_p1_4_original_six_operators_unchanged() {
    let exists = leaf(json!({"field": "properties.x", "operator": "exists"}));
    assert_rows(&exists, &[
        ("present", json!({"properties": {"x": 1}}), Pass, false),
        ("null", json!({"properties": {"x": null}}), Fail, false),
        ("missing", json!({"properties": {}}), Fail, false),
        ("not an object", json!({"properties": "text"}), Fail, false),
    ]);
    let nonempty = leaf(json!({"field": "tags.CostCenter", "operator": "nonempty"}));
    assert_rows(&nonempty, &[
        ("value", json!({"tags": {"CostCenter": "CC-1"}}), Pass, false),
        ("blank", json!({"tags": {"CostCenter": "  "}}), Fail, false),
        ("null", json!({"tags": {"CostCenter": null}}), Fail, false),
        ("empty list", json!({"tags": {"CostCenter": []}}), Fail, false),
        ("missing", json!({}), Unknown, false),
    ]);
    let equals = leaf(json!({"field": "properties.mode", "operator": "equals", "value": "On"}));
    assert_rows(&equals, &[
        ("same, other case", json!({"properties": {"mode": "on"}}), Pass, false),
        ("different", json!({"properties": {"mode": "Off"}}), Fail, false),
        ("missing", json!({}), Unknown, false),
    ]);
    let not_equals = leaf(json!({"field": "properties.mode", "operator": "not_equals", "value": "Off"}));
    assert_rows(&not_equals, &[
        ("different", json!({"properties": {"mode": "On"}}), Pass, false),
        ("same", json!({"properties": {"mode": "off"}}), Fail, false),
        ("missing", json!({}), Unknown, false),
    ]);
    let in_ = leaf(json!({"field": "location", "operator": "in", "value": ["eastus", "eastus2"]}));
    assert_rows(&in_, &[
        ("allowed", json!({"location": "EastUS2"}), Pass, false),
        ("not allowed", json!({"location": "westus"}), Fail, false),
        ("missing", json!({}), Unknown, false),
    ]);
    let not_in = leaf(json!({"field": "location", "operator": "not_in", "value": ["westus"]}));
    assert_rows(&not_in, &[
        ("allowed", json!({"location": "eastus"}), Pass, false),
        ("blocked", json!({"location": "WestUS"}), Fail, false),
        ("missing", json!({}), Unknown, false),
    ]);
}

#[test]
fn ac_p1_4_matches() {
    let c = leaf(json!({"name": "naming", "field": "name", "operator": "matches", "value": "^st[a-z0-9]+$"}));
    assert_rows(&c, &[
        ("pass, case ignored", json!({"name": "STdemo01"}), Pass, false),
        ("fail", json!({"name": "demo"}), Fail, false),
        ("missing is fail", json!({}), Fail, false),
        ("null is fail", json!({"name": null}), Fail, false),
    ]);
    assert_eq!(evaluate_check(&c, &json!({"name": "demo"})).detail, "name 'demo' fails the naming rule");
    assert_eq!(evaluate_check(&c, &json!({})).detail, "name is missing");
    let cs = leaf(json!({"field": "name", "operator": "matches", "value": "^st", "case_sensitive": true}));
    assert_eq!(evaluate_check(&cs, &json!({"name": "STx"})).outcome, Fail);
    let assumed = leaf(json!({"field": "properties.networkAcls.bypass", "operator": "matches", "value": "AzureServices", "when_absent": "AzureServices"}));
    assert_rows(&assumed, &[
        ("listed", json!({"properties": {"networkAcls": {"bypass": "Logging, AzureServices"}}}), Pass, false),
        ("not listed", json!({"properties": {"networkAcls": {"bypass": "None"}}}), Fail, false),
        ("absent uses default", json!({"properties": {}}), Pass, true),
    ]);
}

#[test]
fn ac_p1_4_length_between() {
    let c = leaf(json!({"field": "name", "operator": "length_between", "min": 3, "max": 5}));
    assert_rows(&c, &[
        ("min", json!({"name": "abc"}), Pass, false),
        ("max", json!({"name": "abcde"}), Pass, false),
        ("too long", json!({"name": "abcdef"}), Fail, false),
        ("missing is fail", json!({}), Fail, false),
    ]);
    assert_eq!(evaluate_check(&c, &json!({"name": "abcdef"})).detail, "name length 6; allowed 3 to 5");
}

#[test]
fn ac_p1_4_count_eq_and_count_gte() {
    let eq = leaf(json!({"field": "properties.rules", "operator": "count_eq", "value": 0}));
    assert_rows(&eq, &[
        ("empty list", json!({"properties": {"rules": []}}), Pass, false),
        ("one item", json!({"properties": {"rules": [{"a": 1}]}}), Fail, false),
        ("missing counts 0", json!({}), Pass, false),
    ]);
    assert_eq!(
        evaluate_check(&eq, &json!({"properties": {"rules": [1, 2]}})).detail,
        "properties.rules: 2 found; expected exactly 0"
    );
    let gte = leaf(json!({"field": "properties.rules", "operator": "count_gte", "value": 1}));
    assert_rows(&gte, &[
        ("two", json!({"properties": {"rules": [1, 2]}}), Pass, false),
        ("scalar counts 1", json!({"properties": {"rules": "x"}}), Pass, false),
        ("empty", json!({"properties": {"rules": []}}), Fail, false),
        ("missing counts 0", json!({}), Fail, false),
    ]);
    assert_eq!(evaluate_check(&gte, &json!({})).detail, "properties.rules: 0 found; at least 1 required");
}

#[test]
fn ac_p1_4_count_where_eq() {
    // Unmanaged data disks (managedDisk absent) are counted; none are allowed.
    let c = leaf(json!({
        "field": "properties.storageProfile.dataDisks", "operator": "count_where_eq", "value": 0,
        "where": {"field": "managedDisk", "empty": true},
        "note": "data disks that are not managed disks"
    }));
    let managed = json!({"lun": 0, "managedDisk": {"id": "/subscriptions/x/disks/d0"}});
    let unmanaged = json!({"lun": 1, "vhd": {"uri": "https://example.invalid/d1.vhd"}});
    assert_rows(&c, &[
        ("all managed", json!({"properties": {"storageProfile": {"dataDisks": [managed]}}}), Pass, false),
        ("one unmanaged", json!({"properties": {"storageProfile": {"dataDisks": [managed, unmanaged]}}}), Fail, false),
        ("missing counts 0", json!({"properties": {}}), Pass, false),
    ]);
    assert_eq!(
        evaluate_check(&c, &json!({"properties": {"storageProfile": {"dataDisks": [unmanaged]}}})).detail,
        "1 found, 0 allowed: data disks that are not managed disks"
    );
    let m = leaf(json!({
        "field": "properties.template.containers", "operator": "count_where_eq", "value": 0,
        "where": {"field": "image", "matches": ":latest$"}
    }));
    assert_rows(&m, &[
        ("pinned", json!({"properties": {"template": {"containers": [{"image": "repo/app:1.2"}]}}}), Pass, false),
        ("latest", json!({"properties": {"template": {"containers": [{"image": "repo/app:LATEST"}]}}}), Fail, false),
    ]);
}

#[test]
fn ac_p1_4_count_where_gte() {
    let c = leaf(json!({
        "field": "properties.privateEndpointConnections", "operator": "count_where_gte", "value": 1,
        "where": {"field": "properties.privateLinkServiceConnectionState.status", "equals": "Approved"}
    }));
    assert_rows(&c, &[
        ("approved", json!({"properties": {"privateEndpointConnections": [pe("Approved")]}}), Pass, false),
        ("pending", json!({"properties": {"privateEndpointConnections": [pe("Pending")]}}), Fail, false),
        ("missing counts 0", json!({"properties": {}}), Fail, false),
    ]);
}

#[test]
fn ac_p1_4_ordinal_gte() {
    let c = leaf(json!({
        "field": "properties.minimalTlsVersion", "operator": "ordinal_gte",
        "order": ["None", "1.0", "1.1", "1.2", "1.3"], "value": "1.2"
    }));
    assert_rows(&c, &[
        ("equal", json!({"properties": {"minimalTlsVersion": "1.2"}}), Pass, false),
        ("higher", json!({"properties": {"minimalTlsVersion": "1.3"}}), Pass, false),
        ("lower", json!({"properties": {"minimalTlsVersion": "1.0"}}), Fail, false),
        ("missing is unknown", json!({"properties": {}}), Unknown, false),
        ("unrecognised is unknown", json!({"properties": {"minimalTlsVersion": "SSL3"}}), Unknown, false),
    ]);
    assert_eq!(
        evaluate_check(&c, &json!({"properties": {"minimalTlsVersion": "SSL3"}})).detail,
        "properties.minimalTlsVersion is SSL3, which is not a recognised value"
    );
}

#[test]
fn ac_p1_4_gte_and_lte() {
    let gte = leaf(json!({"field": "properties.softDeleteRetentionInDays", "operator": "gte", "value": 90, "when_absent": 90}));
    assert_rows(&gte, &[
        ("enough", json!({"properties": {"softDeleteRetentionInDays": 90}}), Pass, false),
        ("numeric string", json!({"properties": {"softDeleteRetentionInDays": "120"}}), Pass, false),
        ("too few", json!({"properties": {"softDeleteRetentionInDays": 7}}), Fail, false),
        ("absent uses default", json!({"properties": {}}), Pass, true),
        ("not a number", json!({"properties": {"softDeleteRetentionInDays": "lots"}}), Unknown, false),
    ]);
    assert_eq!(
        evaluate_check(&gte, &json!({"properties": {"softDeleteRetentionInDays": "lots"}})).detail,
        "properties.softDeleteRetentionInDays is lots, which is not a number"
    );
    let lte = leaf(json!({"field": "properties.maxAgeDays", "operator": "lte", "value": 30}));
    assert_rows(&lte, &[
        ("within", json!({"properties": {"maxAgeDays": 30}}), Pass, false),
        ("over", json!({"properties": {"maxAgeDays": 31}}), Fail, false),
        ("missing is unknown", json!({}), Unknown, false),
    ]);
    assert_eq!(
        evaluate_check(&lte, &json!({"properties": {"maxAgeDays": 31}})).detail,
        "properties.maxAgeDays is 31; maximum 30"
    );
}

#[test]
fn ac_p1_4_when_absent_on_original_operators() {
    let c = leaf(json!({"name": "IP forwarding", "field": "properties.enableIPForwarding", "operator": "equals", "value": false, "when_absent": false}));
    assert_rows(&c, &[
        ("off", json!({"properties": {"enableIPForwarding": false}}), Pass, false),
        ("on", json!({"properties": {"enableIPForwarding": true}}), Fail, false),
        ("absent uses default", json!({"properties": {}}), Pass, true),
        ("null uses default", json!({"properties": {"enableIPForwarding": null}}), Pass, true),
    ]);
    assert_eq!(
        evaluate_check(&c, &json!({"properties": {"enableIPForwarding": true}})).detail,
        "IP forwarding is true; expected false"
    );
}

#[test]
fn tags_path_treats_rest_as_one_key() {
    let view = json!({"tags": {"app.owner": "team-a", "Env": "prod"}, "properties": {"a": {"b": 1}}});
    assert_eq!(field_value(&view, "tags.app.owner"), Some(&json!("team-a")));
    assert_eq!(field_value(&view, "tags.env"), Some(&json!("prod")));
    assert_eq!(field_value(&view, "properties.A.b"), Some(&json!(1)));
    assert_eq!(field_value(&view, "properties.a.b.c"), None);
}

// ---------------------------------------------------------------------------
// AC-P1-5..7: detail strings
// ---------------------------------------------------------------------------

#[test]
fn ac_p1_5_ordinal_with_assumed_default() {
    let c = leaf(json!({
        "field": "properties.minimumTlsVersion", "operator": "ordinal_gte",
        "order": ["TLS1_0", "TLS1_1", "TLS1_2"], "value": "TLS1_2", "when_absent": "TLS1_0"
    }));
    let r = evaluate_check(&c, &json!({"properties": {}}));
    assert_eq!(r.outcome, Fail);
    assert!(r.assumed_default);
    assert!(r.detail.ends_with("(property absent; Azure default assumed)"), "{}", r.detail);
    assert_eq!(
        r.detail,
        "properties.minimumTlsVersion is TLS1_0; minimum TLS1_2 (property absent; Azure default assumed)"
    );
}

#[test]
fn ac_p1_6_all_of_fail_beats_unknown() {
    let c = leaf(json!({"all_of": [
        {"name": "purge protection", "field": "properties.enablePurgeProtection", "operator": "equals", "value": true},
        {"name": "retention", "field": "properties.softDeleteRetentionInDays", "operator": "gte", "value": 90},
        {"name": "soft delete", "field": "properties.enableSoftDelete", "operator": "equals", "value": true}
    ]}));
    let r = evaluate_check(&c, &json!({"properties": {"enablePurgeProtection": false, "enableSoftDelete": true}}));
    assert_eq!(r.outcome, Fail);
    assert_eq!(r.detail, "purge protection is false; expected true");
    let r = evaluate_check(&c, &json!({"properties": {"enablePurgeProtection": true, "enableSoftDelete": true}}));
    assert_eq!(r.outcome, Unknown);
    assert_eq!(r.detail, "properties.softDeleteRetentionInDays is not present in the evidence");
    let r = evaluate_check(&c, &json!({"properties": {"enablePurgeProtection": true, "enableSoftDelete": true, "softDeleteRetentionInDays": 90}}));
    assert_eq!(r.outcome, Pass);
    assert_eq!(r.detail, "");
    // Duplicate failure details are listed once.
    let dup = leaf(json!({"all_of": [
        {"field": "properties.x", "operator": "exists"},
        {"field": "properties.x", "operator": "exists"},
        {"field": "properties.y", "operator": "exists"}
    ]}));
    assert_eq!(evaluate_check(&dup, &json!({})).detail, "properties.x is missing; properties.y is missing");
}

#[test]
fn ac_p1_7_context_appended_on_failure() {
    let c = leaf(json!({
        "name": "public network access", "field": "properties.publicNetworkAccess",
        "operator": "equals", "value": "Disabled", "when_absent": "Enabled",
        "context": [{"label": "firewall default action", "field": "properties.networkAcls.defaultAction"}]
    }));
    let r = evaluate_check(&c, &json!({"properties": {"publicNetworkAccess": "Enabled", "networkAcls": {"defaultAction": "Deny"}}}));
    assert_eq!(r.outcome, Fail);
    assert!(r.detail.contains("[firewall default action: Deny]"), "{}", r.detail);
    let r = evaluate_check(&c, &json!({"properties": {}}));
    assert_eq!(
        r.detail,
        "public network access is Enabled; expected Disabled (property absent; Azure default assumed) [firewall default action: not set]"
    );
    let r = evaluate_check(&c, &json!({"properties": {"publicNetworkAccess": "Disabled"}}));
    assert_eq!(r.outcome, Pass);
    assert_eq!(r.detail, "", "context is reported only beside a failure");
}

// ---------------------------------------------------------------------------
// AC-P1-8: not_evaluated and deep-only targets become coverage gaps
// ---------------------------------------------------------------------------

#[test]
fn ac_p1_8_not_evaluated_is_a_coverage_gap() {
    let p = pack(
        r#"
  - id: OUTSIDE-1
    source: { document: d, revision: "1", clause: "1" }
    owner: o
    severity: medium
    not_evaluated: { category: outside_azure, note: Needs sign-in logs from the identity provider }
  - id: CHECKED-1
    source: { document: d, revision: "1", clause: "2" }
    owner: o
    severity: medium
    targets:
      - resource_kind: storage_account
        check: { field: location, operator: exists }
  - id: DEEP-1
    source: { document: d, revision: "1", clause: "3" }
    owner: o
    severity: medium
    targets:
      - resource_kind: storage_account
        check: { field: deep.diagnosticSettings, operator: count_gte, value: 1, evidence_source: deep }
"#,
    );
    let sa = obs("sa1", "Microsoft.Storage/storageAccounts", json!({}), json!({}));
    let sa2 = obs("sa2", "Microsoft.Storage/storageAccounts", json!({}), json!({}));
    let out = run(&p, &[sa, sa2]);
    assert!(out.evaluations.iter().all(|e| e.control_id == "CHECKED-1"));
    assert_eq!(out.evaluations.len(), 2);
    assert_eq!(out.coverage_gaps.len(), 2);
    let outside = out.coverage_gaps.iter().find(|g| g.control_id == "OUTSIDE-1").unwrap();
    assert_eq!(outside.category, GapCategory::OutsideAzure);
    assert_eq!(outside.pack_id, "TEST-PACK");
    assert_eq!(outside.resource_type, None);
    let deep = out.coverage_gaps.iter().find(|g| g.control_id == "DEEP-1").unwrap();
    assert_eq!(deep.category, GapCategory::DeepCollection);
    assert_eq!(deep.resource_type.as_deref(), Some("microsoft.storage/storageaccounts"));
    assert_eq!(deep.resource_count, 2);

    let cov = coverage_report(&p);
    assert_eq!(cov.not_evaluated.get(&GapCategory::OutsideAzure), Some(&1));
    assert_eq!(cov.not_evaluated.get(&GapCategory::DeepCollection), Some(&1));
    assert!(cov.clauses.iter().any(|c| c.control_id == "OUTSIDE-1" && c.category == Some(GapCategory::OutsideAzure)));
    assert_eq!(cov.controls_total, 3);
    assert_eq!(cov.controls_evaluated, 1);
    assert!(cov.controls_evaluated < cov.controls_total);
}

// ---------------------------------------------------------------------------
// AC-P1-9: target filter
// ---------------------------------------------------------------------------

#[test]
fn ac_p1_9_target_filter_skips_unmatched_resources() {
    let p = pack(
        r#"
  - id: HP-LB
    source: { document: d, revision: "1", clause: "1" }
    owner: o
    severity: medium
    targets:
      - resource_kind: avd_host_pool
        filter: { field: properties.hostPoolType, operator: equals, value: Pooled }
        check: { field: properties.loadBalancerType, operator: equals, value: DepthFirst }
"#,
    );
    let pooled = obs("hp-pooled", "Microsoft.DesktopVirtualization/hostpools",
        json!({"hostPoolType": "Pooled", "loadBalancerType": "BreadthFirst"}), json!({}));
    let personal = obs("hp-personal", "Microsoft.DesktopVirtualization/hostpools",
        json!({"hostPoolType": "Personal", "loadBalancerType": "Persistent"}), json!({}));
    let out = run(&p, &[pooled.clone(), personal.clone()]);
    assert_eq!(out.evaluations.len(), 1);
    assert_eq!(out.evaluations[0].resource_id, pooled.resource_id);
    assert_eq!(out.evaluations[0].outcome, Fail);
    let ctx = EvalContext { environment: &EnvironmentClass::Unknown, kinds: builtin_resource_kinds(), joins: &JoinIndex::empty() };
    assert!(evaluate_control(&p.controls[0], &personal, &ctx).is_none());
}

// ---------------------------------------------------------------------------
// AC-P1-10: count_where_gte on private endpoint connections
// ---------------------------------------------------------------------------

fn pe(status: &str) -> Value {
    json!({
        "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa/privateEndpointConnections/pe1",
        "properties": {
            "privateEndpoint": {"id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/privateEndpoints/pe1"},
            "privateLinkServiceConnectionState": {"status": status, "description": "", "actionRequired": "None"},
            "provisioningState": "Succeeded"
        }
    })
}

#[test]
fn ac_p1_10_count_where_gte_private_endpoints() {
    let p = pack(
        r#"
  - id: PE-1
    source: { document: d, revision: "1", clause: "1" }
    owner: o
    severity: high
    targets:
      - resource_kind: storage_account
        check:
          field: properties.privateEndpointConnections
          operator: count_where_gte
          value: 1
          where: { field: properties.privateLinkServiceConnectionState.status, equals: Approved }
"#,
    );
    let pending = obs("sa-pending", "Microsoft.Storage/storageAccounts",
        json!({"privateEndpointConnections": [pe("Pending"), pe("Pending")]}), json!({}));
    let approved = obs("sa-approved", "Microsoft.Storage/storageAccounts",
        json!({"privateEndpointConnections": [pe("Approved")]}), json!({}));
    let out = run(&p, &[pending, approved]);
    let by = |n: &str| out.evaluations.iter().find(|e| e.resource_id.as_str().ends_with(n)).unwrap();
    assert_eq!(by("sa-pending").outcome, Fail);
    assert_eq!(by("sa-pending").detail, "0 found, 1 required");
    assert_eq!(by("sa-approved").outcome, Pass);
}

// ---------------------------------------------------------------------------
// AC-P1-11: unsupported regex fails validation, never panics
// ---------------------------------------------------------------------------

#[test]
fn ac_p1_11_lookbehind_fails_validation_naming_the_control() {
    let yaml = r#"
schema_version: 1
id: T
name: T
revision: "1"
controls:
  - id: NAME-LOOKBEHIND
    source: { document: d, revision: "1", clause: "1" }
    owner: o
    severity: low
    targets:
      - resource_kind: storage_account
        check: { field: name, operator: matches, value: "(?<!x)prod" }
"#;
    let err = parse_pack_yaml(yaml).unwrap_err().to_string();
    assert!(err.contains("NAME-LOOKBEHIND"), "{err}");
    assert!(err.contains("(?<!x)prod"), "{err}");

    // validate_pack on an already-deserialized pack also rejects it.
    let raw: Value = serde_yaml::from_str(yaml).unwrap();
    let pack: PolicyPack = serde_json::from_value(raw).unwrap();
    let err = validate_pack(&pack, builtin_resource_kinds()).unwrap_err().to_string();
    assert!(err.contains("NAME-LOOKBEHIND"), "{err}");

    // Lookahead in a where clause is rejected too.
    let where_yaml = yaml.replace(
        "check: { field: name, operator: matches, value: \"(?<!x)prod\" }",
        "check: { field: properties.x, operator: count_where_eq, value: 0, where: { field: image, matches: \"app(?=:latest)\" } }",
    );
    let err = parse_pack_yaml(&where_yaml).unwrap_err().to_string();
    assert!(err.contains("NAME-LOOKBEHIND"), "{err}");

    // At runtime an unvalidated bad pattern is unknown, not a panic.
    let c = leaf(json!({"field": "name", "operator": "matches", "value": "(?<!x)prod"}));
    assert_eq!(evaluate_check(&c, &json!({"name": "prod"})).outcome, Unknown);
}

#[test]
fn validation_rejects_bad_operator_arguments_and_unknown_kinds() {
    let base = |target: &str| {
        format!(
            "schema_version: 1\nid: T\nname: T\nrevision: \"1\"\ncontrols:\n  - id: C-1\n    source: {{ document: d, revision: \"1\", clause: \"1\" }}\n    owner: o\n    severity: low\n    targets:\n      - {target}\n"
        )
    };
    let cases = [
        ("resource_kind: no_such_kind\n        check: { field: name, operator: exists }", "unknown resource_kind"),
        ("resource_kind: storage_account\n        check: { field: p, operator: ordinal_gte, value: TLS1_2 }", "order"),
        ("resource_kind: storage_account\n        check: { field: p, operator: ordinal_gte, order: [A, B], value: C }", "not in order"),
        ("resource_kind: storage_account\n        check: { field: p, operator: length_between, min: 3 }", "min and max"),
        ("resource_kind: storage_account\n        check: { field: p, operator: count_where_gte, value: 1 }", "where"),
        ("resource_kind: storage_account\n        check: { field: p, operator: gte, value: many }", "numeric"),
        ("resource_kind: storage_account\n        check: { field: p, operator: in, value: eastus }", "list"),
    ];
    for (target, needle) in cases {
        let err = parse_pack_yaml(&base(target)).unwrap_err().to_string();
        assert!(err.contains("C-1") && err.contains(needle), "{needle}: {err}");
    }
    let no_check = "schema_version: 1\nid: T\nname: T\nrevision: \"1\"\ncontrols:\n  - id: EMPTY\n    source: { document: d, revision: \"1\", clause: \"1\" }\n    owner: o\n    severity: low\n";
    let err = parse_pack_yaml(no_check).unwrap_err().to_string();
    assert!(err.contains("EMPTY"), "{err}");
}

// ---------------------------------------------------------------------------
// Joins (Phase 5 stub) and determinism
// ---------------------------------------------------------------------------

#[test]
fn join_leaf_without_join_is_unknown() {
    let c = leaf(json!({"field": "join.subnet.properties.delegations", "operator": "count_eq", "value": 0, "evidence_source": "join"}));
    let r = evaluate_check(&c, &json!({"properties": {}}));
    assert_eq!(r.outcome, Unknown);
    assert_eq!(r.detail, "joined subnet is outside the visible scope");
}

#[test]
fn evaluation_is_deterministic_and_uses_evidence_time() {
    let p = pack(
        r#"
  - id: KV-1
    source: { document: d, revision: "1", clause: "1" }
    owner: o
    severity: high
    targets:
      - resource_kind: key_vault
        check:
          all_of:
            - { name: purge protection, field: properties.enablePurgeProtection, operator: equals, value: true, when_absent: false }
            - { name: soft delete, field: properties.enableSoftDelete, operator: equals, value: true, when_absent: true }
"#,
    );
    let kv = obs("kv1", "Microsoft.KeyVault/vaults", json!({}), json!({}));
    let a = run(&p, std::slice::from_ref(&kv));
    let b = run(&p, std::slice::from_ref(&kv));
    assert_eq!(a.evaluations[0].outcome, b.evaluations[0].outcome);
    assert_eq!(a.evaluations[0].detail, b.evaluations[0].detail);
    assert_eq!(a.evaluations[0].evaluated_at, kv.observation_time);
    assert_eq!(a.evaluations[0].control_revision, "4");
    assert_eq!(
        a.evaluations[0].detail,
        "purge protection is false; expected true (property absent; Azure default assumed)"
    );
    assert_eq!(a.evaluations[0].evidence["assumed_default"], true);
    assert_eq!(a.evaluations[0].evidence["leaves"].as_array().unwrap().len(), 2);
}
