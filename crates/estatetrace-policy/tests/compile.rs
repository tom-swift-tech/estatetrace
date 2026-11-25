//! Phase 7: check-map compile (spec §4.8, AC-P7-1..4). Fictional catalogs only.

use estatetrace_core::GapCategory;
use estatetrace_policy::{
    builtin_resource_kinds, compile_check_map, coverage_report, map_level, parse_catalog,
    parse_check_map_yaml, parse_compile_settings, parse_pack_json, run_example_cases,
    validate_pack, Check, ControlStatus, EvidenceSource, ExampleCase, LintIssue, LintSeverity,
    Operator, PolicyPack,
};
use serde_json::json;

const FIX_CATALOG: &str =
    include_str!("../../../kits/policy-authoring/examples/check_map/catalog.yaml");
const FIX_MAP: &str =
    include_str!("../../../kits/policy-authoring/examples/check_map/check_map.yaml");
const FIX_SETTINGS: &str =
    include_str!("../../../kits/policy-authoring/examples/check_map/settings.yaml");

fn compile(catalog: &str, map: &str, settings: &str) -> (PolicyPack, Vec<LintIssue>) {
    let catalog = parse_catalog(catalog).expect("catalog parses");
    let map = parse_check_map_yaml(map).expect("check map parses");
    let settings = parse_compile_settings(settings).expect("settings parse");
    compile_check_map(&catalog, &map, &settings, builtin_resource_kinds()).expect("compile")
}

fn errors(issues: &[LintIssue]) -> Vec<&LintIssue> {
    issues
        .iter()
        .filter(|i| i.severity == LintSeverity::Error)
        .collect()
}

fn warnings(issues: &[LintIssue]) -> Vec<&LintIssue> {
    issues
        .iter()
        .filter(|i| i.severity == LintSeverity::Warning)
        .collect()
}

fn has_error(issues: &[LintIssue], control: &str, needle: &str) -> bool {
    errors(issues)
        .iter()
        .any(|i| i.control_id.as_deref() == Some(control) && i.message.contains(needle))
}

/// A small fictional catalog: three controls, IDs `T-1`..`T-3`.
const CAT3: &str = r#"
catalog:
  catalog_id: TEST-CAT
  catalog_version: "1"
  title: Test catalog
  issuing_department: Test Office
controls:
  - { control_id: T-1, name: First, requirement_level: must }
  - { control_id: T-2, name: Second, requirement_level: should }
  - { control_id: T-3, name: Third, requirement_level: may }
"#;

/// Bindings for T-1 and T-2 only; append text to extend.
const MAP_HEAD: &str = r#"
catalog_id: TEST-CAT
verified: true
checks:
  T-1:
    targets:
      - { resource_kind: storage_account, name: https, path: properties.supportsHttpsTrafficOnly, expected: true, when_absent: true }
  T-2:
    targets:
      - { resource_kind: key_vault, path: properties.enablePurgeProtection, expected: true }
"#;

fn map_with(extra: &str) -> String {
    format!("{MAP_HEAD}{extra}")
}

const T3_SKIPPED: &str = r#"
not_evaluated:
  T-3: { category: outside_azure, note: Records outside Azure. }
"#;

// ---------------------------------------------------------------------------
// Fixture (AC-P7-2, AC-P7-3 warning, AC-P7-4)
// ---------------------------------------------------------------------------

#[test]
fn ac_p7_4_fixture_compiles_and_passes_validate_pack() {
    let (pack, issues) = compile(FIX_CATALOG, FIX_MAP, FIX_SETTINGS);
    assert!(errors(&issues).is_empty(), "{issues:#?}");
    assert_eq!(pack.id, "EXAMPLE-WORKPLACE-CATALOG");
    assert!(pack.revision.starts_with("2.1+"), "revision {}", pack.revision);
    assert_eq!(pack.owner.as_deref(), Some("Example Cloud Governance Office"));
    let ids: Vec<&str> = pack.controls.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "EXW-STG-01",
            "EXW-AVD-02/pooled",
            "EXW-AVD-02/personal",
            "EXW-IAM-03",
            "EXW-REG-04"
        ]
    );
    validate_pack(&pack, builtin_resource_kinds()).expect("validate_pack");

    // Import path: the JSON the UI posts to /api/packs parses and validates.
    let text = serde_json::to_string(&pack).unwrap();
    let back = parse_pack_json(&text).expect("parse_pack_json");
    assert_eq!(back.controls.len(), 5);

    // Source and evidence come from the catalog.
    let stg = &pack.controls[0];
    assert_eq!(stg.source.document, "Example Workplace Cloud Standard");
    assert_eq!(stg.source.clause, "3.2");
    assert_eq!(stg.source.revision, "2.1");
    assert_eq!(stg.severity, "high");
    assert_eq!(stg.evidence_requirements.len(), 2);
    assert!(stg.fix.as_deref().unwrap().contains("TLS1_2"));
    assert!(stg.judges.as_deref().unwrap().contains("minimum TLS version"));

    // Two not_evaluated categories, reported by coverage_report.
    let cov = coverage_report(&pack);
    assert_eq!(cov.controls_total, 5);
    assert_eq!(cov.controls_evaluated, 3);
    assert_eq!(cov.not_evaluated.get(&GapCategory::OutsideAzure), Some(&1));
    assert_eq!(cov.not_evaluated.get(&GapCategory::NeedsDecision), Some(&1));
    let iam = pack.controls.iter().find(|c| c.id == "EXW-IAM-03").unwrap();
    assert!(iam.targets.is_empty());
    assert_eq!(iam.judges.as_deref(), Some("Privileged access is reviewed every quarter"));
}

#[test]
fn fixture_leaves_map_onto_estatetrace_fields() {
    let (pack, _) = compile(FIX_CATALOG, FIX_MAP, FIX_SETTINGS);
    let stg = &pack.controls[0];
    assert_eq!(stg.targets.len(), 1);
    assert_eq!(stg.targets[0].resource_kind.as_deref(), Some("storage_account"));
    let Check::AllOf { all_of } = &stg.targets[0].check else {
        panic!("all_of expected");
    };
    assert_eq!(all_of.len(), 2);
    let tls = &all_of[0];
    assert_eq!(tls.name.as_deref(), Some("minimum TLS"));
    assert_eq!(tls.field, "properties.minimumTlsVersion");
    assert_eq!(tls.operator, Operator::OrdinalGte);
    assert_eq!(tls.value, Some(json!("TLS1_2")));
    assert_eq!(tls.when_absent, Some(json!("TLS1_0")));
    assert_eq!(tls.order.as_ref().unwrap().len(), 3);
    assert_eq!(all_of[1].operator, Operator::Equals);
    assert_eq!(all_of[1].value, Some(json!(false)));

    // expected_setting resolved from named_values.
    let pooled = &pack.controls[1];
    let Check::Leaf(leaf) = &pooled.targets[0].check else {
        panic!("leaf expected");
    };
    assert_eq!(leaf.operator, Operator::In);
    assert_eq!(leaf.value, Some(json!(["Disabled", "EnabledForClientsOnly"])));
}

#[test]
fn ac_p7_2_variants_compile_with_own_severity_and_filter() {
    let (mut pack, issues) = compile(FIX_CATALOG, FIX_MAP, FIX_SETTINGS);
    assert!(errors(&issues).is_empty(), "{issues:#?}");
    let pooled = pack.controls.iter().find(|c| c.id == "EXW-AVD-02/pooled").unwrap();
    let personal = pack.controls.iter().find(|c| c.id == "EXW-AVD-02/personal").unwrap();
    assert_eq!(pooled.severity, "high");
    assert_eq!(personal.severity, "medium");
    let f1 = pooled.targets[0].filter.as_ref().unwrap();
    let f2 = personal.targets[0].filter.as_ref().unwrap();
    assert_eq!(f1.field, "properties.hostPoolType");
    assert_eq!(f1.value, Some(json!("Pooled")));
    assert_eq!(f2.value, Some(json!("Personal")));
    assert!(pooled.judges.as_deref().unwrap().contains("public network access"));
    assert!(personal.judges.as_deref().unwrap().contains("Variant: Personal pools"));
    assert!(pack.controls.iter().all(|c| c.id != "EXW-AVD-02"));

    // The filters select: a pooled pool is judged only by the pooled variant.
    let pool = |t: &str, access: &str| {
        json!({ "type": "Microsoft.DesktopVirtualization/hostpools",
                "properties": { "hostPoolType": t, "publicNetworkAccess": access } })
    };
    let case = |cid: &str, name: &str, resource, expected: &str| ExampleCase {
        control_id: cid.into(),
        name: name.into(),
        resource,
        environment: None,
        expected: expected.into(),
    };
    pack.example_cases = vec![
        case("EXW-AVD-02/pooled", "pooled open", pool("Pooled", "Enabled"), "fail"),
        case("EXW-AVD-02/pooled", "pooled closed", pool("Pooled", "Disabled"), "pass"),
        case("EXW-AVD-02/pooled", "personal ignored", pool("Personal", "Enabled"), "not_selected"),
        case("EXW-AVD-02/personal", "personal open", pool("Personal", "Enabled"), "fail"),
        case(
            "EXW-AVD-02/personal",
            "personal absent",
            json!({ "type": "Microsoft.DesktopVirtualization/hostpools", "properties": { "hostPoolType": "Personal" } }),
            "fail",
        ),
    ];
    for r in run_example_cases(&pack, builtin_resource_kinds()).unwrap() {
        assert!(r.ok, "{}: expected {} got {} ({})", r.name, r.expected, r.got, r.detail);
    }
}

// ---------------------------------------------------------------------------
// AC-P7-1: coverage lint
// ---------------------------------------------------------------------------

#[test]
fn ac_p7_1_control_in_neither_list_is_an_error_naming_it() {
    let (pack, issues) = compile(CAT3, MAP_HEAD, "");
    let errs = errors(&issues);
    assert_eq!(errs.len(), 1, "{issues:#?}");
    assert_eq!(errs[0].control_id.as_deref(), Some("T-3"));
    assert!(errs[0].message.contains("neither checks nor not_evaluated"));
    assert!(pack.controls.iter().all(|c| c.id != "T-3"));

    // Accounting for it clears the error.
    let (_, issues) = compile(CAT3, &map_with(T3_SKIPPED), "");
    assert!(errors(&issues).is_empty(), "{issues:#?}");
}

#[test]
fn control_in_both_lists_is_an_error() {
    let extra = format!(
        "{T3_SKIPPED}  T-1: {{ category: needs_decision, note: duplicate }}\n"
    );
    let (_, issues) = compile(CAT3, &map_with(&extra), "");
    assert!(has_error(&issues, "T-1", "both checks and not_evaluated"), "{issues:#?}");
}

#[test]
fn map_entry_not_in_catalog_is_a_warning() {
    let extra = format!("{T3_SKIPPED}  T-99: {{ category: outside_azure, note: gone }}\n");
    let (_, issues) = compile(CAT3, &map_with(&extra), "");
    assert!(errors(&issues).is_empty(), "{issues:#?}");
    assert!(warnings(&issues)
        .iter()
        .any(|i| i.control_id.as_deref() == Some("T-99") && i.message.contains("not in the catalog")));
}

// ---------------------------------------------------------------------------
// AC-P7-3: kinds, expected_setting, verified
// ---------------------------------------------------------------------------

#[test]
fn ac_p7_3_unknown_resource_kind_is_an_error() {
    let map = map_with(T3_SKIPPED).replace("resource_kind: key_vault", "resource_kind: flux_capacitor");
    let (pack, issues) = compile(CAT3, &map, "");
    assert!(has_error(&issues, "T-2", "resource_kind 'flux_capacitor'"), "{issues:#?}");
    assert!(pack.controls.iter().all(|c| c.id != "T-2"), "no half-compiled control");
}

#[test]
fn ac_p7_3_missing_expected_setting_is_an_error() {
    let (_, issues) = compile(FIX_CATALOG, FIX_MAP, "named_values: {}");
    assert!(
        has_error(&issues, "EXW-AVD-02/pooled", "expected_setting 'approved_host_pool_access'"),
        "{issues:#?}"
    );
    assert!(has_error(&issues, "EXW-AVD-02/personal", "expected_setting"));
}

#[test]
fn ac_p7_3_verified_false_warns_and_every_control_is_provisional() {
    let (pack, issues) = compile(FIX_CATALOG, FIX_MAP, FIX_SETTINGS);
    assert!(warnings(&issues)
        .iter()
        .any(|i| i.control_id.is_none() && i.message.contains("verified: false")));
    assert!(pack.controls.iter().all(|c| c.status == ControlStatus::Provisional));

    let verified = FIX_MAP.replace("verified: false", "verified: true");
    let (pack, issues) = compile(FIX_CATALOG, &verified, FIX_SETTINGS);
    assert!(!issues.iter().any(|i| i.message.contains("verified")), "{issues:#?}");
    assert!(pack.controls.iter().all(|c| c.status == ControlStatus::Verified));
}

#[test]
fn scalar_setting_is_wrapped_for_list_operators() {
    let map = map_with(T3_SKIPPED).replace(
        "path: properties.enablePurgeProtection, expected: true",
        "path: location, operator: in, expected_setting: home_region",
    );
    let (pack, issues) = compile(CAT3, &map, "named_values: { home_region: westeurope }");
    assert!(errors(&issues).is_empty(), "{issues:#?}");
    let Check::Leaf(l) = &pack.controls[1].targets[0].check else { panic!() };
    assert_eq!(l.value, Some(json!(["westeurope"])));
}

// ---------------------------------------------------------------------------
// Variants
// ---------------------------------------------------------------------------

#[test]
fn target_filter_plus_variant_filter_is_an_error() {
    let map = FIX_MAP.replace("\r\n", "\n").replace(
        "        name: public network access\n",
        "        name: public network access\n        filter: { path: location, expected: westeurope }\n",
    );
    let (_, issues) = compile(FIX_CATALOG, &map, FIX_SETTINGS);
    assert!(
        has_error(&issues, "EXW-AVD-02/pooled", "own filter cannot be used with a variant filter"),
        "{issues:#?}"
    );
}

#[test]
fn variant_with_bad_level_or_empty_suffix_is_an_error() {
    let map = FIX_MAP.replace("level: should", "level: sometimes");
    let (_, issues) = compile(FIX_CATALOG, &map, FIX_SETTINGS);
    assert!(has_error(&issues, "EXW-AVD-02/personal", "variant severity 'sometimes'"));

    let map = FIX_MAP.replace("- suffix: pooled", "- suffix: \"\"");
    let (_, issues) = compile(FIX_CATALOG, &map, FIX_SETTINGS);
    assert!(has_error(&issues, "EXW-AVD-02", "no suffix"), "{issues:#?}");
}

// ---------------------------------------------------------------------------
// suppress and check_overrides
// ---------------------------------------------------------------------------

#[test]
fn suppress_drops_the_control_and_records_the_reason() {
    let settings = r#"
suppress:
  - { control: T-2, reason: Also asserted by the platform catalog, duplicate_of: PLAT-9 }
  - { control: T-77, reason: stale }
"#;
    // T-2 suppressed counts as accounted, even without a binding.
    let (pack, issues) = compile(CAT3, &map_with(T3_SKIPPED), settings);
    assert!(errors(&issues).is_empty(), "{issues:#?}");
    assert!(pack.controls.iter().all(|c| c.id != "T-2"));
    let w = warnings(&issues);
    assert!(w.iter().any(|i| i.control_id.as_deref() == Some("T-2")
        && i.message.contains("suppressed")
        && i.message.contains("duplicate of PLAT-9")
        && i.message.contains("Also asserted by the platform catalog")));
    assert!(w.iter().any(|i| i.control_id.as_deref() == Some("T-77")));
}

#[test]
fn check_override_replaces_one_leaf_and_keeps_the_reason() {
    let settings = r#"
check_overrides:
  EXW-STG-01:
    leaf: minimum TLS
    reason: Legacy partner integration accepted until review
    expected: TLS1_1
"#;
    let (pack, issues) = compile(FIX_CATALOG, FIX_MAP, settings);
    // Without named_values the AVD variants fail; only look at the storage control.
    assert!(!errors(&issues).iter().any(|i| i.control_id.as_deref() == Some("EXW-STG-01")));
    let stg = &pack.controls[0];
    let Check::AllOf { all_of } = &stg.targets[0].check else { panic!() };
    assert_eq!(all_of[0].value, Some(json!("TLS1_1")));
    assert_eq!(all_of[0].when_absent, Some(json!("TLS1_0")), "other fields kept");
    assert_eq!(all_of[0].note.as_deref(), Some("Legacy partner integration accepted until review"));
    assert_eq!(all_of[1].value, Some(json!(false)), "other leaf untouched");
    assert!(stg
        .judges
        .as_deref()
        .unwrap()
        .contains("(override: Legacy partner integration accepted until review)"));
}

#[test]
fn check_override_on_a_variant_id_and_single_leaf_without_selector() {
    let settings = format!(
        "{FIX_SETTINGS}\n"
    )
    .replace(
        "check_overrides: {}",
        "check_overrides:\n  EXW-AVD-02/personal: { reason: Personal pools may use any setting, operator: exists }",
    );
    let (pack, issues) = compile(FIX_CATALOG, FIX_MAP, &settings);
    assert!(errors(&issues).is_empty(), "{issues:#?}");
    let pooled = pack.controls.iter().find(|c| c.id == "EXW-AVD-02/pooled").unwrap();
    let personal = pack.controls.iter().find(|c| c.id == "EXW-AVD-02/personal").unwrap();
    let Check::Leaf(p) = &pooled.targets[0].check else { panic!() };
    let Check::Leaf(q) = &personal.targets[0].check else { panic!() };
    assert_eq!(p.operator, Operator::In);
    assert_eq!(q.operator, Operator::Exists);
    assert!(personal.judges.as_deref().unwrap().contains("override"));
}

#[test]
fn check_override_lint_paths() {
    let run = |ov: &str| compile(CAT3, &map_with(T3_SKIPPED), &format!("check_overrides:\n{ov}")).1;

    let issues = run("  T-1: { leaf: https, expected: false }");
    assert!(has_error(&issues, "T-1", "needs a reason"), "{issues:#?}");

    let issues = run("  T-1: { leaf: nope, reason: r, expected: false }");
    assert!(has_error(&issues, "T-1", "matches no leaf"), "{issues:#?}");

    let issues = run("  T-1: just text");
    assert!(has_error(&issues, "T-1", "not a map"), "{issues:#?}");

    let issues = run("  T-1: { leaf: https, reason: r, expected_setting: missing_name }");
    assert!(has_error(&issues, "T-1", "expected_setting 'missing_name'"), "{issues:#?}");

    let issues = run("  T-9: { reason: r, expected: 1 }");
    assert!(errors(&issues).is_empty(), "{issues:#?}");
    assert!(warnings(&issues).iter().any(|i| i.control_id.as_deref() == Some("T-9")));

    // A selector is required when the control has more than one leaf.
    let issues = compile(
        FIX_CATALOG,
        FIX_MAP,
        &FIX_SETTINGS.replace(
            "check_overrides: {}",
            "check_overrides:\n  EXW-STG-01: { reason: r, expected: TLS1_1 }",
        ),
    )
    .1;
    assert!(has_error(&issues, "EXW-STG-01", "needs `leaf`"), "{issues:#?}");
}

// ---------------------------------------------------------------------------
// Other lint paths
// ---------------------------------------------------------------------------

#[test]
fn catalog_lint_paths() {
    // Duplicate, missing ID, bad level.
    let cat = r#"
catalog: { catalog_id: TEST-CAT }
controls:
  - { control_id: T-1, requirement_level: must }
  - { control_id: T-1, requirement_level: must }
  - { name: no id, requirement_level: must }
  - { control_id: T-2, requirement_level: sometimes }
  - just a string
"#;
    let map = "catalog_id: TEST-CAT\nnot_evaluated:\n  T-1: { category: outside_azure, note: n }\n  T-2: { category: outside_azure, note: n }\n";
    let (_, issues) = compile(cat, map, "");
    assert!(has_error(&issues, "T-1", "appears twice"), "{issues:#?}");
    assert!(has_error(&issues, "T-2", "requirement_level 'sometimes'"));
    assert!(errors(&issues).iter().any(|i| i.message.contains("#3 has no control_id")));
    assert!(errors(&issues).iter().any(|i| i.message.contains("#5 is not a map")));
    // No owner anywhere: a warning, and the control still validates.
    assert!(warnings(&issues).iter().any(|i| i.message.contains("names no owner")));

    // Catalog ID mismatch.
    let (_, issues) = compile(CAT3, &map_with(T3_SKIPPED).replace("catalog_id: TEST-CAT", "catalog_id: OTHER"), "");
    assert!(errors(&issues)
        .iter()
        .any(|i| i.control_id.is_none() && i.message.contains("check map is for catalog 'OTHER'")));
}

#[test]
fn level_mapping_table() {
    for (raw, want) in [
        ("must", "high"),
        ("must_conditional", "high"),
        ("MUST", "high"),
        ("error", "high"),
        ("should", "medium"),
        ("should_conditional", "medium"),
        ("warning", "medium"),
        ("may", "low"),
        ("critical", "critical"),
        ("low", "low"),
    ] {
        assert_eq!(map_level(raw).map(|s| s.as_str()), Some(want), "{raw}");
    }
    assert!(map_level("sometimes").is_none());

    // An explicit control severity wins over the requirement level.
    let cat = CAT3.replace("{ control_id: T-1, name: First, requirement_level: must }",
                           "{ control_id: T-1, name: First, requirement_level: must, severity: critical }");
    let (pack, _) = compile(&cat, &map_with(T3_SKIPPED), "");
    assert_eq!(pack.controls[0].severity, "critical");
    assert_eq!(pack.controls[1].severity, "medium");
    assert_eq!(pack.controls[2].severity, "low");
}

#[test]
fn revision_falls_back_to_a_stable_content_hash() {
    let cat = CAT3.replace("  catalog_version: \"1\"\n", "");
    let (a, _) = compile(&cat, &map_with(T3_SKIPPED), "");
    let (b, _) = compile(&cat, &map_with(T3_SKIPPED), "");
    assert!(a.revision.starts_with("c-") && a.revision.len() == 18, "{}", a.revision);
    assert_eq!(a.revision, b.revision, "deterministic");
    assert_eq!(a.controls[0].source.revision, a.revision);
    let changed = map_with(T3_SKIPPED).replace("expected: true, when_absent: true", "expected: false");
    let (c, _) = compile(&cat, &changed, "");
    assert_ne!(a.revision, c.revision, "a map change changes the hash");
}

#[test]
fn leaf_lint_and_pack_lint_errors_are_compile_errors() {
    // No path.
    let map = map_with(T3_SKIPPED).replace("path: properties.enablePurgeProtection, ", "");
    let (_, issues) = compile(CAT3, &map, "");
    assert!(has_error(&issues, "T-2", "no path"), "{issues:#?}");

    // Unsupported regex (invariant 16), caught by the pack lint validate_pack runs.
    let map = map_with(T3_SKIPPED).replace(
        "path: properties.enablePurgeProtection, expected: true",
        "path: name, operator: matches, expected: \"(?<!x)prod\"",
    );
    let (_, issues) = compile(CAT3, &map, "");
    assert!(has_error(&issues, "T-2", "not a supported regular expression"), "{issues:#?}");

    // No targets.
    let map = map_with(T3_SKIPPED).replace(
        "    targets:\n      - { resource_kind: key_vault, path: properties.enablePurgeProtection, expected: true }\n",
        "    targets: []\n",
    );
    let (_, issues) = compile(CAT3, &map, "");
    assert!(has_error(&issues, "T-2", "no targets"), "{issues:#?}");

    // expected_setting on an all_of target.
    let map = map_with(T3_SKIPPED).replace(
        "      - { resource_kind: key_vault, path: properties.enablePurgeProtection, expected: true }",
        "      - resource_kind: key_vault\n        expected_setting: x\n        all_of:\n          - { path: properties.enablePurgeProtection, expected: true }",
    );
    let (_, issues) = compile(CAT3, &map, "named_values: { x: true }");
    assert!(has_error(&issues, "T-2", "expected_setting on an all_of target"), "{issues:#?}");
}

#[test]
fn where_context_and_options_map_onto_leaf_fields() {
    let map = map_with(T3_SKIPPED).replace(
        "      - { resource_kind: key_vault, path: properties.enablePurgeProtection, expected: true }",
        r#"      - resource_kind: key_vault
        name: approved private links
        path: properties.privateEndpointConnections
        operator: count_where_gte
        expected: 1
        where: { path: properties.privateLinkServiceConnectionState.status, equals: Approved }
        context: [{ label: public access, path: properties.publicNetworkAccess }]
        note: "  spaced   note "
        evidence_source: join
      - resource_kind: storage_account
        path: name
        operator: matches
        expected: "^st"
        case_sensitive: true
      - resource_kind: storage_account
        path: name
        operator: length_between
        min: 3
        max: 24"#,
    );
    let (pack, issues) = compile(CAT3, &map, "");
    assert!(errors(&issues).is_empty(), "{issues:#?}");
    let t = &pack.controls[1].targets;
    let Check::Leaf(a) = &t[0].check else { panic!() };
    assert_eq!(a.operator, Operator::CountWhereGte);
    let w = a.where_.as_ref().unwrap();
    assert_eq!(w.field, "properties.privateLinkServiceConnectionState.status");
    assert_eq!(w.equals, Some(json!("Approved")));
    assert_eq!(a.context[0].field, "properties.publicNetworkAccess");
    assert_eq!(a.note.as_deref(), Some("spaced note"));
    assert_eq!(a.evidence_source, EvidenceSource::Join);
    let Check::Leaf(b) = &t[1].check else { panic!() };
    assert!(b.case_sensitive);
    let Check::Leaf(c) = &t[2].check else { panic!() };
    assert_eq!((c.min, c.max), (Some(3), Some(24)));
}

#[test]
fn parse_errors_and_json_input() {
    assert!(parse_catalog("controls: 3").is_err());
    assert!(parse_catalog("- a\n- b").is_err());
    let err = parse_check_map_yaml(
        "catalog_id: X\nchecks:\n  A:\n    targets:\n      - { resource_kind: key_vault, path: p, expectd: 1 }\n",
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("expectd"), "{err}");
    let err = parse_check_map_yaml(
        "catalog_id: X\nchecks:\n  A:\n    targets:\n      - { resource_kind: key_vault, path: p, operator: sounds_like }\n",
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("sounds_like"), "{err}");
    assert!(parse_compile_settings("").unwrap().named_values.is_empty());

    // JSON text works for all three inputs.
    let cat = serde_json::to_string(&parse_catalog(CAT3).unwrap()).unwrap();
    let map = serde_json::to_string(&parse_check_map_yaml(&map_with(T3_SKIPPED)).unwrap()).unwrap();
    let (pack, issues) = compile(&cat, &map, "{\"named_values\": {}}");
    assert!(errors(&issues).is_empty(), "{issues:#?}");
    assert_eq!(pack.controls.len(), 3);
}

#[test]
fn fixture_is_fictional() {
    // Built at runtime so this file does not itself match the invariant-15 grep.
    let tag_prefix = ["fn", "f_"].concat();
    let catalog_prefix = ["FN", "F-"].concat();
    for text in [FIX_CATALOG, FIX_MAP, FIX_SETTINGS] {
        assert!(!text.contains(&tag_prefix), "invariant 15");
        assert!(!text.to_ascii_uppercase().contains(&catalog_prefix), "invariant 15");
    }
}

#[test]
fn check_map_edit_under_same_catalog_version_changes_pack_revision() {
    let (a, _) = compile(FIX_CATALOG, FIX_MAP, FIX_SETTINGS);
    let edited_map = format!("{FIX_MAP}\n# reviewed\n");
    let (same, _) = compile(FIX_CATALOG, &edited_map, FIX_SETTINGS);
    // A comment does not change the parsed map, so the revision is stable.
    assert_eq!(a.revision, same.revision);
    let edited_settings =
        FIX_SETTINGS.replacen("[Disabled, EnabledForClientsOnly]", "[Disabled]", 1);
    assert_ne!(edited_settings, FIX_SETTINGS, "fixture settings changed");
    let (b, _) = compile(FIX_CATALOG, FIX_MAP, &edited_settings);
    assert_ne!(a.revision, b.revision, "settings change must produce a new pack revision");
    assert!(b.revision.starts_with("2.1+"));
}
