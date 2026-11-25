use estatetrace_policy::{builtin_resource_kinds, coverage_report, pilot_pack, run_example_cases};

#[test]
fn pilot_examples_pass() {
    let pack = pilot_pack();
    let results = run_example_cases(&pack, builtin_resource_kinds()).expect("examples");
    for r in &results {
        assert!(r.ok, "{}: expected={} got={}", r.name, r.expected, r.got);
    }
    let cov = coverage_report(&pack);
    assert_eq!(cov.clauses.len(), 5);
    assert!(cov.clauses.iter().any(|c| c.automation == "manual_evidence"));
}
