use estatetrace_policy::{pilot_pack, run_example_cases, coverage_report};

#[test]
fn pilot_examples_pass() {
    let pack = pilot_pack();
    let results = run_example_cases(&pack).expect("examples");
    for (name, ok, detail) in &results {
        assert!(ok, "{name}: {detail}");
    }
    let cov = coverage_report(&pack);
    assert_eq!(cov.clauses.len(), 5);
    assert!(cov.clauses.iter().any(|c| c.automation == "manual_evidence"));
}