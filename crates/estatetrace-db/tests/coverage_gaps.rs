//! P1: coverage gaps persist per pack and are replaced by each scan (spec §4.4, AC-P1-8).

use estatetrace_core::{CoverageGap, GapCategory};
use estatetrace_db as db;

fn gap(control: &str, category: GapCategory, rtype: Option<&str>, count: u64) -> CoverageGap {
    CoverageGap {
        pack_id: "PACK-A".into(),
        control_id: control.into(),
        category,
        note: format!("{control} note"),
        resource_type: rtype.map(str::to_string),
        resource_count: count,
    }
}

#[tokio::test]
async fn coverage_gaps_replace_per_pack() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("g.db")).await.unwrap();
    assert!(db::schema_version(&pool).await.unwrap() >= 2);

    let first = vec![
        gap("C-1", GapCategory::OutsideAzure, None, 0),
        gap("C-2", GapCategory::DeepCollection, Some("microsoft.storage/storageaccounts"), 4),
    ];
    db::replace_coverage_gaps(&pool, "PACK-A", "1", "scan-1", &first).await.unwrap();
    let mut other = gap("X-1", GapCategory::NeedsDecision, None, 0);
    other.pack_id = "PACK-B".into();
    db::replace_coverage_gaps(&pool, "PACK-B", "7", "scan-1", &[other]).await.unwrap();

    let a = db::list_coverage_gaps(&pool, Some("PACK-A")).await.unwrap();
    assert_eq!(a, first);
    assert_eq!(db::list_coverage_gaps(&pool, None).await.unwrap().len(), 3);

    // A later scan replaces PACK-A's set and leaves PACK-B alone.
    let second = vec![gap("C-2", GapCategory::DeepCollection, Some("microsoft.storage/storageaccounts"), 6)];
    db::replace_coverage_gaps(&pool, "PACK-A", "2", "scan-2", &second).await.unwrap();
    assert_eq!(db::list_coverage_gaps(&pool, Some("PACK-A")).await.unwrap(), second);
    assert_eq!(db::list_coverage_gaps(&pool, Some("PACK-B")).await.unwrap().len(), 1);
}
