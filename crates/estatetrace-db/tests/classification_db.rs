//! P4: classification rule persistence and resource-group tags (spec §4.6). Fictional names only.

use chrono::Utc;
use estatetrace_core::*;
use estatetrace_db as db;
use serde_json::json;

#[tokio::test]
async fn rules_round_trip_pattern_and_segment_map() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("c.db")).await.unwrap();
    for r in suggested_rules() {
        db::upsert_classification_rule(&pool, &r).await.unwrap();
    }
    let mut back = db::list_classification_rules(&pool).await.unwrap();
    back.sort_by_key(|r| std::cmp::Reverse(r.priority));
    let want = suggested_rules();
    assert_eq!(back.len(), want.len());
    for (a, b) in back.iter().zip(want.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.kind, b.kind);
        assert_eq!(a.pattern, b.pattern);
        assert_eq!(a.segment_map, b.segment_map);
        assert_eq!(a.environment, b.environment);
    }
}

#[tokio::test]
async fn resource_group_tags_upsert_is_case_insensitive_on_rg() {
    let dir = tempfile::tempdir().unwrap();
    let pool = db::open_db(&dir.path().join("rg.db")).await.unwrap();
    let row = |rg: &str, env: &str| ResourceGroupTags {
        subscription_id: SubscriptionId::new("sub-contoso-01"),
        resource_group: rg.into(),
        tags: json!({ "Environment": env }),
        observed_at: Utc::now(),
    };
    db::upsert_resource_group_tags(&pool, &[row("RG-App", "dev")]).await.unwrap();
    db::upsert_resource_group_tags(&pool, &[row("rg-app", "prod"), row("rg-other", "dev")])
        .await
        .unwrap();
    let all = db::get_resource_group_tags(&pool, Some("sub-contoso-01")).await.unwrap();
    assert_eq!(all.len(), 2);
    let app = all.iter().find(|r| r.resource_group.eq_ignore_ascii_case("rg-app")).unwrap();
    assert_eq!(app.tags["Environment"], "prod");
    assert!(db::get_resource_group_tags(&pool, Some("sub-other")).await.unwrap().is_empty());
    assert_eq!(db::get_resource_group_tags(&pool, None).await.unwrap().len(), 2);
}
