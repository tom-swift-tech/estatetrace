#[cfg(test)]
mod tests {
    use crate::*;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn ac07_missing_env_tag_on_prod_subscription_stays_prod() {
        let obs = ResourceObservation {
            id: "o1".into(),
            provider: Provider::Azure,
            resource_id: ResourceId::new("/subscriptions/sub-prod/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"),
            tenant_id: TenantId::new("t1"),
            subscription_id: SubscriptionId::new("sub-prod"),
            resource_type: "Microsoft.Storage/storageAccounts".into(),
            name: "sa1".into(),
            location: Some("eastus".into()),
            resource_group: Some("rg".into()),
            tags: json!({}), // missing Environment tag
            properties: json!({}),
            scan_id: "s1".into(),
            observation_time: Utc::now(),
            evidence_available: true,
            lifecycle_epoch: 1,
            arm_meta: serde_json::json!({}),
        };
        let rules = vec![ClassificationRule {
            id: "prod-sub".into(),
            kind: ClassificationRuleKind::Subscription,
            subscription_id: Some(SubscriptionId::new("sub-prod")),
            resource_group: None,
            tag_key: None,
            tag_value: None,
            environment: EnvironmentClass::Prod,
            priority: 100,
            pattern: None,
            segment_map: None,
        }];
        let result = classify_resource(&obs, &rules);
        assert_eq!(result.environment, EnvironmentClass::Prod);
        assert!(result.missing_tag);
    }
}

/// Phase 4 (spec AC-P4-1..5). Fictional names only.
#[cfg(test)]
mod p4 {
    use crate::*;
    use chrono::Utc;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    const PROD_WORD: &str = "(?i)(^|[^a-z0-9])prod(uction)?([^a-z0-9]|$)";

    fn obs(sub: &str, rg: &str, name: &str, tags: Value) -> ResourceObservation {
        ResourceObservation {
            id: format!("obs-{name}"),
            provider: Provider::Azure,
            resource_id: ResourceId::new(format!(
                "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{name}"
            )),
            tenant_id: TenantId::new("tenant-contoso"),
            subscription_id: SubscriptionId::new(sub),
            resource_type: "Microsoft.Web/sites".into(),
            name: name.into(),
            location: Some("eastus".into()),
            resource_group: Some(rg.into()),
            tags,
            properties: json!({}),
            scan_id: "scan-1".into(),
            observation_time: Utc::now(),
            evidence_available: true,
            lifecycle_epoch: 1,
            arm_meta: serde_json::json!({}),
        }
    }

    fn rule(id: &str, kind: ClassificationRuleKind, env: EnvironmentClass, priority: i32) -> ClassificationRule {
        ClassificationRule {
            id: id.into(),
            kind,
            subscription_id: None,
            resource_group: None,
            tag_key: None,
            tag_value: None,
            environment: env,
            priority,
            pattern: None,
            segment_map: None,
        }
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn name_pattern_rule() -> ClassificationRule {
        ClassificationRule {
            pattern: Some(PROD_WORD.into()),
            ..rule("subname-prod", ClassificationRuleKind::SubscriptionNamePattern, EnvironmentClass::Prod, 490)
        }
    }

    #[test]
    fn ac_p4_1_subscription_name_pattern_is_whole_token() {
        let o = obs("sub-1", "rg-web", "app1", json!({}));
        let rules = vec![name_pattern_rule()];
        let classify_name = |name: &str| {
            classify(
                &ClassifyInput { obs: &o, subscription_name: Some(name), rg_tags: None },
                &rules,
            )
        };
        let prod = classify_name("Corp-Prod-01");
        assert_eq!(prod.environment, EnvironmentClass::Prod);
        assert_eq!(prod.source, ClassificationSource::SubscriptionName);
        assert_eq!(prod.winning_rule_id.as_deref(), Some("subname-prod"));

        let products = classify_name("Products-Shared");
        assert_eq!(products.environment, EnvironmentClass::Unknown);
        assert_eq!(products.source, ClassificationSource::None);

        // Case-insensitive, and also when the rule pattern omits the inline flag.
        assert_eq!(classify_name("contoso-PRODUCTION").environment, EnvironmentClass::Prod);
        let no_flag = vec![ClassificationRule {
            pattern: Some("(^|[^a-z0-9])prod(uction)?([^a-z0-9]|$)".into()),
            ..name_pattern_rule()
        }];
        let r = classify(
            &ClassifyInput { obs: &o, subscription_name: Some("Contoso-Prod-01"), rg_tags: None },
            &no_flag,
        );
        assert_eq!(r.environment, EnvironmentClass::Prod);
        let r = classify(
            &ClassifyInput { obs: &o, subscription_name: Some("ProductsHub"), rg_tags: None },
            &no_flag,
        );
        assert_eq!(r.environment, EnvironmentClass::Unknown);
    }

    #[test]
    fn ac_p4_1_suggested_rules_order_and_no_false_conflict() {
        let o = obs("sub-1", "rg", "app1", json!({}));
        let rules = suggested_rules();
        for r in &rules {
            validate_rule(r).unwrap();
        }
        let at = |name: &str| {
            classify(&ClassifyInput { obs: &o, subscription_name: Some(name), rg_tags: None }, &rules)
        };
        let np = at("Contoso-Non-Prod-02");
        assert_eq!(np.environment, EnvironmentClass::NonProd);
        assert!(!np.conflicting, "lower name patterns do not count as conflicts");
        assert_eq!(at("Contoso-NonProd").environment, EnvironmentClass::NonProd);
        assert_eq!(at("Contoso-Prod-01").environment, EnvironmentClass::Prod);
        assert_eq!(at("Contoso-Dev-Test").environment, EnvironmentClass::Dev);
        assert_eq!(at("Contoso-UAT").environment, EnvironmentClass::NonProd);
        assert_eq!(at("Contoso-Sandbox").environment, EnvironmentClass::Sandbox);
        assert_eq!(at("Products-Shared").environment, EnvironmentClass::Unknown);
        assert_eq!(
            subscription_name_environment("Contoso-Prod-01", &rules),
            Some(EnvironmentClass::Prod)
        );
        assert_eq!(subscription_name_environment("Products-Shared", &rules), None);
    }

    #[test]
    fn ac_p4_2_tag_segment() {
        let rules = vec![ClassificationRule {
            tag_key: Some("svc".into()),
            segment_map: Some(map(&[("dev", "dev"), ("prod", "prod"), ("dr", "prod")])),
            ..rule("svc-seg", ClassificationRuleKind::TagSegment, EnvironmentClass::Unknown, 300)
        }];
        let dev = classify_resource(&obs("s", "rg", "a", json!({ "svc": "1183.DEV" })), &rules);
        assert_eq!(dev.environment, EnvironmentClass::Dev);
        assert_eq!(dev.source, ClassificationSource::TagSegment);

        let prod = classify_resource(&obs("s", "rg", "a", json!({ "SVC": "272.PROD.TX" })), &rules);
        assert_eq!(prod.environment, EnvironmentClass::Prod);
        assert_eq!(prod.source, ClassificationSource::TagSegment);

        // Segment normalisation (case, spaces, -/_) and the first-word fallback.
        let dr = classify_resource(&obs("s", "rg", "a", json!({ "svc": "40.D-R" })), &rules);
        assert_eq!(dr.environment, EnvironmentClass::Prod);
        let first_word = classify_resource(&obs("s", "rg", "a", json!({ "svc": "51.Dev Payments" })), &rules);
        assert_eq!(first_word.environment, EnvironmentClass::Dev);

        // Segment 0 is the ID and is never read; unknown segments give no match.
        let none = classify_resource(&obs("s", "rg", "a", json!({ "svc": "prod.unknown" })), &rules);
        assert_eq!(none.environment, EnvironmentClass::Unknown);
        assert_eq!(none.source, ClassificationSource::None);
    }

    #[test]
    fn ac_p4_3_resource_group_tag_fallback() {
        let rules = vec![
            ClassificationRule {
                tag_key: Some("Environment".into()),
                ..rule("tag-env", ClassificationRuleKind::Tag, EnvironmentClass::Unknown, 280)
            },
            ClassificationRule {
                tag_key: Some("Environment".into()),
                ..rule("rgtag-env", ClassificationRuleKind::ResourceGroupTag, EnvironmentClass::Unknown, 270)
            },
        ];
        let o = obs("s", "rg-web", "app1", json!({}));
        let rg = json!({ "environment": "prod" });
        let r = classify(&ClassifyInput { obs: &o, subscription_name: None, rg_tags: Some(&rg) }, &rules);
        assert_eq!(r.environment, EnvironmentClass::Prod);
        assert_eq!(r.source, ClassificationSource::ResourceGroupTag);
        assert_eq!(r.winning_rule_id.as_deref(), Some("rgtag-env"));
        assert!(r.missing_tag);

        // The resource's own tag outranks the RG tag; disagreement is flagged.
        let o2 = obs("s", "rg-web", "app1", json!({ "Environment": "dev" }));
        let r2 = classify(&ClassifyInput { obs: &o2, subscription_name: None, rg_tags: Some(&rg) }, &rules);
        assert_eq!(r2.environment, EnvironmentClass::Dev);
        assert_eq!(r2.source, ClassificationSource::ResourceTag);
        assert!(r2.conflicting);

        // Equality form: tag_value given, rule environment used.
        let eq_rule = vec![ClassificationRule {
            tag_key: Some("Environment".into()),
            tag_value: Some("prod".into()),
            ..rule("rgtag-eq", ClassificationRuleKind::ResourceGroupTag, EnvironmentClass::Prod, 270)
        }];
        let r3 = classify(&ClassifyInput { obs: &o, subscription_name: None, rg_tags: Some(&rg) }, &eq_rule);
        assert_eq!(r3.environment, EnvironmentClass::Prod);
        assert_eq!(r3.source, ClassificationSource::ResourceGroupTag);
    }

    #[test]
    fn ac_p4_4_known_prod_subscription_beats_missing_tag_and_tag_rules() {
        let mut rules = suggested_rules();
        rules.push(ClassificationRule {
            subscription_id: Some(SubscriptionId::new("sub-prod")),
            ..rule("prod-sub", ClassificationRuleKind::Subscription, EnvironmentClass::Prod, 1000)
        });
        // No Environment tag; RG says dev; name token says dev.
        let o = obs("sub-prod", "rg-dev", "web-dev-01", json!({}));
        let rg = json!({ "Environment": "dev" });
        let r = classify(
            &ClassifyInput { obs: &o, subscription_name: Some("Contoso-Shared"), rg_tags: Some(&rg) },
            &rules,
        );
        assert_eq!(r.environment, EnvironmentClass::Prod);
        assert_eq!(r.source, ClassificationSource::Subscription);
        assert!(r.missing_tag);
        assert!(r.conflicting, "lower-priority dev evidence is surfaced as a conflict");

        // Prod subscription name also beats tag rules (tag rules sit below subscription rules).
        let o2 = obs("sub-x", "rg", "app", json!({ "Environment": "dev" }));
        let r2 = classify(
            &ClassifyInput { obs: &o2, subscription_name: Some("Contoso-Prod-01"), rg_tags: None },
            &suggested_rules(),
        );
        assert_eq!(r2.environment, EnvironmentClass::Prod);
        assert_eq!(r2.source, ClassificationSource::SubscriptionName);
    }

    #[test]
    fn name_token_rules() {
        let rules = vec![ClassificationRule {
            segment_map: Some(default_environment_map()),
            ..rule("tok", ClassificationRuleKind::NameToken, EnvironmentClass::Unknown, 100)
        }];
        let r = classify_resource(&obs("s", "rg", "contoso-web-UAT-01", json!({})), &rules);
        assert_eq!(r.environment, EnvironmentClass::NonProd);
        assert_eq!(r.source, ClassificationSource::NameToken);
        let r = classify_resource(&obs("s", "rg", "productsweb", json!({})), &rules);
        assert_eq!(r.environment, EnvironmentClass::Unknown);

        // Without a map, tokens go through EnvironmentClass::parse.
        let bare = vec![rule("tok2", ClassificationRuleKind::NameToken, EnvironmentClass::Unknown, 100)];
        assert_eq!(
            classify_resource(&obs("s", "rg", "vm_sbx_7", json!({})), &bare).environment,
            EnvironmentClass::Sandbox
        );

        // With a pattern, a matching token yields the rule's environment.
        let pat = vec![ClassificationRule {
            pattern: Some("^p[0-9]+$".into()),
            ..rule("tok3", ClassificationRuleKind::NameToken, EnvironmentClass::Prod, 100)
        }];
        assert_eq!(
            classify_resource(&obs("s", "rg", "sql-p01-east", json!({})), &pat).environment,
            EnvironmentClass::Prod
        );
    }

    #[test]
    fn validate_rule_rejects_bad_regex_and_missing_fields() {
        let bad = ClassificationRule {
            pattern: Some("(?<!x)prod".into()),
            ..name_pattern_rule()
        };
        let err = validate_rule(&bad).unwrap_err();
        assert!(err.contains("subname-prod"), "{err}");
        let no_pattern = rule("x", ClassificationRuleKind::SubscriptionNamePattern, EnvironmentClass::Prod, 1);
        assert!(validate_rule(&no_pattern).is_err());
        let bad_map = ClassificationRule {
            tag_key: Some("svc".into()),
            segment_map: Some(map(&[("dev", "development-ish")])),
            ..rule("y", ClassificationRuleKind::TagSegment, EnvironmentClass::Unknown, 1)
        };
        assert!(validate_rule(&bad_map).is_err());
        assert!(validate_rule(&name_pattern_rule()).is_ok());
    }

    #[test]
    fn classification_result_source_defaults_when_absent() {
        let old = json!({
            "environment": "prod",
            "winning_rule_id": "r",
            "conflicting": false,
            "missing_tag": true,
            "reason": "rule r"
        });
        let r: ClassificationResult = serde_json::from_value(old).unwrap();
        assert_eq!(r.source, ClassificationSource::None);
        let rule_json = json!({
            "id": "r", "kind": "tag", "subscription_id": null, "resource_group": null,
            "tag_key": "Environment", "tag_value": "prod", "environment": "prod", "priority": 1
        });
        let rr: ClassificationRule = serde_json::from_value(rule_json).unwrap();
        assert!(rr.pattern.is_none() && rr.segment_map.is_none());
    }

    fn ownership_cfg() -> OwnershipConfig {
        OwnershipConfig {
            application_tag: Some("app-name".into()),
            application_id_tag: Some("app-id".into()),
            owner_tag: Some("owner".into()),
            line_of_business_tag: Some("lob".into()),
            lob_rollup_pattern: Some(r"^\d+".into()),
            lob_names: map(&[("11", "Contoso Lending")]),
            placeholder_values: vec!["n/a".into()],
        }
    }

    #[test]
    fn ac_p4_5_ownership_falls_back_to_rg_and_rolls_up_lob() {
        let cfg = ownership_cfg();
        let rg = json!({ "App-Name": "Payments", "owner": "team-rg", "lob": "11.3" });

        // Resource tag missing -> RG value.
        let o = obs("s", "rg", "a", json!({}));
        let own = derive_ownership(&ClassifyInput { obs: &o, subscription_name: None, rg_tags: Some(&rg) }, &cfg);
        assert_eq!(own.application.as_deref(), Some("Payments"));
        assert!(own.from_resource_group);
        assert_eq!(own.line_of_business.as_deref(), Some("11"));
        assert_eq!(own.line_of_business_name.as_deref(), Some("Contoso Lending"));

        // Resource tag `undefined` (any case, padded) -> RG value.
        let o2 = obs("s", "rg", "a", json!({ "app-name": "  Undefined ", "owner": "N/A" }));
        let own2 = derive_ownership(&ClassifyInput { obs: &o2, subscription_name: None, rg_tags: Some(&rg) }, &cfg);
        assert_eq!(own2.application.as_deref(), Some("Payments"));
        assert_eq!(own2.owner.as_deref(), Some("team-rg"));
        assert!(own2.from_resource_group);

        // Resource's own value wins and is trimmed; nothing from the RG.
        let o3 = obs("s", "rg", "a", json!({ "APP-NAME": " Ledger ", "owner": "team-a", "lob": "7", "app-id": "1183" }));
        let own3 = derive_ownership(&ClassifyInput { obs: &o3, subscription_name: None, rg_tags: None }, &cfg);
        assert_eq!(own3.application.as_deref(), Some("Ledger"));
        assert_eq!(own3.application_id.as_deref(), Some("1183"));
        assert_eq!(own3.owner.as_deref(), Some("team-a"));
        assert_eq!(own3.line_of_business.as_deref(), Some("7"));
        assert_eq!(own3.line_of_business_name, None);
        assert!(!own3.from_resource_group);

        // No config -> nothing derived.
        let empty = derive_ownership(&ClassifyInput::resource_only(&o3), &OwnershipConfig::default());
        assert_eq!(empty, Ownership::default());

        assert!(validate_ownership_config(&cfg).is_ok());
        let bad = OwnershipConfig { lob_rollup_pattern: Some("(".into()), ..cfg };
        assert!(validate_ownership_config(&bad).is_err());
    }

    #[test]
    fn settings_doc_without_ownership_still_parses() {
        let doc: SettingsDoc = serde_json::from_value(json!({
            "scan_interval_minutes": 60,
            "operations_timezone": null,
            "chat_history_enabled": false,
            "retention": {},
            "production_mappings": {},
            "servicenow": null,
            "chat": null,
            "theme_path": null
        }))
        .unwrap();
        assert!(doc.ownership.is_none());
    }
}
