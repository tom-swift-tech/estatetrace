//! Resource kinds: the names pack targets use, mapped to Azure resource types (spec §4.2).

use crate::evaluator::evaluate_leaf;
use crate::pack::Leaf;
use anyhow::{Context, Result};
use estatetrace_core::EvalOutcome;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceKinds {
    pub kinds: BTreeMap<String, ResourceKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceKind {
    /// Resource Graph `type`, lowercase.
    pub arm_type: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// A resource of `arm_type` is this kind only when the filter passes.
    #[serde(default)]
    pub filter: Option<Leaf>,
}

impl ResourceKinds {
    /// Parse a kinds document. ARM types are normalised to lowercase.
    pub fn from_yaml(text: &str) -> Result<Self> {
        let mut kinds: ResourceKinds =
            serde_yaml::from_str(text).context("resource kinds document")?;
        for k in kinds.kinds.values_mut() {
            k.arm_type = k.arm_type.to_ascii_lowercase();
        }
        Ok(kinds)
    }

    /// Look a kind up by its name or one of its aliases (case-insensitive).
    pub fn resolve(&self, name_or_alias: &str) -> Option<&ResourceKind> {
        let wanted = name_or_alias.trim();
        if let Some(k) = self.kinds.get(wanted) {
            return Some(k);
        }
        self.kinds
            .iter()
            .find(|(name, k)| {
                name.eq_ignore_ascii_case(wanted)
                    || k.aliases.iter().any(|a| a.eq_ignore_ascii_case(wanted))
            })
            .map(|(_, k)| k)
    }

    /// True when the resource view's `type` is the kind's ARM type and the kind filter passes.
    pub fn matches(&self, kind: &ResourceKind, resource_view: &Value) -> bool {
        let type_ok = resource_view
            .get("type")
            .and_then(|t| t.as_str())
            .map(|t| t.eq_ignore_ascii_case(&kind.arm_type))
            .unwrap_or(false);
        if !type_ok {
            return false;
        }
        match &kind.filter {
            None => true,
            Some(f) => evaluate_leaf(f, resource_view).outcome == EvalOutcome::Pass,
        }
    }
}

/// The generic Azure kinds shipped in `kits/policy-authoring/resource_kinds.yaml`.
pub fn builtin_resource_kinds() -> &'static ResourceKinds {
    static KINDS: OnceLock<ResourceKinds> = OnceLock::new();
    KINDS.get_or_init(|| {
        ResourceKinds::from_yaml(include_str!(
            "../../../kits/policy-authoring/resource_kinds.yaml"
        ))
        .expect("built-in resource_kinds.yaml must parse")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn builtin_kinds_parse_and_resolve_aliases() {
        let kinds = builtin_resource_kinds();
        assert!(kinds.kinds.len() > 40);
        let sa = kinds.resolve("storage_account").unwrap();
        assert_eq!(sa.arm_type, "microsoft.storage/storageaccounts");
        assert_eq!(
            kinds.resolve("Storage").unwrap().arm_type,
            "microsoft.storage/storageaccounts"
        );
        assert!(kinds.resolve("no_such_kind").is_none());
        for (name, k) in &kinds.kinds {
            assert_eq!(k.arm_type, k.arm_type.to_ascii_lowercase(), "{name}");
            assert!(k.arm_type.starts_with("microsoft."), "{name}");
        }
    }

    #[test]
    fn function_app_filter_selects_function_apps_only() {
        let kinds = builtin_resource_kinds();
        let fa = kinds.resolve("function_app").unwrap();
        let web = kinds.resolve("app_service").unwrap();
        let func = json!({ "type": "Microsoft.Web/sites", "kind": "functionapp,linux" });
        let site = json!({ "type": "Microsoft.Web/sites", "kind": "app,linux" });
        let unknown_kind = json!({ "type": "Microsoft.Web/sites" });
        assert!(kinds.matches(fa, &func));
        assert!(!kinds.matches(fa, &site));
        assert!(!kinds.matches(fa, &unknown_kind));
        assert!(kinds.matches(web, &site));
        assert!(kinds.matches(web, &func));
        let vm = json!({ "type": "Microsoft.Compute/virtualMachines" });
        assert!(!kinds.matches(web, &vm));
    }
}
