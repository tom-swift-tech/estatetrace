//! Cross-resource joins exposed to checks as `join.<name>` (spec §3.1).
//!
//! Phase 1 ships only the empty index, so a leaf with `evidence_source: join` evaluates to
//! unknown ("joined <name> is outside the visible scope"). Phase 5 fills the index from the
//! latest VNet observations (subnet ID -> subnet object).

use estatetrace_core::ResourceObservation;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct JoinIndex {
    _private: (),
}

impl JoinIndex {
    /// An index with no joins.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The `join` object for one resource, or `None` when nothing joins to it.
    pub fn view_for(&self, _obs: &ResourceObservation) -> Option<Value> {
        None
    }
}
