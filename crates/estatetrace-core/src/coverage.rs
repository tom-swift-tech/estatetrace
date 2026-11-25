//! Coverage gaps: controls (or control targets) a scan cannot judge per resource (spec §4.3).

use serde::{Deserialize, Serialize};

/// Why a control is not evaluated per resource.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GapCategory {
    /// Evidence lives outside Azure (records, sign-in logs, test evidence).
    OutsideAzure,
    /// Azure holds the evidence, but EstateTrace does not collect it yet.
    MoreCollection,
    /// True of every resource by construction, so a per-resource check says nothing.
    ByConstruction,
    /// The standard needs an owner decision before it can be checked.
    NeedsDecision,
    /// Needs per-resource ARM calls (the deep tier), which are not collected.
    DeepCollection,
}

impl GapCategory {
    pub const ALL: [GapCategory; 5] = [
        GapCategory::OutsideAzure,
        GapCategory::MoreCollection,
        GapCategory::ByConstruction,
        GapCategory::NeedsDecision,
        GapCategory::DeepCollection,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            GapCategory::OutsideAzure => "outside_azure",
            GapCategory::MoreCollection => "more_collection",
            GapCategory::ByConstruction => "by_construction",
            GapCategory::NeedsDecision => "needs_decision",
            GapCategory::DeepCollection => "deep_collection",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        GapCategory::ALL
            .into_iter()
            .find(|c| c.as_str().eq_ignore_ascii_case(s.trim()))
    }
}

/// One control (or one target type of a control) that produced no per-resource evaluations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageGap {
    pub pack_id: String,
    pub control_id: String,
    pub category: GapCategory,
    pub note: String,
    /// ARM type for a deep-only target; `None` for a whole-control gap.
    pub resource_type: Option<String>,
    /// Resources of `resource_type` in the evaluated set (0 for a whole-control gap).
    pub resource_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_category_round_trips() {
        for c in GapCategory::ALL {
            assert_eq!(GapCategory::parse(c.as_str()), Some(c));
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(json, format!("\"{}\"", c.as_str()));
        }
        assert_eq!(GapCategory::parse("nope"), None);
    }
}
