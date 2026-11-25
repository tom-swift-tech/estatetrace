//! Shared domain models for EstateTrace.

pub mod classification;
pub mod coverage;
pub mod findings;
pub mod ids;
pub mod observations;
pub mod scope;
pub mod time;
pub mod views;

#[cfg(test)]
mod scope_tests;
#[cfg(test)]
mod classification_tests;

pub use classification::*;
pub use coverage::*;
pub use findings::*;
pub use ids::*;
pub use observations::*;
pub use scope::*;
pub use time::*;
pub use views::*;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("{0}")]
    Message(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Azure,
}

impl Provider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Azure => "azure",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Track,
    Exclude,
    AwaitReview,
}

impl DecisionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DecisionKind::Track => "track",
            DecisionKind::Exclude => "exclude",
            DecisionKind::AwaitReview => "await_review",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "track" => Some(Self::Track),
            "exclude" => Some(Self::Exclude),
            "await_review" => Some(Self::AwaitReview),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSource {
    Explicit,
    SavedRule,
    TenantDefault,
}

impl DecisionSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            DecisionSource::Explicit => "explicit",
            DecisionSource::SavedRule => "saved_rule",
            DecisionSource::TenantDefault => "tenant_default",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "explicit" => Some(Self::Explicit),
            "saved_rule" => Some(Self::SavedRule),
            "tenant_default" => Some(Self::TenantDefault),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvalOutcome {
    Pass,
    Fail,
    Unknown,
    Inapplicable,
}

impl EvalOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            EvalOutcome::Pass => "pass",
            EvalOutcome::Fail => "fail",
            EvalOutcome::Unknown => "unknown",
            EvalOutcome::Inapplicable => "inapplicable",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pass" => Some(Self::Pass),
            "fail" => Some(Self::Fail),
            "unknown" => Some(Self::Unknown),
            "inapplicable" => Some(Self::Inapplicable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TicketRelType {
    Explicit,
    TimingCandidate,
    OperatorConfirmed,
}

impl TicketRelType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TicketRelType::Explicit => "explicit",
            TicketRelType::TimingCandidate => "timing_candidate",
            TicketRelType::OperatorConfirmed => "operator_confirmed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExportState {
    Suggested,
    Exported,
    Assigned,
    Verified,
}

impl ExportState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExportState::Suggested => "suggested",
            ExportState::Exported => "exported",
            ExportState::Assigned => "assigned",
            ExportState::Verified => "verified",
        }
    }
}