use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Dual timestamps required by the local release contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DualTime {
    /// Provider/source event time when available.
    pub event_time: Option<DateTime<Utc>>,
    /// Local observation/collection time.
    pub observation_time: DateTime<Utc>,
}

impl DualTime {
    pub fn observed_now() -> Self {
        Self {
            event_time: None,
            observation_time: Utc::now(),
        }
    }

    pub fn with_event(event_time: DateTime<Utc>) -> Self {
        Self {
            event_time: Some(event_time),
            observation_time: Utc::now(),
        }
    }
}