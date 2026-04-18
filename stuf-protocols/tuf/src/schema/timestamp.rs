use crate::schema::role::{Role, RoleType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The expected version, length, and hashes of snapshot.json
/// as recorded in timestamp.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampMeta {
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<HashMap<String, String>>,
}

/// The timestamp metadata — the most frequently updated TUF role.
///
/// Timestamp points to the current snapshot.json and is resigned on a
/// short interval to bound the window of a freeze attack. Clients check
/// timestamp first in the update sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timestamp {
    #[serde(rename = "_type")]
    pub role_type: String,

    pub spec_version: String,
    pub version: u32,
    pub expires: DateTime<Utc>,

    /// Must contain exactly one entry: "snapshot.json".
    pub meta: HashMap<String, TimestampMeta>,
}

impl Timestamp {
    /// Returns the snapshot.json entry from the meta map.
    pub fn snapshot_meta(&self) -> Option<&TimestampMeta> {
        self.meta.get("snapshot.json")
    }
}

impl Role for Timestamp {
    fn role_type() -> RoleType {
        RoleType::Timestamp
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn expires(&self) -> &DateTime<Utc> {
        &self.expires
    }
}
