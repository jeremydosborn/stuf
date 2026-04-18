use crate::schema::role::{Role, RoleType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The expected version, length, and hashes of a metadata file
/// as recorded in snapshot.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<HashMap<String, String>>,
}

/// The snapshot metadata — records the current version of every
/// targets metadata file so clients can detect rollback attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(rename = "_type")]
    pub role_type: String,

    pub spec_version: String,
    pub version: u32,
    pub expires: DateTime<Utc>,

    /// Map from metadata filename (e.g. "targets.json") to its
    /// expected version and optional length/hash.
    pub meta: HashMap<String, SnapshotMeta>,
}

impl Snapshot {
    /// Look up the expected metadata for a given filename.
    pub fn meta_for(&self, filename: &str) -> Option<&SnapshotMeta> {
        self.meta.get(filename)
    }
}

impl Role for Snapshot {
    fn role_type() -> RoleType {
        RoleType::Snapshot
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn expires(&self) -> &DateTime<Utc> {
        &self.expires
    }
}
