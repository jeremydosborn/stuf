//! TUF snapshot metadata — records current version of every targets file.

#[cfg(feature = "alloc")]
use alloc::{collections::BTreeMap, string::String};

use crate::schema::role::{Role, RoleType};
use serde::{Deserialize, Serialize};

/// Expected version and optional hash of a metadata file
/// as recorded in snapshot.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<BTreeMap<String, String>>,
}

/// Snapshot metadata — records the current version of every
/// targets metadata file to prevent rollback attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(rename = "_type")]
    pub role_type: String,

    pub spec_version: String,
    pub version: u32,

    /// Expiry as unix timestamp (seconds since epoch).
    pub expires: u64,

    /// Map from metadata filename to expected version.
    pub meta: BTreeMap<String, SnapshotMeta>,
}

impl Snapshot {
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

    fn expires(&self) -> u64 {
        self.expires
    }
}
