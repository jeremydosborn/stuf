//! TUF timestamp metadata — most frequently updated role.

#[cfg(feature = "alloc")]
use alloc::{string::String, collections::BTreeMap};

use serde::{Deserialize, Serialize};
use crate::schema::role::{Role, RoleType};

/// Expected version and optional hash of snapshot.json
/// as recorded in timestamp.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampMeta {
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<BTreeMap<String, String>>,
}

/// Timestamp metadata — points to current snapshot.json.
/// Resigned frequently to bound freeze attack window.
/// Clients verify this first in the update sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timestamp {
    #[serde(rename = "_type")]
    pub role_type: String,

    pub spec_version: String,
    pub version: u32,

    /// Expiry as unix timestamp (seconds since epoch).
    pub expires: u64,

    /// Must contain exactly one entry: "snapshot.json".
    pub meta: BTreeMap<String, TimestampMeta>,
}

impl Timestamp {
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

    fn expires(&self) -> u64 {
        self.expires
    }
}
