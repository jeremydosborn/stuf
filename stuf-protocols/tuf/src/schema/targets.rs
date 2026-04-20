//! TUF targets metadata — lists target files and their expected properties.

#[cfg(feature = "alloc")]
use alloc::{collections::BTreeMap, string::String, vec::Vec};

use crate::schema::role::{Role, RoleType};
use serde::{Deserialize, Serialize};

/// Hash algorithms and digests for a target file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hashes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha512: Option<String>,
}

/// A single target file entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub length: u64,
    pub hashes: Hashes,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, alloc::string::String>,
}

/// Target paths a delegated role is authoritative for.
/// MVP: delegation is stubbed, PathSet is here for schema completeness.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathSet {
    Paths { paths: Vec<String> },
    Any,
}

/// A delegated role entry within a targets file.
/// MVP: delegation is stubbed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedRole {
    pub name: String,
    pub keyids: Vec<crate::schema::keys::KeyId>,
    pub threshold: u32,
    pub paths: PathSet,
    #[serde(default)]
    pub terminating: bool,
}

/// Delegations block within a targets file.
/// MVP: stubbed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegations {
    pub keys: BTreeMap<crate::schema::keys::KeyId, crate::schema::keys::PublicKey>,
    pub roles: Vec<DelegatedRole>,
}

/// Targets metadata — lists target files the role is authoritative for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Targets {
    #[serde(rename = "_type")]
    pub role_type: String,

    pub spec_version: String,
    pub version: u32,

    /// Expiry as unix timestamp (seconds since epoch).
    pub expires: u64,

    #[serde(default)]
    pub targets: BTreeMap<String, Target>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegations: Option<Delegations>,
}

impl Targets {
    pub fn get_target(&self, name: &str) -> Option<&Target> {
        self.targets.get(name)
    }
}

impl Role for Targets {
    fn role_type() -> RoleType {
        RoleType::Targets
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn expires(&self) -> u64 {
        self.expires
    }
}
