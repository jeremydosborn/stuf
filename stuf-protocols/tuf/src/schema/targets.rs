use crate::schema::{
    keys::{KeyId, PublicKey},
    role::{Role, RoleKeys, RoleType},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The hash algorithms and digests for a target file.
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
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Specifies the target paths that a delegated role is authoritative for.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathSet {
    /// Explicit list of path patterns.
    Paths { paths: Vec<String> },
    /// Matches all paths — used when a role has universal delegation.
    Any,
}

/// A single delegated role entry within a targets file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedRole {
    pub name: String,
    pub keyids: Vec<KeyId>,
    pub threshold: u32,
    pub paths: PathSet,
    /// If true, targets not matched by this role's paths are not searched
    /// further down the delegation chain.
    #[serde(default)]
    pub terminating: bool,
}

/// The delegations block within a targets file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegations {
    /// Public keys used by delegated roles, keyed by KeyId.
    pub keys: HashMap<KeyId, PublicKey>,
    /// Ordered list of delegated roles.
    pub roles: Vec<DelegatedRole>,
}

/// The targets metadata — lists target files and their expected properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Targets {
    #[serde(rename = "_type")]
    pub role_type: String,

    pub spec_version: String,
    pub version: u32,
    pub expires: DateTime<Utc>,

    /// The target files this role is authoritative for.
    #[serde(default)]
    pub targets: HashMap<String, Target>,

    /// Delegations to sub-roles, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegations: Option<Delegations>,
}

impl Targets {
    pub fn get_target(&self, name: &str) -> Option<&Target> {
        self.targets.get(name)
    }

    pub fn delegated_roles(&self) -> &[DelegatedRole] {
        self.delegations
            .as_ref()
            .map(|d| d.roles.as_slice())
            .unwrap_or(&[])
    }
}

impl Role for Targets {
    fn role_type() -> RoleType {
        RoleType::Targets
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn expires(&self) -> &DateTime<Utc> {
        &self.expires
    }
}

/// A named targets role — used when a delegated targets role needs
/// to carry its delegation name alongside the metadata.
#[derive(Debug, Clone)]
pub struct NamedTargets {
    pub name: String,
    pub targets: Targets,
    pub role_keys: RoleKeys,
}
