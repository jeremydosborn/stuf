use crate::schema::keys::KeyId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The four top-level TUF roles.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoleType {
    Root,
    Targets,
    Snapshot,
    Timestamp,
}

impl fmt::Display for RoleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoleType::Root => write!(f, "root"),
            RoleType::Targets => write!(f, "targets"),
            RoleType::Snapshot => write!(f, "snapshot"),
            RoleType::Timestamp => write!(f, "timestamp"),
        }
    }
}

/// A role identifier — either a top-level role or a named delegated role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RoleId {
    TopLevel(RoleType),
    Delegated(String),
}

impl fmt::Display for RoleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoleId::TopLevel(r) => write!(f, "{r}"),
            RoleId::Delegated(name) => write!(f, "{name}"),
        }
    }
}

/// The key IDs and signing threshold for a role.
/// Appears in root.json and in delegations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleKeys {
    /// The key IDs authorized to sign for this role.
    pub keyids: Vec<KeyId>,
    /// Number of valid signatures required to trust this role's metadata.
    pub threshold: u32,
}

impl RoleKeys {
    pub fn new(keyids: Vec<KeyId>, threshold: u32) -> Self {
        Self { keyids, threshold }
    }

    pub fn threshold_met(&self, valid_count: u32) -> bool {
        valid_count >= self.threshold
    }
}

/// Common behavior across all role metadata types.
/// Implemented by Root, Targets, Snapshot, Timestamp.
pub trait Role {
    fn role_type() -> RoleType
    where
        Self: Sized;

    fn version(&self) -> u32;
    fn expires(&self) -> &chrono::DateTime<chrono::Utc>;
}
