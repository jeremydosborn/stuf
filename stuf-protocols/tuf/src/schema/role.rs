//! TUF role types and threshold signing requirements.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::schema::keys::KeyId;
use core::fmt;
use serde::{Deserialize, Serialize};

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

/// Key IDs and signing threshold for a role.
/// Appears in root.json and in delegations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleKeys {
    pub keyids: Vec<KeyId>,
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
pub trait Role {
    fn role_type() -> RoleType
    where
        Self: Sized;
    fn version(&self) -> u32;
    /// Expiry as unix timestamp (seconds since epoch).
    /// No chrono dependency — the Clock trait in stuf-env
    /// handles parsing and comparison.
    fn expires(&self) -> u64;
}
