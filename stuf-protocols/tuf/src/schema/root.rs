//! TUF root metadata — the trust anchor for a TUF repository.

#[cfg(feature = "alloc")]
use alloc::{string::String, collections::BTreeMap};

use serde::{Deserialize, Serialize};
use crate::schema::{
    keys::{KeyId, PublicKey},
    role::{Role, RoleKeys, RoleType},
};

/// Root metadata — lists which keys are authorized for each role
/// and the threshold of signatures required.
///
/// For MVP: root is baked into the binary at compile time via
/// include_bytes!() and never fetched over the network.
/// Root rotation is out of scope for MVP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Root {
    #[serde(rename = "_type")]
    pub role_type: String,

    pub spec_version: String,
    pub version: u32,

    /// Expiry as unix timestamp (seconds since epoch).
    pub expires: u64,

    pub consistent_snapshot: bool,

    /// All public keys referenced by any role.
    pub keys: BTreeMap<KeyId, PublicKey>,

    /// Top-level roles and their authorized keys + threshold.
    pub roles: BTreeMap<String, RoleKeys>,
}

impl Root {
    pub fn role_keys(&self, role: &RoleType) -> Option<&RoleKeys> {
        self.roles.get(&role.to_string())
    }

    pub fn key(&self, id: &KeyId) -> Option<&PublicKey> {
        self.keys.get(id)
    }
}

impl Role for Root {
    fn role_type() -> RoleType {
        RoleType::Root
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn expires(&self) -> u64 {
        self.expires
    }
}
