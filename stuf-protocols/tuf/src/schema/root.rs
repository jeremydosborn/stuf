use crate::schema::{
    keys::PublicKey,
    role::{Role, RoleKeys, RoleType},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::schema::keys::KeyId;

/// The root metadata — the trust anchor for a TUF repository.
///
/// Root lists which keys are authorized for each top-level role and
/// what threshold of signatures is required. Root rotation is performed
/// by producing a new root signed by a threshold of both the old and
/// new root keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Root {
    /// Must be "root".
    #[serde(rename = "_type")]
    pub role_type: String,

    /// Spec version this metadata conforms to.
    pub spec_version: String,

    /// Monotonically increasing version number.
    pub version: u32,

    /// Expiry timestamp in UTC.
    pub expires: DateTime<Utc>,

    /// Whether clients must use consistent snapshots.
    pub consistent_snapshot: bool,

    /// All public keys referenced by any role in this root, keyed by KeyId.
    pub keys: HashMap<KeyId, PublicKey>,

    /// The four top-level roles and their authorized keys + threshold.
    pub roles: HashMap<String, RoleKeys>,
}

impl Root {
    /// Look up the RoleKeys for a given top-level role.
    pub fn role_keys(&self, role: &RoleType) -> Option<&RoleKeys> {
        self.roles.get(&role.to_string())
    }

    /// Look up a public key by ID.
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

    fn expires(&self) -> &DateTime<Utc> {
        &self.expires
    }
}
