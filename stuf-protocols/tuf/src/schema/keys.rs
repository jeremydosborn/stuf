//! Cryptographic key types for TUF metadata.
//!
//! Pure data types only — no crypto operations happen here.
//! Key material is passed to stuf-env implementations via the
//! Verifier and Signer traits in sign/.

#[cfg(feature = "alloc")]
use alloc::string::String;

use serde::{Deserialize, Serialize};
use core::fmt;

/// A key identifier — SHA-256 digest of the canonical key encoding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The cryptographic algorithm of a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Ed25519,
    Rsa,
    #[serde(rename = "ecdsa-sha2-nistp256")]
    EcdsaP256,
    #[serde(other)]
    Unknown,
}

/// The signature scheme used with this key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureScheme {
    Ed25519,
    #[serde(rename = "rsassa-pss-sha256")]
    RsassaPssSha256,
    #[serde(rename = "ecdsa-sha2-nistp256")]
    EcdsaSha2Nistp256,
    #[serde(other)]
    Unknown,
}

/// Raw public key material as stored in TUF metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyValue {
    pub public: String,
}

/// A public key entry as it appears in root or delegations metadata.
///
/// Contains no crypto logic — just the data. stuf-env implementations
/// receive this and perform actual verification operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub keytype: KeyType,
    pub scheme: SignatureScheme,
    pub keyval: KeyValue,
}
