use serde::{Deserialize, Serialize};
use std::fmt;

/// A key identifier — the SHA-256 digest of the canonical key encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    EcdsaP256Sha256,
    #[serde(other)]
    Unknown,
}

/// The scheme used to sign with this key.
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

/// The raw public key material as it appears in TUF metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyValue {
    pub public: String,
}

/// A public key entry as stored in root or delegations metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub keytype: KeyType,
    pub scheme: SignatureScheme,
    pub keyval: KeyValue,
    /// Whether this key has been revoked. Not in the TUF spec directly
    /// but useful for key lifecycle management.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub revoked: bool,
}

impl PublicKey {
    /// Returns the raw public key bytes decoded from the keyval.
    /// The encoding depends on keytype — callers in stuf-env handle
    /// the actual crypto; this just provides the raw material.
    pub fn public_bytes(&self) -> crate::error::Result<Vec<u8>> {
        hex::decode(&self.keyval.public).map_err(|e| {
            crate::error::Error::InvalidKeyId(format!(
                "failed to decode key bytes: {e}"
            ))
        })
    }
}
