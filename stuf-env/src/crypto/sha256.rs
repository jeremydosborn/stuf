//! SHA-256 hashing primitive.
//!
//! Wraps the sha2 crate behind a feature flag.
//! stuf-tuf calls these directly for target and metadata hash checks.

use alloc::string::String;
use sha2::{Digest, Sha256};

/// Compute SHA-256 digest, return raw bytes.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result.into()
}

/// Compute SHA-256 digest, return hex-encoded string.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}
