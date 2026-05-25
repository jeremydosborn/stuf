//! Hash verification — protocol logic.
//!
//! This module owns the comparison logic (what to hash, what to
//! compare against). The actual hash computation is in stuf-env.
//!
//! Security: no hash algorithm compiled in = hard error.
//! A target with no supported hash field = hard error.

use crate::{error::Result, schema::targets::Hashes};

/// Verify target bytes against expected hashes from targets metadata.
/// Protocol logic: extracts expected hex from the Hashes struct,
/// calls stuf-env for the computation, compares.
#[cfg(feature = "hash-sha256")]
pub fn verify_target_hashes(bytes: &[u8], hashes: &Hashes) -> Result<()> {
    use crate::error::Error;

    match hashes.sha256 {
        Some(ref expected_hex) => {
            let actual_hex = stuf_env::crypto::sha256_hex(bytes);
            if actual_hex != *expected_hex {
                Err(Error::TargetHashMismatch)
            } else {
                Ok(())
            }
        }
        None => {
            // Target metadata has no sha256 hash — fail closed.
            Err(Error::NoSupportedHash)
        }
    }
}

/// Verify metadata bytes against expected hash from parent metadata.
/// Used for timestamp→snapshot and snapshot→targets checks.
#[cfg(feature = "hash-sha256")]
pub fn verify_metadata_hash(
    bytes: &[u8],
    expected_hashes: &alloc::collections::BTreeMap<alloc::string::String, alloc::string::String>,
) -> Result<()> {
    use crate::error::Error;

    if let Some(expected_hex) = expected_hashes.get("sha256") {
        let actual_hex = stuf_env::crypto::sha256_hex(bytes);
        if actual_hex != *expected_hex {
            return Err(Error::MetadataHashMismatch);
        }
    }
    // No sha256 in parent metadata is not an error for metadata —
    // hashes are optional per TUF spec for metadata cross-references.
    // Only targets require hashes.
    Ok(())
}

/// Verify metadata length against expected length from parent metadata.
pub fn verify_metadata_length(bytes: &[u8], expected_length: Option<u64>) -> Result<()> {
    use crate::error::Error;

    if let Some(expected) = expected_length {
        let actual = bytes.len() as u64;
        if actual != expected {
            return Err(Error::MetadataLengthMismatch { expected, actual });
        }
    }
    Ok(())
}

#[cfg(not(feature = "hash-sha256"))]
pub fn verify_target_hashes(_bytes: &[u8], _hashes: &Hashes) -> Result<()> {
    // No hash algorithm compiled in — fail closed.
    Err(crate::error::Error::NoHashAlgorithm)
}

#[cfg(not(feature = "hash-sha256"))]
pub fn verify_metadata_hash(
    _bytes: &[u8],
    _expected_hashes: &alloc::collections::BTreeMap<alloc::string::String, alloc::string::String>,
) -> Result<()> {
    Err(crate::error::Error::NoHashAlgorithm)
}
