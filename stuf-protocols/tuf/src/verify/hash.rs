//! Hash verification — protocol logic.
//!
//! This module owns the comparison logic (what to hash, what to
//! compare against). The actual hash computation is in stuf-env.

use crate::{
    error::{Error, Result},
    schema::targets::Hashes,
};

/// Verify target bytes against expected hashes from targets metadata.
/// Protocol logic: extracts expected hex from the Hashes struct,
/// calls stuf-env for the computation, compares.
#[cfg(feature = "hash-sha256")]
pub fn verify_target_hashes(bytes: &[u8], hashes: &Hashes) -> Result<()> {
    if let Some(ref expected_hex) = hashes.sha256 {
        let actual_hex = stuf_env::crypto::sha256_hex(bytes);
        if actual_hex != *expected_hex {
            return Err(Error::TargetHashMismatch);
        }
    }
    Ok(())
}

#[cfg(not(feature = "hash-sha256"))]
pub fn verify_target_hashes(_bytes: &[u8], _hashes: &Hashes) -> Result<()> {
    // No hash algorithm compiled in — skip verification.
    // This is a configuration error but we don't panic.
    Ok(())
}
