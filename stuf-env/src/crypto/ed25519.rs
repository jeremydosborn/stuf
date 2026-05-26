//! Ed25519 signature verification using ed25519-dalek.
//!
//! Raw bytes in, pass/fail out. No protocol-specific types.

use ed25519_dalek::{Signature, VerifyingKey};

#[derive(Debug)]
pub struct Ed25519Error;

impl core::fmt::Display for Ed25519Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ed25519 verification failed")
    }
}

/// Verify an Ed25519 signature.
///
/// Takes raw bytes — no protocol-specific key types.
/// stuf-tuf is responsible for extracting key bytes from its
/// own PublicKey schema type before calling this.
pub fn ed25519_verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), Ed25519Error> {
    let verifying_key = VerifyingKey::from_bytes(public_key).map_err(|_| Ed25519Error)?;
    let sig = Signature::from_bytes(signature);

    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(message, &sig)
        .map_err(|_| Ed25519Error)
}
