//! Signing trait boundaries.
//!
//! Verifier and Signer are defined here — implemented in stuf-env.
//! stuf-tuf never owns crypto primitives directly.

use crate::schema::keys::PublicKey;
use crate::schema::targets::Hashes;

/// Signature verification — implemented by stuf-env crypto modules.
pub trait Verifier {
    fn verify(
        &self,
        key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), VerifyError>;

    /// Verify target bytes against expected hashes.
    /// stuf-env owns the actual hash computation.
    fn verify_hash(
        &self,
        bytes: &[u8],
        hashes: &Hashes,
    ) -> Result<(), VerifyError>;
}

/// Signing — used by the publisher side (build/).
/// MVP: stubbed. Implemented in stuf-env.
pub trait Signer {
    fn key_id(&self) -> &crate::schema::keys::KeyId;
    fn public_key(&self) -> &PublicKey;
    fn sign(&self, message: &[u8]) -> Result<alloc::vec::Vec<u8>, SignError>;
}

#[derive(Debug)]
pub struct VerifyError;

#[derive(Debug)]
pub struct SignError;

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "signature verification failed")
    }
}

impl core::fmt::Display for SignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "signing failed")
    }
}

