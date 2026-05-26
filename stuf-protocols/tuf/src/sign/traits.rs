//! Signing trait boundaries.
//!
//! Signature verification is handled by calling stuf-env crypto
//! functions directly — no Verifier trait. The protocol logic in
//! verify/signatures.rs extracts key bytes from TUF's PublicKey
//! and dispatches to the right stuf-env function.
//!
//! Signer is still a trait because the publisher side needs it.

use crate::schema::keys::PublicKey;

/// Signing — used by the publisher side (build/).
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
