//! Core trust primitives.
//!
//! Verified<T> is the only way to represent trusted data in stuf.
//! There is one definition, here, in stuf-core. Protocols implement
//! verification logic and construct Verified<T> on success.

use crate::error::StufError;

/// A value whose authenticity has been established through verification.
///
/// Only verification code should call `new()`. App code receives
/// Verified<T> as output — the type proves the check happened.
#[derive(Debug, Clone)]
pub struct Verified<T> {
    payload: T,
}

impl<T> Verified<T> {
    /// Construct a verified value.
    ///
    /// Public so protocol crates (stuf-tuf, etc.) can construct
    /// Verified<T> after their verification logic passes.
    pub fn new(payload: T) -> Self {
        Self { payload }
    }

    /// Consume and return the inner value.
    pub fn into_inner(self) -> T {
        self.payload
    }

    /// Borrow the verified payload.
    pub fn payload(&self) -> &T {
        &self.payload
    }
}

/// The core verification contract.
///
/// A protocol (TUF, in-toto, etc.) implements this trait.
/// The app calls verify() with a payload and evidence, and gets
/// back Verified<T> if the protocol accepts it.
pub trait Verifier<T> {
    fn verify(&self, payload: T, evidence: &[u8]) -> Result<Verified<T>, StufError>;
}
