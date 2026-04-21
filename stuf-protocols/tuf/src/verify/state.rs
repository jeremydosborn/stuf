//! Type state primitives for the TUF verification chain.
//!
//! Checked<T> is internal chain bookkeeping — it means "signatures
//! passed for this metadata role." It is NOT core's Verified<T>.
//!
//! Core's Verified<T> is returned at the end of the chain when
//! the entire TUF update sequence succeeds, including firmware
//! hash and length checks.

use crate::schema::signed::Signed;
use serde::de::DeserializeOwned;

/// A metadata payload that has not been verified.
///
/// The inner value is not pub — callers cannot reach inside
/// without passing through a verification function.
#[derive(Debug)]
pub struct Unverified<T>(pub(crate) T);

impl<T> Unverified<Signed<T>>
where
    T: DeserializeOwned,
{
    /// Parse raw bytes into an unverified envelope.
    pub fn from_signed(signed: Signed<T>) -> Self {
        Unverified(signed)
    }

    /// Expose signatures for verification routines.
    /// Only accessible within this crate.
    pub(crate) fn signatures(&self) -> &[crate::schema::signed::Signature] {
        &self.0.signatures
    }

    /// Expose the signed payload for canonical encoding.
    /// Only accessible within this crate.
    pub(crate) fn payload(&self) -> &T {
        &self.0.signed
    }

    /// Consume and produce a checked value.
    /// Only callable from within this crate after threshold is met.
    pub(crate) fn into_checked(self) -> Checked<T> {
        Checked(self.0.signed)
    }
}

/// A metadata payload whose signatures have been verified against
/// a trusted key set and found to meet the required threshold.
///
/// This is internal to stuf-tuf's chain — it tracks which metadata
/// roles have passed signature checks. It is NOT core's Verified<T>.
#[derive(Debug, Clone)]
pub struct Checked<T>(pub(crate) T);

impl<T> Checked<T> {
    pub fn get(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Clock abstraction — injected by the app, never owned by stuf-tuf.
///
/// Returns current time as unix timestamp (seconds since epoch).
/// No chrono dependency. The app decides how to read time —
/// hardware timer, RTOS tick, system clock, or fixed value for testing.
pub trait Clock {
    fn now_secs(&self) -> u64;
}

/// Fixed clock for testing — always returns the same instant.
#[derive(Debug, Clone)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.0
    }
}
