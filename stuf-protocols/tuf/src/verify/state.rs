use crate::schema::signed::Signed;
use serde::de::DeserializeOwned;

/// A metadata payload that has not yet been verified.
///
/// The only way to obtain a `Verified<T>` is to pass an `Unverified<T>`
/// through the appropriate verification function. Raw bytes and parsed
/// but unverified structs are quarantined here — they cannot reach any
/// code that requires trust without going through the verification gate.
///
/// The inner value is intentionally not `pub` — callers cannot reach
/// inside without verifying first.
#[derive(Debug)]
pub struct Unverified<T>(pub(crate) T);

impl<T> Unverified<Signed<T>>
where
    T: DeserializeOwned,
{
    /// Parse raw bytes into an unverified envelope.
    /// Deserialization succeeds here — signature and trust checks happen later.
    pub fn from_bytes(bytes: &[u8]) -> crate::error::Result<Self> {
        let signed: Signed<T> = serde_json::from_slice(bytes)?;
        Ok(Unverified(signed))
    }
}

impl<T> Unverified<Signed<T>> {
    /// Expose the raw signatures for verification routines.
    /// Only accessible within this crate — external callers cannot
    /// read signatures off an unverified payload.
    pub(crate) fn signatures(&self) -> &[crate::schema::signed::Signature] {
        &self.0.signatures
    }

    /// Expose the canonical bytes for signature verification.
    pub(crate) fn canonical_bytes(&self) -> crate::error::Result<Vec<u8>>
    where
        T: serde::Serialize,
    {
        self.0.canonical_bytes()
    }

    /// Consume the unverified envelope and produce a verified one.
    /// Only callable from within this crate — verification functions
    /// call this after confirming signatures meet the threshold.
    pub(crate) fn into_verified(self) -> Verified<T> {
        Verified(self.0.signed)
    }
}

/// A metadata payload whose signatures have been checked against a
/// trusted set of keys and found to meet the required threshold.
///
/// Callers outside this crate can only obtain a `Verified<T>` by going
/// through the verification chain — there is no other constructor.
#[derive(Debug, Clone)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    /// Access the verified inner value.
    pub fn get(&self) -> &T {
        &self.0
    }

    /// Consume and unwrap the verified value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// A clock abstraction injected by the caller.
///
/// The library never calls `SystemTime::now()` directly — the updater
/// app owns the time source. This matters for embedded targets where
/// the system clock may not be reliable, and for testing.
pub trait Clock: Send + Sync {
    fn now(&self) -> chrono::DateTime<chrono::Utc>;
}

/// A fixed clock for testing — always returns the same instant.
#[derive(Debug, Clone)]
pub struct FixedClock(pub chrono::DateTime<chrono::Utc>);

impl Clock for FixedClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.0
    }
}
