//! Encoding trait — how TUF metadata is serialized and deserialized.
//!
//! stuf-tuf does not own any serialization logic.
//! Implementations live in stuf-env behind feature flags:
//! - encoding-json  → serde_json
//! - encoding-cbor  → ciborium
//!
//! The app selects which via Cargo.toml features.

use crate::error::Error;

/// Encoding abstraction for TUF metadata.
///
/// Decodes raw bytes into typed schema structs and produces
/// canonical bytes for signature verification.
pub trait Encoding {
    /// Decode bytes into a typed metadata value.
    fn decode<T>(&self, bytes: &[u8]) -> Result<T, Error>
    where
        T: for<'de> serde::Deserialize<'de>;

    /// Produce canonical bytes for signature verification.
    /// For JSON this is canonical JSON (sorted keys, no whitespace).
    /// The encoding format defines what canonical means.
    fn canonical<T>(&self, value: &T) -> Result<alloc::vec::Vec<u8>, Error>
    where
        T: serde::Serialize;
}
