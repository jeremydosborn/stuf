//! Crypto primitives for stuf-env.
//!
//! Direct functions, not traits. The app's feature flags select
//! which algorithms are compiled in. stuf-tuf calls these directly.

#[cfg(feature = "crypto-ed25519")]
mod ed25519;

#[cfg(feature = "hash-sha256")]
mod sha256;

#[cfg(feature = "crypto-ed25519")]
pub use ed25519::{ed25519_verify, Ed25519Error};

#[cfg(feature = "hash-sha256")]
pub use sha256::{sha256, sha256_hex};
