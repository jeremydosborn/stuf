//! stuf-env — environment implementations for the stuf framework.
//!
//! Each implementation is gated behind a feature flag.
//! Apps pull in only what they need via Cargo.toml features.

#[cfg(feature = "crypto-ed25519")]
pub mod crypto;

#[cfg(feature = "transport-mock")]
pub mod transport;

#[cfg(any(feature = "clock-fixed", feature = "clock-std"))]
pub mod clock;

#[cfg(feature = "encoding-json")]
pub mod encoding;
