//! stuf-env — environment abstractions and implementations for stuf.
//!
//! Defines traits for pluggable environmental concerns (transport, clock,
//! storage) and provides concrete implementations behind feature flags.
//!
//! Crypto primitives are direct functions, not traits — the app's
//! feature flags select which algorithms are compiled in.

#![no_std]
extern crate alloc;

// ── Trait definitions (always available) ────────────────────────────────────

pub mod clock;
pub mod storage;
pub mod transport;

// ── Crypto implementations (feature-gated) ─────────────────────────────────

#[cfg(any(feature = "crypto-ed25519", feature = "hash-sha256"))]
pub mod crypto;
