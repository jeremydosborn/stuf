//! Transport abstraction and implementations.

/// The URL or resource identifier passed to fetch.
/// Protocol-agnostic — could be HTTP, UART channel, CAN bus ID, etc.
pub type ResourceId<'a> = &'a str;

/// Transport abstraction — how bytes move in this environment.
///
/// The implementor decides the buffer type. A std environment returns
/// `Vec<u8>`, a bare metal environment returns a fixed stack buffer.
pub trait Transport {
    /// The buffer type returned by fetch.
    type Buffer: AsRef<[u8]>;

    /// The error type for transport failures.
    type Error: core::fmt::Debug;

    /// Fetch a resource by identifier.
    fn fetch(&self, id: ResourceId<'_>) -> Result<Self::Buffer, Self::Error>;
}

// ── Implementations ────────────────────────────────────────────────────────

#[cfg(feature = "transport-mock")]
mod mock;

#[cfg(feature = "transport-mock")]
pub use mock::MockTransport;
