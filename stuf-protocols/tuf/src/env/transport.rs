/// The URL or resource identifier passed to fetch.
/// Protocol-agnostic — could be HTTP, UART channel, CAN bus ID, etc.
pub type ResourceId<'a> = &'a str;

/// Transport abstraction — how bytes move in this environment.
///
/// The implementor decides the buffer type. A std environment returns
/// `Vec<u8>`, a bare metal environment returns a fixed stack buffer.
/// stuf-tuf never allocates transport buffers itself.
pub trait Transport {
    /// The buffer type returned by fetch.
    /// Must be readable as a byte slice.
    type Buffer: AsRef<[u8]>;

    /// The error type for transport failures.
    type Error: core::fmt::Debug;

    /// Fetch a resource by identifier.
    /// The implementor owns retry logic, timeouts, and error handling.
    fn fetch(&self, id: ResourceId<'_>) -> Result<Self::Buffer, Self::Error>;
}
