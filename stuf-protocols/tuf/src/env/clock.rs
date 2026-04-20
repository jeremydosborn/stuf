/// Clock abstraction — how time is read in this environment.
///
/// The implementor decides the timestamp representation.
/// A std environment might use `chrono::DateTime<Utc>`.
/// A bare metal environment might use a `u64` hardware counter.
/// stuf-tuf never reads the system clock directly.
pub trait Clock {
    /// The timestamp type for this environment.
    /// Must be comparable so expiry checks work.
    type Timestamp: PartialOrd + core::fmt::Debug;

    /// Return the current time as a timestamp.
    fn now(&self) -> Self::Timestamp;

    /// Parse a timestamp from its serialized representation.
    /// The encoding of expiry fields in metadata depends on the
    /// environment's chosen timestamp type.
    fn parse(&self, raw: &str) -> Result<Self::Timestamp, ClockError>;
}

#[derive(Debug)]
pub struct ClockError(pub &'static str);

impl core::fmt::Display for ClockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "clock error: {}", self.0)
    }
}
