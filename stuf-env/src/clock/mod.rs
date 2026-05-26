//! Clock abstraction and implementations.

/// Clock abstraction — how time is read in this environment.
///
/// Returns current time as unix timestamp (seconds since epoch).
/// The app decides how to read time — hardware timer, RTOS tick,
/// system clock, or fixed value for testing.
pub trait Clock {
    fn now_secs(&self) -> u64;
}

// ── Implementations ────────────────────────────────────────────────────────

/// Fixed clock — always returns the same instant. For testing.
#[cfg(feature = "clock-fixed")]
#[derive(Debug, Clone)]
pub struct FixedClock(pub u64);

#[cfg(feature = "clock-fixed")]
impl FixedClock {
    pub fn new(unix_secs: u64) -> Self {
        Self(unix_secs)
    }
}

#[cfg(feature = "clock-fixed")]
impl Clock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.0
    }
}

#[cfg(feature = "clock-std")]
pub struct SystemClock;

#[cfg(feature = "clock-std")]
impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        // Note: requires std — only available with clock-std feature
        extern crate std;
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
