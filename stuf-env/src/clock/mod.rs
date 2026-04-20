//! Clock implementations for stuf-env.

use stuf_tuf::verify::state::Clock;

#[derive(Debug, Clone)]
pub struct FixedClock(pub u64);

impl FixedClock {
    pub fn new(unix_secs: u64) -> Self { Self(unix_secs) }
}

impl Clock for FixedClock {
    fn now_secs(&self) -> u64 { self.0 }
}

#[cfg(feature = "clock-std")]
pub struct SystemClock;

#[cfg(feature = "clock-std")]
impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
