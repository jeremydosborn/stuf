//! Expiry checking — used at each step of the verify chain.

use crate::{
    error::{Error, Result},
    verify::state::Clock,
};

/// Check that metadata has not expired.
/// expires is unix timestamp (seconds since epoch).
/// clock.now_secs() returns current unix timestamp.
pub fn check_expiry<C: Clock>(expires: u64, clock: &C) -> Result<()> {
    if clock.now_secs() > expires {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
