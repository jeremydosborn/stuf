use crate::{
    error::{Error, Result},
    schema::role::Role,
    verify::state::{Clock, Verified},
};

/// Check that a verified metadata item has not expired according to
/// the provided clock. Called after signature verification — expiry
/// is a separate concern from trust.
pub fn check_expiry<T: Role>(metadata: &Verified<T>, clock: &dyn Clock) -> Result<()> {
    let now = clock.now();
    let expires = metadata.get().expires();
    if now > *expires {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
