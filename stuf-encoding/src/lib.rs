#![no_std]
extern crate alloc;

mod heap;

pub use heap::error::EncodeError;

#[cfg(feature = "jcs")]
pub use heap::jcs::canonicalize;

#[cfg(feature = "json")]
pub use heap::json::decode;
