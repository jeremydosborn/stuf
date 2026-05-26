#![no_std]
extern crate alloc;

mod heap;

pub use heap::canonicalize::{Canonicalize, EncodeError};
pub use heap::decode::Decode;

#[cfg(feature = "jcs")]
pub use heap::jcs::Jcs;

#[cfg(feature = "json")]
pub use heap::json::JsonDecoder;

#[cfg(feature = "jcs")]
pub use heap::combined::JcsJsonEncoding;
