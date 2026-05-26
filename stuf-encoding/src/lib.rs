#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod heap;

#[cfg(feature = "no-heap")]
pub mod no_heap;

#[cfg(feature = "alloc")]
pub use heap::error::EncodeError;

#[cfg(all(feature = "alloc", feature = "jcs"))]
pub use heap::jcs::canonicalize;

#[cfg(all(feature = "alloc", feature = "json"))]
pub use heap::json::decode;

#[cfg(not(feature = "alloc"))]
#[derive(Debug)]
pub enum EncodeError {
    Canonicalize,
    Decode,
}
