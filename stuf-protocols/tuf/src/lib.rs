#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(any(feature = "alloc", feature = "no-heap")))]
compile_error!("enable either `alloc` or `no-heap`");

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod env;
pub mod error;

#[cfg(feature = "alloc")]
pub mod schema;

#[cfg(feature = "alloc")]
pub mod sign;

pub mod verify;

#[cfg(feature = "publisher")]
pub mod build;

pub use error::{Error, Result};

#[cfg(feature = "alloc")]
pub use verify::chain::TrustAnchor;

#[cfg(feature = "no-heap")]
pub use verify::no_heap::TrustAnchor as NoHeapTrustAnchor;

pub use verify::limits::Limits;
