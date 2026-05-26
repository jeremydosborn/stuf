//! Combined JCS canonicalization + JSON decoding.
//!
//! Convenience type that implements both Canonicalize and Decode.
//! Pass this to any verification chain that needs both.

use alloc::vec::Vec;

use crate::heap::canonicalize::{Canonicalize, EncodeError};
use crate::heap::decode::Decode;
use crate::heap::jcs::Jcs;
use crate::heap::json::JsonDecoder;

/// JCS canonicalization + JSON decoding in one type.
/// Drop-in replacement for the old TufEncoding.
#[derive(Debug, Clone, Copy)]
pub struct JcsJsonEncoding;

impl Canonicalize for JcsJsonEncoding {
    fn canonicalize<T>(&self, value: &T) -> Result<Vec<u8>, EncodeError>
    where
        T: serde::Serialize,
    {
        Jcs.canonicalize(value)
    }
}

impl Decode for JcsJsonEncoding {
    fn decode<T>(&self, bytes: &[u8]) -> Result<T, EncodeError>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        JsonDecoder.decode(bytes)
    }
}
