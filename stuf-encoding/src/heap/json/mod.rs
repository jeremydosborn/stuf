//! JSON decoder using serde_json.
//!
//! Not TUF-specific — any protocol that uses JSON metadata
//! can use this decoder.

use crate::{Decode, EncodeError};

#[derive(Debug, Clone, Copy)]
pub struct JsonDecoder;

impl Decode for JsonDecoder {
    fn decode<T>(&self, bytes: &[u8]) -> Result<T, EncodeError>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        serde_json::from_slice(bytes).map_err(|_| EncodeError::Decode)
    }
}
