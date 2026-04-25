pub mod canonicalize;
pub mod decode;

use alloc::vec::Vec;
use stuf_encoding::{Canonicalize, Decode, EncodeError};

pub use decode::json::JsonDecoder;

#[cfg(feature = "canonical-jcs")]
pub use canonicalize::jcs::Jcs;

/// Convenience type — implements both Canonicalize + Decode for TUF.
/// Pass this to TrustAnchor::new().
#[derive(Debug, Clone, Copy)]
pub struct TufEncoding;

impl Canonicalize for TufEncoding {
    fn canonicalize<T>(&self, value: &T) -> Result<Vec<u8>, EncodeError>
    where
        T: serde::Serialize,
    {
        #[cfg(feature = "canonical-jcs")]
        {
            Jcs.canonicalize(value)
        }

        #[cfg(not(feature = "canonical-jcs"))]
        {
            let _ = value;
            Err(EncodeError::Canonicalize)
        }
    }
}

impl Decode for TufEncoding {
    fn decode<T>(&self, bytes: &[u8]) -> Result<T, EncodeError>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        JsonDecoder.decode(bytes)
    }
}
