//! JSON encoding implementation using serde_json.

use stuf_tuf::{encoding::Encoding, error::Error};

pub struct JsonEncoding;

impl Encoding for JsonEncoding {
    fn decode<T>(&self, bytes: &[u8]) -> Result<T, Error>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        serde_json::from_slice(bytes).map_err(|_| Error::Deserialize)
    }

    fn canonical<T>(&self, value: &T) -> Result<Vec<u8>, Error>
    where
        T: serde::Serialize,
    {
        serde_json::to_vec(value).map_err(|_| Error::Encoding)
    }
}
