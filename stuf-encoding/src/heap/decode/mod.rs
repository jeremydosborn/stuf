use crate::EncodeError;

pub trait Decode {
    fn decode<T>(&self, bytes: &[u8]) -> Result<T, EncodeError>
    where
        T: for<'de> serde::Deserialize<'de>;
}
