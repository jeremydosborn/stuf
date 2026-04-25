use alloc::vec::Vec;
use core::fmt;

#[derive(Debug)]
pub enum EncodeError {
    Canonicalize,
    Decode,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::Canonicalize => write!(f, "canonicalization failed"),
            EncodeError::Decode => write!(f, "decoding failed"),
        }
    }
}

pub trait Canonicalize {
    fn canonicalize<T>(&self, value: &T) -> Result<Vec<u8>, EncodeError>
    where
        T: serde::Serialize;
}
