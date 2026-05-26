//! Unified error type for stuf-tuf.
//! no_std compatible — no thiserror dependency.

use core::fmt;

#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Metadata could not be deserialized.
    Deserialize,
    /// Signature threshold not met.
    ThresholdNotMet { threshold: u32, valid: u32 },
    /// No valid signatures found.
    NoValidSignatures,
    /// Metadata has expired.
    Expired,
    /// Version mismatch detected.
    VersionMismatch { expected: u32, received: u32 },
    /// Snapshot metadata mismatch.
    SnapshotMismatch,
    /// Target hash mismatch.
    TargetHashMismatch,
    /// Target length mismatch.
    TargetLengthMismatch { expected: u64, actual: u64 },
    /// Target not found in metadata.
    TargetNotFound,
    /// No keys for role.
    NoKeysForRole,
    /// Transport error.
    Transport,
    /// Encoding error.
    Encoding,
    /// Metadata hash mismatch (timestamp→snapshot or snapshot→targets).
    MetadataHashMismatch,
    /// Metadata length mismatch (timestamp→snapshot or snapshot→targets).
    MetadataLengthMismatch { expected: u64, actual: u64 },
    /// No hash algorithm compiled in — cannot verify.
    NoHashAlgorithm,
    /// Key type or signature scheme not supported.
    UnsupportedKeyType,
    /// Target has no supported hash algorithm in its metadata.
    NoSupportedHash,
    /// Hash hex string has wrong length for its algorithm.
    InvalidHashLength { expected: usize, actual: usize },
    /// Hash hex string contains non-hex characters.
    InvalidHashEncoding,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Deserialize => write!(f, "failed to deserialize metadata"),
            Error::ThresholdNotMet { threshold, valid } => {
                write!(f, "threshold not met: needed {threshold}, got {valid}")
            }
            Error::NoValidSignatures => write!(f, "no valid signatures found"),
            Error::Expired => write!(f, "metadata has expired"),
            Error::VersionMismatch { expected, received } => {
                write!(
                    f,
                    "version mismatch: expected {expected}, received {received}"
                )
            }
            Error::SnapshotMismatch => write!(f, "snapshot metadata mismatch"),
            Error::TargetHashMismatch => write!(f, "target hash mismatch"),
            Error::TargetLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "target length mismatch: expected {expected}, got {actual}"
                )
            }
            Error::TargetNotFound => write!(f, "target not found"),
            Error::NoKeysForRole => write!(f, "no keys for role"),
            Error::Transport => write!(f, "transport error"),
            Error::Encoding => write!(f, "encoding error"),
            Error::MetadataHashMismatch => write!(f, "metadata hash mismatch"),
            Error::MetadataLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "metadata length mismatch: expected {expected}, got {actual}"
                )
            }
            Error::NoHashAlgorithm => write!(f, "no hash algorithm compiled in"),
            Error::UnsupportedKeyType => write!(f, "unsupported key type or signature scheme"),
            Error::NoSupportedHash => write!(f, "no supported hash in target metadata"),
            Error::InvalidHashLength { expected, actual } => {
                write!(
                    f,
                    "invalid hash length: expected {expected} hex chars, got {actual}"
                )
            }
            Error::InvalidHashEncoding => write!(f, "hash contains non-hex characters"),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

impl From<stuf_encoding::EncodeError> for Error {
    fn from(e: stuf_encoding::EncodeError) -> Self {
        match e {
            stuf_encoding::EncodeError::Decode => Error::Deserialize,
            stuf_encoding::EncodeError::Canonicalize => Error::Encoding,
        }
    }
}
