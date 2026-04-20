//! Unified error type for stuf-tuf.
//! no_std compatible — no thiserror dependency.

use core::fmt;

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
    /// Version rollback detected.
    VersionRollback { trusted: u32, received: u32 },
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
            Error::VersionRollback { trusted, received } => {
                write!(f, "rollback detected: trusted {trusted}, received {received}")
            }
            Error::SnapshotMismatch => write!(f, "snapshot metadata mismatch"),
            Error::TargetHashMismatch => write!(f, "target hash mismatch"),
            Error::TargetLengthMismatch { expected, actual } => {
                write!(f, "target length mismatch: expected {expected}, got {actual}")
            }
            Error::TargetNotFound => write!(f, "target not found"),
            Error::NoKeysForRole => write!(f, "no keys for role"),
            Error::Transport => write!(f, "transport error"),
            Error::Encoding => write!(f, "encoding error"),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
