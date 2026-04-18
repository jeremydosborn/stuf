use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    // Schema / deserialization
    #[error("failed to deserialize metadata: {0}")]
    Deserialize(#[from] serde_json::Error),

    #[error("invalid key ID: {0}")]
    InvalidKeyId(String),

    #[error("invalid key type: {0}")]
    InvalidKeyType(String),

    #[error("invalid signature encoding: {0}")]
    InvalidSignatureEncoding(String),

    // Verification
    #[error("metadata has expired")]
    Expired,

    #[error("signature threshold not met: needed {threshold}, got {valid}")]
    ThresholdNotMet { threshold: u32, valid: u32 },

    #[error("no valid signatures found for role {role}")]
    NoValidSignatures { role: String },

    #[error("root version is not sequential: expected {expected}, got {actual}")]
    NonSequentialRootVersion { expected: u32, actual: u32 },

    #[error("version rollback detected: trusted {trusted}, received {received}")]
    VersionRollback { trusted: u32, received: u32 },

    #[error("snapshot meta mismatch for {file}: {reason}")]
    SnapshotMismatch { file: String, reason: String },

    #[error("target hash mismatch for {target}")]
    TargetHashMismatch { target: String },

    #[error("target length mismatch for {target}: expected {expected}, got {actual}")]
    TargetLengthMismatch {
        target: String,
        expected: u64,
        actual: u64,
    },

    #[error("target not found: {0}")]
    TargetNotFound(String),

    #[error("delegation cycle detected at role {0}")]
    DelegationCycle(String),

    #[error("max delegation depth exceeded")]
    DelegationDepthExceeded,

    // Build
    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("role {0} has no keys assigned")]
    NoKeysForRole(String),
}

pub type Result<T> = std::result::Result<T, Error>;
