//! Configurable metadata limits for the TUF verification chain.
//!
//! These limits bound the maximum size and complexity of metadata
//! that the verifier will accept. They exist for two reasons:
//!
//! 1. **Security** — prevent resource exhaustion from malicious
//!    metadata served by a compromised mirror (the "endless data"
//!    attack described in the TUF spec).
//!
//! 2. **Embedded sizing** — on no-heap targets, these limits
//!    determine the size of fixed buffers at compile time.
//!
//! The TUF spec deliberately leaves limit values to implementers:
//! "The value for X is set by the authors of the application using TUF."
//!
//! Users can override the defaults via `Limits::new()` and pass
//! custom limits to `TrustAnchor::with_limits()`.

/// Metadata size and complexity limits.
///
/// All limits are enforced before parsing — oversized input is
/// rejected without touching the JSON parser.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum size of root.json in bytes.
    pub max_root_bytes: usize,
    /// Maximum size of timestamp.json in bytes.
    pub max_timestamp_bytes: usize,
    /// Maximum size of snapshot.json in bytes.
    pub max_snapshot_bytes: usize,
    /// Maximum size of targets.json in bytes.
    pub max_targets_bytes: usize,
    /// Maximum number of keys in root metadata.
    pub max_keys: usize,
    /// Maximum number of signatures on any metadata file.
    pub max_signatures: usize,
    /// Maximum number of target entries in targets metadata.
    pub max_targets_entries: usize,
}

impl Limits {
    /// Construct custom limits.
    pub const fn new(
        max_root_bytes: usize,
        max_timestamp_bytes: usize,
        max_snapshot_bytes: usize,
        max_targets_bytes: usize,
        max_keys: usize,
        max_signatures: usize,
        max_targets_entries: usize,
    ) -> Self {
        Self {
            max_root_bytes,
            max_timestamp_bytes,
            max_snapshot_bytes,
            max_targets_bytes,
            max_keys,
            max_signatures,
            max_targets_entries,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        DEFAULT
    }
}

/// Default limits — generous for embedded, safe against resource exhaustion.
///
/// These are sized for a typical firmware update use case:
/// - A handful of signing keys (< 32)
/// - One or two target files per update
/// - Metadata well under 16 KB each
///
/// For cloud/server deployments with many targets or delegations,
/// increase `max_targets_bytes` and `max_targets_entries`.
pub const DEFAULT: Limits = Limits {
    max_root_bytes: 16_384,     // 16 KB
    max_timestamp_bytes: 2_048, // 2 KB
    max_snapshot_bytes: 4_096,  // 4 KB
    max_targets_bytes: 16_384,  // 16 KB
    max_keys: 32,
    max_signatures: 16,
    max_targets_entries: 64,
};
