
/// Canonical JSON encoding for deterministic signing.
///
/// Implementations must produce a stable, deterministic byte representation
/// of the input suitable for cryptographic signing and verification.
///
/// For TUF, this means:
/// - sorted keys
/// - no insignificant whitespace
/// - consistent escaping rules
///
/// Other protocols may define different canonicalization rules.
pub trait CanonicalJson {
    type Error;

    /// Produce canonical JSON bytes for this value.
    fn canonical_json(&self) -> Result<Vec<u8>, Self::Error>;
}
