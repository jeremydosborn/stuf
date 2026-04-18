use crate::schema::keys::KeyId;
use serde::{Deserialize, Serialize};

/// A hex-encoded signature value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// The ID of the key that produced this signature.
    pub keyid: KeyId,
    /// The hex-encoded signature bytes.
    pub sig: String,
}

impl Signature {
    /// Decode the signature bytes from hex.
    pub fn bytes(&self) -> crate::error::Result<Vec<u8>> {
        hex::decode(&self.sig).map_err(|e| {
            crate::error::Error::InvalidSignatureEncoding(format!(
                "failed to decode signature for key {}: {e}",
                self.keyid
            ))
        })
    }
}

/// The canonical TUF signed envelope.
///
/// Every TUF metadata file is a `Signed<T>` — a list of signatures over
/// the canonical JSON encoding of the `signed` payload.
///
/// `T` is one of `Root`, `Targets`, `Snapshot`, or `Timestamp`.
/// The type parameter enforces that callers know what they are verifying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed<T> {
    pub signed: T,
    pub signatures: Vec<Signature>,
}

impl<T> Signed<T>
where
    T: Serialize,
{
    /// Produce the canonical JSON bytes of the `signed` field.
    /// This is what signatures are computed over.
    /// Callers in stuf-env use this to verify or produce signatures.
    pub fn canonical_bytes(&self) -> crate::error::Result<Vec<u8>> {
        // Standard JSON serialization here; stuf-env is responsible for
        // canonicalization (e.g. olpc-cjson or equivalent) if required
        // by the signature scheme in use.
        serde_json::to_vec(&self.signed).map_err(crate::error::Error::Deserialize)
    }
}
