//! The TUF signed envelope — every metadata file is Signed<T>.

use crate::schema::keys::KeyId;
use serde::{Deserialize, Serialize};

use alloc::string::String;
use alloc::vec::Vec;

/// A hex-encoded signature value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub keyid: KeyId,
    pub sig: String,
}

/// The canonical TUF signed envelope.
///
/// Every TUF metadata file is a `Signed<T>` — signatures over
/// the canonical encoding of the `signed` payload.
///
/// T is one of Root, Targets, Snapshot, or Timestamp.
/// Canonical byte production is handled by the Encoding trait
/// in stuf-env — this type owns no serialization logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed<T> {
    pub signed: T,
    pub signatures: Vec<Signature>,
}
