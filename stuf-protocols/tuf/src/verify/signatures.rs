//! Signature verification helper.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{
    error::{Error, Result},
    schema::{
        keys::{KeyId, KeyType, PublicKey, SignatureScheme},
        role::RoleKeys,
        signed::Signature,
    },
};

pub fn verify_signatures(
    sigs: &[Signature],
    role_keys: &RoleKeys,
    available_keys: &BTreeMap<KeyId, PublicKey>,
    canonical: &[u8],
) -> Result<()> {
    let mut valid = 0u32;
    let mut counted: BTreeSet<KeyId> = BTreeSet::new();

    for sig in sigs {
        if !role_keys.keyids.contains(&sig.keyid) {
            continue;
        }

        if counted.contains(&sig.keyid) {
            continue;
        }

        if let Some(pubkey) = available_keys.get(&sig.keyid) {
            let sig_bytes: Vec<u8> = match hex::decode(&sig.sig) {
                Ok(b) => b,
                Err(_) => continue,
            };

            if verify_single(pubkey, canonical, &sig_bytes).is_ok() {
                valid += 1;
                counted.insert(sig.keyid.clone());
            }
        }
    }

    if role_keys.threshold_met(valid) {
        Ok(())
    } else {
        Err(Error::ThresholdNotMet {
            threshold: role_keys.threshold,
            valid,
        })
    }
}

/// Verify a single signature, checking keytype and scheme match.
/// Returns Ok(()) on success, Err on failure or unsupported type.
#[allow(unused_variables)]
fn verify_single(key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    // Check keytype and scheme match before attempting crypto
    match (&key.keytype, &key.scheme) {
        #[cfg(feature = "crypto-ed25519")]
        (KeyType::Ed25519, SignatureScheme::Ed25519) => {
            let pub_bytes: [u8; 32] = hex::decode(&key.keyval.public)
                .map_err(|_| Error::UnsupportedKeyType)?
                .try_into()
                .map_err(|_| Error::UnsupportedKeyType)?;

            let sig_bytes: [u8; 64] = signature
                .try_into()
                .map_err(|_| Error::UnsupportedKeyType)?;

            stuf_env::crypto::ed25519_verify(&pub_bytes, message, &sig_bytes)
                .map_err(|_| Error::NoValidSignatures)
        }

        // Mismatched keytype/scheme (e.g. Ed25519 key with RSA scheme)
        (KeyType::Ed25519, _) | (_, SignatureScheme::Ed25519) => Err(Error::UnsupportedKeyType),

        // Unsupported key types — fail explicitly
        _ => Err(Error::UnsupportedKeyType),
    }
}
