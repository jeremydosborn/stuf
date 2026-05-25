//! Signature verification helper.
//!
//! Calls stuf-env crypto functions directly. The protocol logic here
//! handles TUF-specific concerns: key type dispatch, threshold counting,
//! role key matching. The actual crypto is in stuf-env.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{
    error::{Error, Result},
    schema::{
        keys::{KeyId, PublicKey},
        role::RoleKeys,
        signed::Signature,
    },
};

#[cfg(feature = "crypto-ed25519")]
use crate::schema::keys::KeyType;

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
            if verify_single(pubkey, canonical, &sig_bytes) {
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

/// Dispatch to the right stuf-env crypto function based on key type.
/// This is where TUF key types meet raw crypto primitives.
fn verify_single(
    key: &PublicKey,
    #[cfg_attr(not(feature = "crypto-ed25519"), allow(unused_variables))] message: &[u8],
    #[cfg_attr(not(feature = "crypto-ed25519"), allow(unused_variables))] signature: &[u8],
) -> bool {
    match key.keytype {
        #[cfg(feature = "crypto-ed25519")]
        KeyType::Ed25519 => {
            let key_bytes = match hex::decode(&key.keyval.public) {
                Ok(b) => b,
                Err(_) => return false,
            };
            let key_array: [u8; 32] = match key_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let sig_array: [u8; 64] = match signature.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            stuf_env::crypto::ed25519_verify(&key_array, message, &sig_array).is_ok()
        }
        #[allow(unreachable_patterns)]
        _ => false,
    }
}
