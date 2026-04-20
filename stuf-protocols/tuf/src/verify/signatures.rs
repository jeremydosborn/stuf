//! Signature verification helper.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::{
    error::{Error, Result},
    schema::{
        keys::{KeyId, PublicKey},
        role::RoleKeys,
        signed::Signature,
    },
    sign::traits::Verifier,
};

pub fn verify_signatures(
    sigs: &[Signature],
    role_keys: &RoleKeys,
    available_keys: &BTreeMap<KeyId, PublicKey>,
    canonical: &[u8],
    verifier: &dyn Verifier,
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
            if verifier.verify(pubkey, canonical, &sig_bytes).is_ok() {
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
