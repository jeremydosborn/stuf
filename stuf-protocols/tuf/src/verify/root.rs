use crate::{
    error::{Error, Result},
    schema::{
        keys::PublicKey,
        role::{RoleKeys, RoleType},
        root::Root,
        signed::Signature,
    },
    sign::traits::Verifier,
    verify::state::{Clock, Unverified, Verified},
};

/// Verify a root metadata file against a set of trusted keys.
///
/// TUF requires that a new root be signed by a threshold of keys from
/// BOTH the old root and the new root. This function handles the
/// single-root case (bootstrapping from a trusted root shipped with
/// the application) and is called twice during root rotation.
pub fn verify_root(
    unverified: Unverified<crate::schema::signed::Signed<Root>>,
    role_keys: &RoleKeys,
    available_keys: &std::collections::HashMap<crate::schema::keys::KeyId, PublicKey>,
    verifier: &dyn Verifier,
    clock: &dyn Clock,
) -> Result<Verified<Root>> {
    let canonical = unverified.canonical_bytes()?;
    let valid = count_valid_signatures(
        unverified.signatures(),
        role_keys,
        available_keys,
        &canonical,
        verifier,
    );

    if !role_keys.threshold_met(valid) {
        return Err(Error::ThresholdNotMet {
            threshold: role_keys.threshold,
            valid,
        });
    }

    let verified = unverified.into_verified();
    crate::verify::expiry::check_expiry(&verified, clock)?;
    Ok(verified)
}

/// During root rotation, verify that the new root is signed by a threshold
/// of keys from the OLD root AND a threshold of keys from the NEW root.
pub fn verify_root_rotation(
    unverified: Unverified<crate::schema::signed::Signed<Root>>,
    trusted: &Verified<Root>,
    verifier: &dyn Verifier,
    clock: &dyn Clock,
) -> Result<Verified<Root>> {
    let canonical = unverified.canonical_bytes()?;

    // Must satisfy old root's threshold
    let old_role_keys = trusted
        .get()
        .role_keys(&RoleType::Root)
        .ok_or_else(|| Error::NoKeysForRole("root".into()))?;

    let old_valid = count_valid_signatures(
        unverified.signatures(),
        old_role_keys,
        &trusted.get().keys,
        &canonical,
        verifier,
    );

    if !old_role_keys.threshold_met(old_valid) {
        return Err(Error::ThresholdNotMet {
            threshold: old_role_keys.threshold,
            valid: old_valid,
        });
    }

    // Parse inner to get new keys — we need them before fully trusting
    // the new root, which is intentional: we verify structure first.
    let new_root_inner: Root = serde_json::from_slice(&canonical)?;

    let new_role_keys = new_root_inner
        .roles
        .get("root")
        .ok_or_else(|| Error::NoKeysForRole("root".into()))?;

    let new_valid = count_valid_signatures(
        unverified.signatures(),
        new_role_keys,
        &new_root_inner.keys,
        &canonical,
        verifier,
    );

    if !new_role_keys.threshold_met(new_valid) {
        return Err(Error::ThresholdNotMet {
            threshold: new_role_keys.threshold,
            valid: new_valid,
        });
    }

    // Version must be exactly trusted_version + 1
    let expected_version = trusted.get().version() + 1;
    if new_root_inner.version != expected_version {
        return Err(Error::NonSequentialRootVersion {
            expected: expected_version,
            actual: new_root_inner.version,
        });
    }

    let verified = unverified.into_verified();
    crate::verify::expiry::check_expiry(&verified, clock)?;
    Ok(verified)
}

/// Count how many signatures in `sigs` are valid against keys in
/// `role_keys` using `available_keys` for key material.
pub(crate) fn count_valid_signatures(
    sigs: &[Signature],
    role_keys: &RoleKeys,
    available_keys: &std::collections::HashMap<crate::schema::keys::KeyId, PublicKey>,
    canonical: &[u8],
    verifier: &dyn Verifier,
) -> u32 {
    let mut valid = 0u32;
    let mut counted = std::collections::HashSet::new();

    for sig in sigs {
        // Only count keys authorized for this role
        if !role_keys.keyids.contains(&sig.keyid) {
            continue;
        }
        // Don't double-count the same key
        if counted.contains(&sig.keyid) {
            continue;
        }
        if let Some(pubkey) = available_keys.get(&sig.keyid) {
            if let Ok(sig_bytes) = sig.bytes() {
                if verifier.verify(pubkey, canonical, &sig_bytes).is_ok() {
                    valid += 1;
                    counted.insert(sig.keyid.clone());
                }
            }
        }
    }

    valid
}

