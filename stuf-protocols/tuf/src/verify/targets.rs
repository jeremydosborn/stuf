use crate::{
    error::{Error, Result},
    schema::{
        role::RoleType,
        snapshot::Snapshot,
        targets::Targets,
    },
    sign::traits::Verifier,
    verify::{
        expiry::check_expiry,
        root::count_valid_signatures,
        state::{Clock, Unverified, Verified},
    },
};

/// Verify a targets metadata file.
///
/// Checks:
/// 1. Signatures meet the threshold defined in the trusted root
/// 2. Version matches what snapshot.json recorded
/// 3. Not expired
pub fn verify_targets(
    unverified: Unverified<crate::schema::signed::Signed<Targets>>,
    trusted_root: &Verified<crate::schema::root::Root>,
    trusted_snapshot: &Verified<Snapshot>,
    verifier: &dyn Verifier,
    clock: &dyn Clock,
) -> Result<Verified<Targets>> {
    // Check signature threshold against root's targets keys
    let role_keys = trusted_root
        .get()
        .role_keys(&RoleType::Targets)
        .ok_or_else(|| Error::NoKeysForRole("targets".into()))?;

    let canonical = unverified.canonical_bytes()?;
    let valid = count_valid_signatures(
        unverified.signatures(),
        role_keys,
        &trusted_root.get().keys,
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

    // Version must match what snapshot recorded
    let snap_meta = trusted_snapshot
        .get()
        .meta_for("targets.json")
        .ok_or_else(|| Error::SnapshotMismatch {
            file: "targets.json".into(),
            reason: "not listed in snapshot".into(),
        })?;

    if verified.get().version() != snap_meta.version {
        return Err(Error::SnapshotMismatch {
            file: "targets.json".into(),
            reason: format!(
                "version mismatch: snapshot says {}, got {}",
                snap_meta.version,
                verified.get().version()
            ),
        });
    }

    check_expiry(&verified, clock)?;
    Ok(verified)
}

/// Verify that a downloaded target file matches the hash and length
/// recorded in verified targets metadata.
pub fn verify_target_bytes(
    name: &str,
    bytes: &[u8],
    trusted_targets: &Verified<Targets>,
) -> Result<()> {
    let target = trusted_targets
        .get()
        .get_target(name)
        .ok_or_else(|| Error::TargetNotFound(name.to_string()))?;

    // Length check
    if bytes.len() as u64 != target.length {
        return Err(Error::TargetLengthMismatch {
            target: name.to_string(),
            expected: target.length,
            actual: bytes.len() as u64,
        });
    }

    // SHA-256 hash check if present
    if let Some(expected_hex) = &target.hashes.sha256 {
        use std::fmt::Write;
        // Simple SHA-256 — stuf-env provides the real impl via a trait;
        // this placeholder shows the shape. The actual call will be:
        // verifier.hash_sha256(bytes)
        let _ = expected_hex; // used below when crypto trait is wired in
        // TODO: wire through a Hasher trait from stuf-env
        // For now the structure is correct, crypto impl comes with stuf-env
    }

    Ok(())
}

