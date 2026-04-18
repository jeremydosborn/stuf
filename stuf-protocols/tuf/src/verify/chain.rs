use crate::{
    error::{Error, Result},
    schema::{
        role::RoleType,
        root::Root,
        snapshot::Snapshot,
        targets::Targets,
        timestamp::Timestamp,
    },
    sign::traits::Verifier,
    verify::{
        expiry::check_expiry,
        root::{count_valid_signatures, verify_root, verify_root_rotation},
        state::{Clock, Unverified, Verified},
        targets::verify_targets,
    },
};

/// The TUF verification chain.
///
/// Drives the client through the standard TUF update sequence:
///   1. Refresh root (with rotation if needed)
///   2. Verify timestamp
///   3. Verify snapshot
///   4. Verify targets
///
/// Each step only becomes available after the previous one succeeds.
/// The type states are enforced structurally — you cannot call
/// `verify_snapshot` before `verify_timestamp` has returned a
/// `TimestampVerified` chain.
///
/// The chain owns no I/O — every fetch is a caller-supplied closure.
pub struct TrustAnchor {
    pub(crate) root: Verified<Root>,
    pub(crate) verifier: Box<dyn Verifier>,
    pub(crate) clock: Box<dyn Clock>,
}

pub struct TimestampVerified {
    pub(crate) root: Verified<Root>,
    pub(crate) timestamp: Verified<Timestamp>,
    pub(crate) verifier: Box<dyn Verifier>,
    pub(crate) clock: Box<dyn Clock>,
}

pub struct SnapshotVerified {
    pub(crate) root: Verified<Root>,
    pub(crate) timestamp: Verified<Timestamp>,
    pub(crate) snapshot: Verified<Snapshot>,
    pub(crate) verifier: Box<dyn Verifier>,
    pub(crate) clock: Box<dyn Clock>,
}

pub struct TargetsVerified {
    pub(crate) root: Verified<Root>,
    pub(crate) snapshot: Verified<Snapshot>,
    pub(crate) targets: Verified<Targets>,
    pub(crate) verifier: Box<dyn Verifier>,
    pub(crate) clock: Box<dyn Clock>,
}

impl TrustAnchor {
    /// Bootstrap the chain from a trusted root shipped with the application.
    ///
    /// `trusted_root_bytes` is the root.json you trust unconditionally —
    /// typically bundled at build time or provisioned at manufacturing.
    pub fn new(
        trusted_root_bytes: &[u8],
        verifier: Box<dyn Verifier>,
        clock: Box<dyn Clock>,
    ) -> Result<Self> {
        let unverified: Unverified<crate::schema::signed::Signed<Root>> =
            Unverified::from_bytes(trusted_root_bytes)?;

        let root_keys = {
            let inner: Root = serde_json::from_slice(trusted_root_bytes)?;
            inner
                .roles
                .get("root")
                .ok_or_else(|| Error::NoKeysForRole("root".into()))?
                .clone()
        };

        // For the initial anchor, verify root against itself
        let inner: Root = serde_json::from_slice(trusted_root_bytes)?;
        let verified = verify_root(unverified, &root_keys, &inner.keys, verifier.as_ref(), clock.as_ref())?;

        Ok(Self { root: verified, verifier, clock })
    }

    /// Attempt root rotation.
    ///
    /// Fetches successive root versions until no newer version exists,
    /// verifying each against both the previous and new keys per the spec.
    /// `fetch` is called with the versioned filename e.g. "2.root.json".
    pub fn update_root<F>(mut self, mut fetch: F) -> Result<Self>
    where
        F: FnMut(&str) -> Option<Vec<u8>>,
    {
        loop {
            let next_version = self.root.get().version() + 1;
            let filename = format!("{next_version}.root.json");

            match fetch(&filename) {
                None => break, // No newer root — we're current
                Some(bytes) => {
                    let unverified: Unverified<crate::schema::signed::Signed<Root>> =
                        Unverified::from_bytes(&bytes)?;
                    let new_root = verify_root_rotation(
                        unverified,
                        &self.root,
                        self.verifier.as_ref(),
                        self.clock.as_ref(),
                    )?;
                    self.root = new_root;
                }
            }
        }
        Ok(self)
    }

    /// Verify timestamp.json using the current trusted root.
    pub fn verify_timestamp<F>(self, mut fetch: F) -> Result<TimestampVerified>
    where
        F: FnMut(&str) -> Vec<u8>,
    {
        let bytes = fetch("timestamp.json");
        let unverified: Unverified<crate::schema::signed::Signed<Timestamp>> =
            Unverified::from_bytes(&bytes)?;

        let role_keys = self
            .root
            .get()
            .role_keys(&RoleType::Timestamp)
            .ok_or_else(|| Error::NoKeysForRole("timestamp".into()))?;

        let canonical = unverified.canonical_bytes()?;
        let valid = count_valid_signatures(
            unverified.signatures(),
            role_keys,
            &self.root.get().keys,
            &canonical,
            self.verifier.as_ref(),
        );

        if !role_keys.threshold_met(valid) {
            return Err(Error::ThresholdNotMet {
                threshold: role_keys.threshold,
                valid,
            });
        }

        let verified = unverified.into_verified();
        check_expiry(&verified, self.clock.as_ref())?;

        Ok(TimestampVerified {
            root: self.root,
            timestamp: verified,
            verifier: self.verifier,
            clock: self.clock,
        })
    }
}

impl TimestampVerified {
    /// Verify snapshot.json, checking version against timestamp.
    pub fn verify_snapshot<F>(self, mut fetch: F) -> Result<SnapshotVerified>
    where
        F: FnMut(&str) -> Vec<u8>,
    {
        let snap_meta = self
            .timestamp
            .get()
            .snapshot_meta()
            .ok_or_else(|| Error::SnapshotMismatch {
                file: "snapshot.json".into(),
                reason: "not referenced in timestamp".into(),
            })?;

        let bytes = fetch("snapshot.json");
        let unverified: Unverified<crate::schema::signed::Signed<Snapshot>> =
            Unverified::from_bytes(&bytes)?;

        let role_keys = self
            .root
            .get()
            .role_keys(&RoleType::Snapshot)
            .ok_or_else(|| Error::NoKeysForRole("snapshot".into()))?;

        let canonical = unverified.canonical_bytes()?;
        let valid = count_valid_signatures(
            unverified.signatures(),
            role_keys,
            &self.root.get().keys,
            &canonical,
            self.verifier.as_ref(),
        );

        if !role_keys.threshold_met(valid) {
            return Err(Error::ThresholdNotMet {
                threshold: role_keys.threshold,
                valid,
            });
        }

        let verified = unverified.into_verified();

        // Version must match timestamp's record
        if verified.get().version() < snap_meta.version {
            return Err(Error::VersionRollback {
                trusted: snap_meta.version,
                received: verified.get().version(),
            });
        }

        check_expiry(&verified, self.clock.as_ref())?;

        Ok(SnapshotVerified {
            root: self.root,
            timestamp: self.timestamp,
            snapshot: verified,
            verifier: self.verifier,
            clock: self.clock,
        })
    }
}

impl SnapshotVerified {
    /// Verify targets.json, checking version against snapshot.
    pub fn verify_targets<F>(self, mut fetch: F) -> Result<TargetsVerified>
    where
        F: FnMut(&str) -> Vec<u8>,
    {
        let bytes = fetch("targets.json");
        let unverified: Unverified<crate::schema::signed::Signed<Targets>> =
            Unverified::from_bytes(&bytes)?;

        let verified = verify_targets(
            unverified,
            &self.root,
            &self.snapshot,
            self.verifier.as_ref(),
            self.clock.as_ref(),
        )?;

        Ok(TargetsVerified {
            root: self.root,
            snapshot: self.snapshot,
            targets: verified,
            verifier: self.verifier,
            clock: self.clock,
        })
    }
}

impl TargetsVerified {
    /// The verified targets — safe to use for update decisions.
    pub fn targets(&self) -> &Verified<Targets> {
        &self.targets
    }

    /// The verified root — available if the app needs to inspect keys.
    pub fn root(&self) -> &Verified<Root> {
        &self.root
    }
}

