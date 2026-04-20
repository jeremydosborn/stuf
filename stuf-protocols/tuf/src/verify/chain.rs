//! TUF verification chain — the core MVP flow.
//!
//! timestamp → snapshot → targets → firmware
//!
//! Each step only becomes available after the previous succeeds.
//! The chain is generic over Transport, Clock, Verifier, and Encoding —
//! all injected by the app via stuf-env implementations.
//!
//! MVP scope: trusted root baked in, no root rotation.

use crate::{
    encoding::Encoding,
    env::transport::Transport,
    error::{Error, Result},
    schema::{
        role::{Role, RoleType},
        root::Root,
        signed::Signed,
        snapshot::Snapshot,
        targets::{Target, Targets},
        timestamp::Timestamp,
    },
    sign::traits::Verifier,
    verify::{
        expiry::check_expiry,
        signatures::verify_signatures,
        state::{Clock, Unverified, Verified},
    },
};

/// Entry point — bootstrapped from a trusted root baked into the binary.
///
/// MVP: root is trusted unconditionally via include_bytes!().
/// Root rotation is out of scope.
pub struct TrustAnchor<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Encoding,
{
    pub(crate) root: Verified<Root>,
    pub(crate) verifier: V,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) encoding: E,
}

pub struct TimestampVerified<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Encoding,
{
    pub(crate) root: Verified<Root>,
    pub(crate) timestamp: Verified<Timestamp>,
    pub(crate) verifier: V,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) encoding: E,
}

pub struct SnapshotVerified<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Encoding,
{
    pub(crate) root: Verified<Root>,
    pub(crate) snapshot: Verified<Snapshot>,
    pub(crate) verifier: V,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) encoding: E,
}

pub struct TargetsVerified<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Encoding,
{
    pub(crate) root: Verified<Root>,
    pub(crate) snapshot: Verified<Snapshot>,
    pub(crate) targets: Verified<Targets>,
    pub(crate) verifier: V,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) encoding: E,
}

impl<V, T, C, E> TrustAnchor<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Encoding,
{
    /// Bootstrap from a trusted root baked in at compile time.
    pub fn new(
        root_bytes: &[u8],
        verifier: V,
        transport: T,
        clock: C,
        encoding: E,
    ) -> Result<Self> {
        let signed: Signed<Root> = encoding.decode(root_bytes)?;
        let unverified = Unverified::from_signed(signed);

        let root_inner = unverified.payload().clone();
        let role_keys = root_inner
            .role_keys(&RoleType::Root)
            .ok_or(Error::NoKeysForRole)?;

        let canonical = encoding.canonical(unverified.payload())?;
        verify_signatures(
            unverified.signatures(),
            role_keys,
            &root_inner.keys,
            &canonical,
            &verifier,
        )?;

        let verified = unverified.into_verified();
        Ok(Self { root: verified, verifier, transport, clock, encoding })
    }

    /// Step 1 — fetch and verify timestamp.json
    pub fn verify_timestamp(self) -> Result<TimestampVerified<V, T, C, E>> {
        let bytes = self.transport
            .fetch("timestamp.json")
            .map_err(|_| Error::Transport)?;

        let signed: Signed<Timestamp> = self.encoding.decode(bytes.as_ref())?;
        let unverified = Unverified::from_signed(signed);

        let role_keys = self.root
            .get()
            .role_keys(&RoleType::Timestamp)
            .ok_or(Error::NoKeysForRole)?;

        let canonical = self.encoding.canonical(unverified.payload())?;
        verify_signatures(
            unverified.signatures(),
            role_keys,
            &self.root.get().keys,
            &canonical,
            &self.verifier,
        )?;

        let verified = unverified.into_verified();
        check_expiry(verified.get().expires(), &self.clock)?;

        Ok(TimestampVerified {
            root: self.root,
            timestamp: verified,
            verifier: self.verifier,
            transport: self.transport,
            clock: self.clock,
            encoding: self.encoding,
        })
    }
}

impl<V, T, C, E> TimestampVerified<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Encoding,
{
    /// Step 2 — fetch and verify snapshot.json
    pub fn verify_snapshot(self) -> Result<SnapshotVerified<V, T, C, E>> {
        let snap_meta = self.timestamp
            .get()
            .snapshot_meta()
            .ok_or(Error::SnapshotMismatch)?;

        let bytes = self.transport
            .fetch("snapshot.json")
            .map_err(|_| Error::Transport)?;

        let signed: Signed<Snapshot> = self.encoding.decode(bytes.as_ref())?;
        let unverified = Unverified::from_signed(signed);

        let role_keys = self.root
            .get()
            .role_keys(&RoleType::Snapshot)
            .ok_or(Error::NoKeysForRole)?;

        let canonical = self.encoding.canonical(unverified.payload())?;
        verify_signatures(
            unverified.signatures(),
            role_keys,
            &self.root.get().keys,
            &canonical,
            &self.verifier,
        )?;

        let verified = unverified.into_verified();

        // Version must match timestamp's record
        if verified.get().version() < snap_meta.version {
            return Err(Error::VersionRollback {
                trusted: snap_meta.version,
                received: verified.get().version(),
            });
        }

        check_expiry(verified.get().expires(), &self.clock)?;

        Ok(SnapshotVerified {
            root: self.root,
            snapshot: verified,
            verifier: self.verifier,
            transport: self.transport,
            clock: self.clock,
            encoding: self.encoding,
        })
    }
}

impl<V, T, C, E> SnapshotVerified<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Encoding,
{
    /// Step 3 — fetch and verify targets.json
    pub fn verify_targets(self) -> Result<TargetsVerified<V, T, C, E>> {
        let snap_meta = self.snapshot
            .get()
            .meta_for("targets.json")
            .ok_or(Error::SnapshotMismatch)?;

        let bytes = self.transport
            .fetch("targets.json")
            .map_err(|_| Error::Transport)?;

        let signed: Signed<Targets> = self.encoding.decode(bytes.as_ref())?;
        let unverified = Unverified::from_signed(signed);

        let role_keys = self.root
            .get()
            .role_keys(&RoleType::Targets)
            .ok_or(Error::NoKeysForRole)?;

        let canonical = self.encoding.canonical(unverified.payload())?;
        verify_signatures(
            unverified.signatures(),
            role_keys,
            &self.root.get().keys,
            &canonical,
            &self.verifier,
        )?;

        let verified = unverified.into_verified();

        // Version must match snapshot's record
        if verified.get().version() < snap_meta.version {
            return Err(Error::VersionRollback {
                trusted: snap_meta.version,
                received: verified.get().version(),
            });
        }

        check_expiry(verified.get().expires(), &self.clock)?;

        Ok(TargetsVerified {
            root: self.root,
            snapshot: self.snapshot,
            targets: verified,
            verifier: self.verifier,
            transport: self.transport,
            clock: self.clock,
            encoding: self.encoding,
        })
    }
}

impl<V, T, C, E> TargetsVerified<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Encoding,
{
    /// Step 4 — fetch firmware and verify against targets metadata
    pub fn verify_target(&self, name: &str) -> Result<Verified<Target>> {
        let target_meta = self.targets
            .get()
            .get_target(name)
            .ok_or(Error::TargetNotFound)?;

        let bytes = self.transport
            .fetch(name)
            .map_err(|_| Error::Transport)?;

        let bytes = bytes.as_ref();

        // Length check
        if bytes.len() as u64 != target_meta.length {
            return Err(Error::TargetLengthMismatch {
                expected: target_meta.length,
                actual: bytes.len() as u64,
            });
        }

        // Hash check delegated to verifier — stuf-env owns crypto
        self.verifier
            .verify_hash(bytes, &target_meta.hashes)
            .map_err(|_| Error::TargetHashMismatch)?;

        Ok(Verified(target_meta.clone()))
    }

    pub fn targets(&self) -> &Verified<Targets> {
        &self.targets
    }

    pub fn root(&self) -> &Verified<Root> {
        &self.root
    }
}


