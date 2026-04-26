//! TUF verification chain — the core MVP flow.
//!
//! timestamp → snapshot → targets → firmware
//!
//! Each step only becomes available after the previous succeeds.
//! The chain is generic over Transport, Clock, Verifier, and Encoding —
//! all injected by the app via stuf-env implementations.
//!
//! Internal chain state uses Checked<T> (signature checks passed).
//! The final output — verify_target / verify_target_bytes — returns
//! core's Verified<T>, the one true trust type.
//!
//! Two fetch modes:
//!   - verify_timestamp() etc. — chain fetches via Transport
//!   - verify_timestamp_bytes() etc. — caller passes pre-fetched &[u8]
//!     For no_alloc bare metal where the app owns all buffers.
//!
//! MVP scope: trusted root baked in, no root rotation.

use stuf_core::trust::Verified;
use stuf_encoding::{Canonicalize, Decode};

use crate::{
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
        state::{Checked, Clock, Unverified},
    },
};

// ── Type states ───────────────────────────────────────────────────────────────

/// Entry point — bootstrapped from a trusted root baked into the binary.
pub struct TrustAnchor<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    pub(crate) root: Checked<Root>,
    pub(crate) verifier: V,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) encoding: E,
}

pub struct TimestampChecked<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    pub(crate) root: Checked<Root>,
    pub(crate) timestamp: Checked<Timestamp>,
    pub(crate) verifier: V,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) encoding: E,
}

pub struct SnapshotChecked<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    pub(crate) root: Checked<Root>,
    pub(crate) snapshot: Checked<Snapshot>,
    pub(crate) verifier: V,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) encoding: E,
}

#[allow(dead_code)]
pub struct TargetsChecked<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    pub(crate) root: Checked<Root>,
    pub(crate) snapshot: Checked<Snapshot>,
    pub(crate) targets: Checked<Targets>,
    pub(crate) verifier: V,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) encoding: E,
}

// ── TrustAnchor ───────────────────────────────────────────────────────────────

impl<V, T, C, E> TrustAnchor<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
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

        let canonical = encoding.canonicalize(unverified.payload())?;
        verify_signatures(
            unverified.signatures(),
            role_keys,
            &root_inner.keys,
            &canonical,
            &verifier,
        )?;

        let checked = unverified.into_checked();
        Ok(Self {
            root: checked,
            verifier,
            transport,
            clock,
            encoding,
        })
    }

    /// Step 1 — fetch and verify timestamp.json via Transport.
    pub fn verify_timestamp(self) -> Result<TimestampChecked<V, T, C, E>> {
        let bytes = self
            .transport
            .fetch("timestamp.json")
            .map_err(|_| Error::Transport)?;
        self.verify_timestamp_inner(bytes.as_ref())
    }

    /// Step 1 (no_alloc) — verify pre-fetched timestamp bytes.
    pub fn verify_timestamp_bytes(self, bytes: &[u8]) -> Result<TimestampChecked<V, T, C, E>> {
        self.verify_timestamp_inner(bytes)
    }

    fn verify_timestamp_inner(self, bytes: &[u8]) -> Result<TimestampChecked<V, T, C, E>> {
        let signed: Signed<Timestamp> = self.encoding.decode(bytes)?;
        let unverified = Unverified::from_signed(signed);

        let role_keys = self
            .root
            .get()
            .role_keys(&RoleType::Timestamp)
            .ok_or(Error::NoKeysForRole)?;

        let canonical = self.encoding.canonicalize(unverified.payload())?;
        verify_signatures(
            unverified.signatures(),
            role_keys,
            &self.root.get().keys,
            &canonical,
            &self.verifier,
        )?;

        let checked = unverified.into_checked();
        check_expiry(checked.get().expires(), &self.clock)?;

        Ok(TimestampChecked {
            root: self.root,
            timestamp: checked,
            verifier: self.verifier,
            transport: self.transport,
            clock: self.clock,
            encoding: self.encoding,
        })
    }
}

// ── TimestampChecked ──────────────────────────────────────────────────────────

impl<V, T, C, E> TimestampChecked<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    /// Step 2 — fetch and verify snapshot.json via Transport.
    pub fn verify_snapshot(self) -> Result<SnapshotChecked<V, T, C, E>> {
        let bytes = self
            .transport
            .fetch("snapshot.json")
            .map_err(|_| Error::Transport)?;
        self.verify_snapshot_inner(bytes.as_ref())
    }

    /// Step 2 (no_alloc) — verify pre-fetched snapshot bytes.
    pub fn verify_snapshot_bytes(self, bytes: &[u8]) -> Result<SnapshotChecked<V, T, C, E>> {
        self.verify_snapshot_inner(bytes)
    }

    fn verify_snapshot_inner(self, bytes: &[u8]) -> Result<SnapshotChecked<V, T, C, E>> {
        let snap_meta = self
            .timestamp
            .get()
            .snapshot_meta()
            .ok_or(Error::SnapshotMismatch)?;

        let signed: Signed<Snapshot> = self.encoding.decode(bytes)?;
        let unverified = Unverified::from_signed(signed);

        let role_keys = self
            .root
            .get()
            .role_keys(&RoleType::Snapshot)
            .ok_or(Error::NoKeysForRole)?;

        let canonical = self.encoding.canonicalize(unverified.payload())?;
        verify_signatures(
            unverified.signatures(),
            role_keys,
            &self.root.get().keys,
            &canonical,
            &self.verifier,
        )?;

        let checked = unverified.into_checked();

        if checked.get().version() != snap_meta.version {
            return Err(Error::VersionMismatch {
                expected: snap_meta.version,
                received: checked.get().version(),
            });
        }

        check_expiry(checked.get().expires(), &self.clock)?;

        Ok(SnapshotChecked {
            root: self.root,
            snapshot: checked,
            verifier: self.verifier,
            transport: self.transport,
            clock: self.clock,
            encoding: self.encoding,
        })
    }
}

// ── SnapshotChecked ───────────────────────────────────────────────────────────

impl<V, T, C, E> SnapshotChecked<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    /// Step 3 — fetch and verify targets.json via Transport.
    pub fn verify_targets(self) -> Result<TargetsChecked<V, T, C, E>> {
        let bytes = self
            .transport
            .fetch("targets.json")
            .map_err(|_| Error::Transport)?;
        self.verify_targets_inner(bytes.as_ref())
    }

    /// Step 3 (no_alloc) — verify pre-fetched targets bytes.
    pub fn verify_targets_bytes(self, bytes: &[u8]) -> Result<TargetsChecked<V, T, C, E>> {
        self.verify_targets_inner(bytes)
    }

    fn verify_targets_inner(self, bytes: &[u8]) -> Result<TargetsChecked<V, T, C, E>> {
        let snap_meta = self
            .snapshot
            .get()
            .meta_for("targets.json")
            .ok_or(Error::SnapshotMismatch)?;

        let signed: Signed<Targets> = self.encoding.decode(bytes)?;
        let unverified = Unverified::from_signed(signed);

        let role_keys = self
            .root
            .get()
            .role_keys(&RoleType::Targets)
            .ok_or(Error::NoKeysForRole)?;

        let canonical = self.encoding.canonicalize(unverified.payload())?;
        verify_signatures(
            unverified.signatures(),
            role_keys,
            &self.root.get().keys,
            &canonical,
            &self.verifier,
        )?;

        let checked = unverified.into_checked();

        if checked.get().version() != snap_meta.version {
            return Err(Error::VersionMismatch {
                expected: snap_meta.version,
                received: checked.get().version(),
            });
        }

        check_expiry(checked.get().expires(), &self.clock)?;

        Ok(TargetsChecked {
            root: self.root,
            snapshot: self.snapshot,
            targets: checked,
            verifier: self.verifier,
            transport: self.transport,
            clock: self.clock,
            encoding: self.encoding,
        })
    }
}

// ── TargetsChecked ────────────────────────────────────────────────────────────

impl<V, T, C, E> TargetsChecked<V, T, C, E>
where
    V: Verifier,
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    /// Step 4 — fetch firmware via Transport and verify against targets metadata.
    /// Returns core's Verified<Target> — the one true trust type.
    pub fn verify_target(&self, name: &str) -> Result<Verified<Target>> {
        self.targets
            .get()
            .get_target(name)
            .ok_or(Error::TargetNotFound)?;

        let bytes = self.transport.fetch(name).map_err(|_| Error::Transport)?;
        self.verify_target_inner(name, bytes.as_ref())
    }

    /// Step 4 (no_alloc) — verify pre-fetched firmware bytes.
    /// Returns core's Verified<Target> — the one true trust type.
    pub fn verify_target_bytes(&self, name: &str, bytes: &[u8]) -> Result<Verified<Target>> {
        self.verify_target_inner(name, bytes)
    }

    fn verify_target_inner(&self, name: &str, bytes: &[u8]) -> Result<Verified<Target>> {
        let target_meta = self
            .targets
            .get()
            .get_target(name)
            .ok_or(Error::TargetNotFound)?;

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

        // Full TUF chain passed — return core's Verified<T>
        Ok(Verified::new(target_meta.clone()))
    }

    pub fn targets(&self) -> &Checked<Targets> {
        &self.targets
    }

    pub fn root(&self) -> &Checked<Root> {
        &self.root
    }
}
