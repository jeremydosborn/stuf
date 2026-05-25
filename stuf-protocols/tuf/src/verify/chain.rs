//! TUF verification chain — the core MVP flow.
//!
//! timestamp → snapshot → targets → firmware
//!
//! Each step only becomes available after the previous succeeds.
//! The chain is generic over Transport, Clock, and Encoding —
//! injected by the app. Crypto is called directly via stuf-env
//! functions (feature-gated at compile time).
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
use stuf_env::transport::Transport;
use stuf_env::clock::Clock;

use crate::{
    error::{Error, Result},
    schema::{
        role::{Role, RoleType},
        root::Root,
        signed::Signed,
        snapshot::Snapshot,
        targets::{Target, Targets},
        timestamp::Timestamp,
    },
    verify::{
        expiry::check_expiry,
        hash::verify_target_hashes,
        signatures::verify_signatures,
        state::{Checked, Unverified},
    },
};

// ── Type states ───────────────────────────────────────────────────────────────

/// Entry point — bootstrapped from a trusted root baked into the binary.
pub struct TrustAnchor<T, C, E>
where
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    pub(crate) root: Checked<Root>,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) encoding: E,
}

pub struct TimestampChecked<T, C, E>
where
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    pub(crate) root: Checked<Root>,
    pub(crate) timestamp: Checked<Timestamp>,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) encoding: E,
}

pub struct SnapshotChecked<T, C, E>
where
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    pub(crate) root: Checked<Root>,
    pub(crate) snapshot: Checked<Snapshot>,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) encoding: E,
}

#[allow(dead_code)]
pub struct TargetsChecked<T, C, E>
where
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    pub(crate) root: Checked<Root>,
    pub(crate) snapshot: Checked<Snapshot>,
    pub(crate) targets: Checked<Targets>,
    pub(crate) transport: T,
    pub(crate) clock: C,
    pub(crate) encoding: E,
}

// ── TrustAnchor ───────────────────────────────────────────────────────────────

impl<T, C, E> TrustAnchor<T, C, E>
where
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    /// Bootstrap from a trusted root baked in at compile time.
    pub fn new(
        root_bytes: &[u8],
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
        )?;

        let checked = unverified.into_checked();
        Ok(Self {
            root: checked,
            transport,
            clock,
            encoding,
        })
    }

    /// Step 1 — fetch and verify timestamp.json via Transport.
    pub fn verify_timestamp(self) -> Result<TimestampChecked<T, C, E>> {
        let bytes = self
            .transport
            .fetch("timestamp.json")
            .map_err(|_| Error::Transport)?;
        self.verify_timestamp_inner(bytes.as_ref())
    }

    /// Step 1 (no_alloc) — verify pre-fetched timestamp bytes.
    pub fn verify_timestamp_bytes(self, bytes: &[u8]) -> Result<TimestampChecked<T, C, E>> {
        self.verify_timestamp_inner(bytes)
    }

    fn verify_timestamp_inner(self, bytes: &[u8]) -> Result<TimestampChecked<T, C, E>> {
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
        )?;

        let checked = unverified.into_checked();
        check_expiry(checked.get().expires(), &self.clock)?;

        Ok(TimestampChecked {
            root: self.root,
            timestamp: checked,
            transport: self.transport,
            clock: self.clock,
            encoding: self.encoding,
        })
    }
}

// ── TimestampChecked ──────────────────────────────────────────────────────────

impl<T, C, E> TimestampChecked<T, C, E>
where
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    /// Step 2 — fetch and verify snapshot.json via Transport.
    pub fn verify_snapshot(self) -> Result<SnapshotChecked<T, C, E>> {
        let bytes = self
            .transport
            .fetch("snapshot.json")
            .map_err(|_| Error::Transport)?;
        self.verify_snapshot_inner(bytes.as_ref())
    }

    /// Step 2 (no_alloc) — verify pre-fetched snapshot bytes.
    pub fn verify_snapshot_bytes(self, bytes: &[u8]) -> Result<SnapshotChecked<T, C, E>> {
        self.verify_snapshot_inner(bytes)
    }

    fn verify_snapshot_inner(self, bytes: &[u8]) -> Result<SnapshotChecked<T, C, E>> {
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
            transport: self.transport,
            clock: self.clock,
            encoding: self.encoding,
        })
    }
}

// ── SnapshotChecked ───────────────────────────────────────────────────────────

impl<T, C, E> SnapshotChecked<T, C, E>
where
    T: Transport,
    C: Clock,
    E: Canonicalize + Decode,
{
    /// Step 3 — fetch and verify targets.json via Transport.
    pub fn verify_targets(self) -> Result<TargetsChecked<T, C, E>> {
        let bytes = self
            .transport
            .fetch("targets.json")
            .map_err(|_| Error::Transport)?;
        self.verify_targets_inner(bytes.as_ref())
    }

    /// Step 3 (no_alloc) — verify pre-fetched targets bytes.
    pub fn verify_targets_bytes(self, bytes: &[u8]) -> Result<TargetsChecked<T, C, E>> {
        self.verify_targets_inner(bytes)
    }

    fn verify_targets_inner(self, bytes: &[u8]) -> Result<TargetsChecked<T, C, E>> {
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
            transport: self.transport,
            clock: self.clock,
            encoding: self.encoding,
        })
    }
}

// ── TargetsChecked ────────────────────────────────────────────────────────────

impl<T, C, E> TargetsChecked<T, C, E>
where
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

        // Hash check — calls stuf-env directly
        verify_target_hashes(bytes, &target_meta.hashes)?;

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
