//! Shared test helpers for stuf-tuf tests.

#![allow(dead_code)]

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use stuf_env::crypto::sha256_hex;

use stuf_tuf::schema::{
    keys::{KeyId, KeyType, KeyValue, PublicKey, SignatureScheme},
    role::RoleKeys,
    root::Root,
    signed::{Signature, Signed},
    snapshot::{Snapshot, SnapshotMeta},
    targets::{Hashes, Target, Targets},
    timestamp::{Timestamp, TimestampMeta},
};

// ── Real ed25519 key generation ───────────────────────────────────────────────

pub struct TestKey {
    pub signing_key: SigningKey,
    pub key_id: KeyId,
    pub public_key: PublicKey,
}

impl TestKey {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_bytes = signing_key.verifying_key().to_bytes();
        let public_hex = hex::encode(public_bytes);

        let key_id = KeyId(sha256_hex(&public_bytes));

        let public_key = PublicKey {
            keytype: KeyType::Ed25519,
            scheme: SignatureScheme::Ed25519,
            keyval: KeyValue { public: public_hex },
        };

        Self {
            signing_key,
            key_id,
            public_key,
        }
    }

    pub fn sign(&self, payload: &[u8]) -> String {
        let sig = self.signing_key.sign(payload);
        hex::encode(sig.to_bytes())
    }

    pub fn role_keys(&self, threshold: u32) -> RoleKeys {
        RoleKeys::new(vec![self.key_id.clone()], threshold)
    }
}

// ── Signing helpers ───────────────────────────────────────────────────────────

fn canonical_bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
    stuf_encoding::canonicalize(value).expect("canonicalize")
}

pub fn sign_root(root: &Root, key: &TestKey) -> Vec<u8> {
    let payload = canonical_bytes(root);
    let sig_hex = key.sign(&payload);
    let signed = Signed {
        signed: root.clone(),
        signatures: vec![Signature {
            keyid: key.key_id.clone(),
            sig: sig_hex,
        }],
    };
    serde_json::to_vec(&signed).unwrap()
}

pub fn sign_timestamp(ts: &Timestamp, key: &TestKey) -> Vec<u8> {
    let payload = canonical_bytes(ts);
    let sig_hex = key.sign(&payload);
    let signed = Signed {
        signed: ts.clone(),
        signatures: vec![Signature {
            keyid: key.key_id.clone(),
            sig: sig_hex,
        }],
    };
    serde_json::to_vec(&signed).unwrap()
}

pub fn sign_snapshot(snap: &Snapshot, key: &TestKey) -> Vec<u8> {
    let payload = canonical_bytes(snap);
    let sig_hex = key.sign(&payload);
    let signed = Signed {
        signed: snap.clone(),
        signatures: vec![Signature {
            keyid: key.key_id.clone(),
            sig: sig_hex,
        }],
    };
    serde_json::to_vec(&signed).unwrap()
}

pub fn sign_targets(targets: &Targets, key: &TestKey) -> Vec<u8> {
    let payload = canonical_bytes(targets);
    let sig_hex = key.sign(&payload);
    let signed = Signed {
        signed: targets.clone(),
        signatures: vec![Signature {
            keyid: key.key_id.clone(),
            sig: sig_hex,
        }],
    };
    serde_json::to_vec(&signed).unwrap()
}

// ── Metadata builders ─────────────────────────────────────────────────────────

pub fn make_root(
    root_key: &TestKey,
    targets_key: &TestKey,
    snapshot_key: &TestKey,
    timestamp_key: &TestKey,
    expires: u64,
    version: u32,
) -> Root {
    let mut keys = BTreeMap::new();
    keys.insert(root_key.key_id.clone(), root_key.public_key.clone());
    keys.insert(targets_key.key_id.clone(), targets_key.public_key.clone());
    keys.insert(snapshot_key.key_id.clone(), snapshot_key.public_key.clone());
    keys.insert(
        timestamp_key.key_id.clone(),
        timestamp_key.public_key.clone(),
    );

    let mut roles = BTreeMap::new();
    roles.insert("root".to_string(), root_key.role_keys(1));
    roles.insert("targets".to_string(), targets_key.role_keys(1));
    roles.insert("snapshot".to_string(), snapshot_key.role_keys(1));
    roles.insert("timestamp".to_string(), timestamp_key.role_keys(1));

    Root {
        role_type: "root".to_string(),
        spec_version: "1.0.0".to_string(),
        version,
        expires,
        consistent_snapshot: false,
        keys,
        roles,
    }
}

pub fn make_timestamp(snapshot_version: u32, expires: u64, version: u32) -> Timestamp {
    let mut meta = BTreeMap::new();
    meta.insert(
        "snapshot.json".to_string(),
        TimestampMeta {
            version: snapshot_version,
            length: None,
            hashes: None,
        },
    );
    Timestamp {
        role_type: "timestamp".to_string(),
        spec_version: "1.0.0".to_string(),
        version,
        expires,
        meta,
    }
}

/// Timestamp with explicit hash and length for snapshot.
pub fn make_timestamp_with_hash(
    snapshot_version: u32,
    expires: u64,
    version: u32,
    snapshot_hash: Option<BTreeMap<String, String>>,
    snapshot_length: Option<u64>,
) -> Timestamp {
    let mut meta = BTreeMap::new();
    meta.insert(
        "snapshot.json".to_string(),
        TimestampMeta {
            version: snapshot_version,
            length: snapshot_length,
            hashes: snapshot_hash,
        },
    );
    Timestamp {
        role_type: "timestamp".to_string(),
        spec_version: "1.0.0".to_string(),
        version,
        expires,
        meta,
    }
}

pub fn make_snapshot(targets_version: u32, expires: u64, version: u32) -> Snapshot {
    let mut meta = BTreeMap::new();
    meta.insert(
        "targets.json".to_string(),
        SnapshotMeta {
            version: targets_version,
            length: None,
            hashes: None,
        },
    );
    Snapshot {
        role_type: "snapshot".to_string(),
        spec_version: "1.0.0".to_string(),
        version,
        expires,
        meta,
    }
}

/// Snapshot with explicit hash and length for targets.
pub fn make_snapshot_with_hash(
    targets_version: u32,
    expires: u64,
    version: u32,
    targets_hash: Option<BTreeMap<String, String>>,
    targets_length: Option<u64>,
) -> Snapshot {
    let mut meta = BTreeMap::new();
    meta.insert(
        "targets.json".to_string(),
        SnapshotMeta {
            version: targets_version,
            length: targets_length,
            hashes: targets_hash,
        },
    );
    Snapshot {
        role_type: "snapshot".to_string(),
        spec_version: "1.0.0".to_string(),
        version,
        expires,
        meta,
    }
}

pub fn make_targets(firmware: &[u8], expires: u64, version: u32) -> Targets {
    let hash = sha256_hex(firmware);
    let mut targets_map = BTreeMap::new();
    targets_map.insert(
        "firmware.bin".to_string(),
        Target {
            length: firmware.len() as u64,
            hashes: Hashes {
                sha256: Some(hash),
                sha512: None,
            },
            custom: BTreeMap::new(),
        },
    );
    Targets {
        role_type: "targets".to_string(),
        spec_version: "1.0.0".to_string(),
        version,
        expires,
        targets: targets_map,
        delegations: None,
    }
}

/// Targets with a custom hash string for the firmware entry.
pub fn make_targets_with_hash(
    firmware: &[u8],
    sha256: Option<String>,
    sha512: Option<String>,
    expires: u64,
    version: u32,
) -> Targets {
    let mut targets_map = BTreeMap::new();
    targets_map.insert(
        "firmware.bin".to_string(),
        Target {
            length: firmware.len() as u64,
            hashes: Hashes { sha256, sha512 },
            custom: BTreeMap::new(),
        },
    );
    Targets {
        role_type: "targets".to_string(),
        spec_version: "1.0.0".to_string(),
        version,
        expires,
        targets: targets_map,
        delegations: None,
    }
}

/// Compute SHA-256 hash of bytes and return as a BTreeMap suitable for
/// TimestampMeta.hashes / SnapshotMeta.hashes.
pub fn sha256_hash_map(bytes: &[u8]) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("sha256".to_string(), sha256_hex(bytes));
    m
}

// ── Constants ─────────────────────────────────────────────────────────────────

pub const FIRMWARE: &[u8] = b"FIRMWARE_V1.1.0_GOLDEN_BROWN\0\0\0\0";
pub const FAR_FUTURE: u64 = 9_999_999_999;
pub const PAST: u64 = 1_000;
pub const NOW: u64 = 1_735_689_600; // 2026-01-01

// ── MockTransport ─────────────────────────────────────────────────────────────

pub struct MockTransport {
    pub files: BTreeMap<String, Vec<u8>>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            files: BTreeMap::new(),
        }
    }

    pub fn with(mut self, name: &str, data: Vec<u8>) -> Self {
        self.files.insert(name.to_string(), data);
        self
    }
}

impl stuf_env::transport::Transport for MockTransport {
    type Buffer = Vec<u8>;
    type Error = ();

    fn fetch(&self, id: &str) -> Result<Vec<u8>, ()> {
        self.files.get(id).cloned().ok_or(())
    }
}
