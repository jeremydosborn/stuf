//! stuf demo publisher
//!
//! Generates real ed25519 keys, signs TUF metadata, and serves it
//! over HTTP for the toaster QEMU demo.
//!
//! Usage: cargo run --bin publisher

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ── TUF metadata types (minimal, for signing) ─────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
struct KeyVal {
    public: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Key {
    keytype: String,
    scheme: String,
    keyval: KeyVal,
}

#[derive(Serialize, Deserialize, Clone)]
struct RoleKeys {
    keyids: Vec<String>,
    threshold: u32,
}

#[derive(Serialize, Deserialize)]
struct RootSigned {
    #[serde(rename = "_type")]
    role_type: String,
    spec_version: String,
    version: u32,
    expires: u64,
    consistent_snapshot: bool,
    keys: HashMap<String, Key>,
    roles: HashMap<String, RoleKeys>,
}

#[derive(Serialize, Deserialize)]
struct Hashes {
    sha256: String,
}

#[derive(Serialize, Deserialize)]
struct Target {
    length: u64,
    hashes: Hashes,
}

#[derive(Serialize, Deserialize)]
struct TargetsSigned {
    #[serde(rename = "_type")]
    role_type: String,
    spec_version: String,
    version: u32,
    expires: u64,
    targets: HashMap<String, Target>,
}

#[derive(Serialize, Deserialize)]
struct SnapshotMeta {
    version: u32,
}

#[derive(Serialize, Deserialize)]
struct SnapshotSigned {
    #[serde(rename = "_type")]
    role_type: String,
    spec_version: String,
    version: u32,
    expires: u64,
    meta: HashMap<String, SnapshotMeta>,
}

#[derive(Serialize, Deserialize)]
struct TimestampMeta {
    version: u32,
}

#[derive(Serialize, Deserialize)]
struct TimestampSigned {
    #[serde(rename = "_type")]
    role_type: String,
    spec_version: String,
    version: u32,
    expires: u64,
    meta: HashMap<String, TimestampMeta>,
}

#[derive(Serialize, Deserialize)]
struct Signature {
    keyid: String,
    sig: String,
}

#[derive(Serialize, Deserialize)]
struct Signed<T> {
    signed: T,
    signatures: Vec<Signature>,
}

// ── Key generation and signing ─────────────────────────────────────────────

struct KeyPair {
    signing_key: SigningKey,
    key_id: String,
    public_hex: String,
}

impl KeyPair {
    fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_bytes = signing_key.verifying_key().to_bytes();
        let public_hex = hex::encode(public_bytes);
        // Key ID is SHA256 of the public key bytes
        let mut hasher = Sha256::new();
        hasher.update(&public_bytes);
        let key_id = hex::encode(hasher.finalize());
        Self {
            signing_key,
            key_id,
            public_hex,
        }
    }

    fn to_tuf_key(&self) -> Key {
        Key {
            keytype: "ed25519".to_string(),
            scheme: "ed25519".to_string(),
            keyval: KeyVal {
                public: self.public_hex.clone(),
            },
        }
    }

    fn sign(&self, payload: &[u8]) -> String {
        let sig = self.signing_key.sign(payload);
        hex::encode(sig.to_bytes())
    }
}

fn sign_metadata<T: Serialize + serde::de::DeserializeOwned>(
    payload: &T,
    keypair: &KeyPair,
) -> Signed<T> {
    // Serialize the signed portion to canonical JSON
    let canonical = serde_json::to_vec(payload).expect("serialize");
    let sig_hex = keypair.sign(&canonical);
    Signed {
        signed: serde_json::from_slice(&canonical).expect("round-trip"),
        signatures: vec![Signature {
            keyid: keypair.key_id.clone(),
            sig: sig_hex,
        }],
    }
}

// ── Firmware binary ────────────────────────────────────────────────────────

fn make_firmware() -> Vec<u8> {
    // Fake firmware — in a real system this would be the actual binary
    let mut firmware = Vec::new();
    firmware.extend_from_slice(b"TOASTER_FIRMWARE_V1.1.0\n");
    firmware.extend_from_slice(b"Toast setting: golden brown\n");
    firmware.extend_from_slice(b"Verified by stuf TUF client\n");
    // Pad to 1KB
    firmware.resize(1024, 0u8);
    firmware
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ── Expiry helpers ─────────────────────────────────────────────────────────

fn expires_in_days(days: u64) -> u64 {
    // Current unix timestamp + days in seconds
    // For demo we use a fixed base: 2026-01-01 = 1735689600
    1735689600u64 + (days * 86400)
}

// ── Build TUF repository ───────────────────────────────────────────────────

struct Repo {
    root_json: Vec<u8>,
    targets_json: Vec<u8>,
    snapshot_json: Vec<u8>,
    timestamp_json: Vec<u8>,
    firmware: Vec<u8>,
    root_key_hex: String,
    root_key_id: String,
}

fn build_repo() -> Repo {
    println!("stuf demo publisher");
    println!("══════════════════════════════════════");
    println!();

    // Generate keypairs
    println!("generating ed25519 keypairs...");
    let root_key = KeyPair::generate();
    let targets_key = KeyPair::generate();
    let snapshot_key = KeyPair::generate();
    let timestamp_key = KeyPair::generate();

    println!("  root key id:      {}", &root_key.key_id[..16]);
    println!("  targets key id:   {}", &targets_key.key_id[..16]);
    println!("  snapshot key id:  {}", &snapshot_key.key_id[..16]);
    println!("  timestamp key id: {}", &timestamp_key.key_id[..16]);
    println!();

    // Firmware
    let firmware = make_firmware();
    let firmware_hash = sha256_hex(&firmware);
    let firmware_name = "toaster-firmware-1.1.0.bin";
    println!("firmware: {} ({} bytes)", firmware_name, firmware.len());
    println!("  sha256: {}", &firmware_hash[..32]);
    println!();

    // Build key map for root
    let mut keys = HashMap::new();
    keys.insert(root_key.key_id.clone(), root_key.to_tuf_key());
    keys.insert(targets_key.key_id.clone(), targets_key.to_tuf_key());
    keys.insert(snapshot_key.key_id.clone(), snapshot_key.to_tuf_key());
    keys.insert(timestamp_key.key_id.clone(), timestamp_key.to_tuf_key());

    // Build roles map for root
    let mut roles = HashMap::new();
    roles.insert(
        "root".to_string(),
        RoleKeys {
            keyids: vec![root_key.key_id.clone()],
            threshold: 1,
        },
    );
    roles.insert(
        "targets".to_string(),
        RoleKeys {
            keyids: vec![targets_key.key_id.clone()],
            threshold: 1,
        },
    );
    roles.insert(
        "snapshot".to_string(),
        RoleKeys {
            keyids: vec![snapshot_key.key_id.clone()],
            threshold: 1,
        },
    );
    roles.insert(
        "timestamp".to_string(),
        RoleKeys {
            keyids: vec![timestamp_key.key_id.clone()],
            threshold: 1,
        },
    );

    // Root
    print!("signing root.json...      ");
    let root_signed_payload = RootSigned {
        role_type: "root".to_string(),
        spec_version: "1.0.0".to_string(),
        version: 1,
        expires: expires_in_days(365),
        consistent_snapshot: false,
        keys,
        roles,
    };
    let root = sign_metadata(&root_signed_payload, &root_key);
    let root_json = serde_json::to_vec_pretty(&root).unwrap();
    println!("✓");

    // Targets
    print!("signing targets.json...   ");
    let mut targets = HashMap::new();
    targets.insert(
        firmware_name.to_string(),
        Target {
            length: firmware.len() as u64,
            hashes: Hashes {
                sha256: firmware_hash,
            },
        },
    );
    let targets_signed_payload = TargetsSigned {
        role_type: "targets".to_string(),
        spec_version: "1.0.0".to_string(),
        version: 1,
        expires: expires_in_days(30),
        targets,
    };
    let targets_meta = sign_metadata(&targets_signed_payload, &targets_key);
    let targets_json = serde_json::to_vec_pretty(&targets_meta).unwrap();
    println!("✓");

    // Snapshot
    print!("signing snapshot.json...  ");
    let mut meta = HashMap::new();
    meta.insert("targets.json".to_string(), SnapshotMeta { version: 1 });
    let snapshot_signed_payload = SnapshotSigned {
        role_type: "snapshot".to_string(),
        spec_version: "1.0.0".to_string(),
        version: 1,
        expires: expires_in_days(7),
        meta,
    };
    let snapshot_meta = sign_metadata(&snapshot_signed_payload, &snapshot_key);
    let snapshot_json = serde_json::to_vec_pretty(&snapshot_meta).unwrap();
    println!("✓");

    // Timestamp
    print!("signing timestamp.json... ");
    let mut ts_meta = HashMap::new();
    ts_meta.insert("snapshot.json".to_string(), TimestampMeta { version: 1 });
    let timestamp_signed_payload = TimestampSigned {
        role_type: "timestamp".to_string(),
        spec_version: "1.0.0".to_string(),
        version: 1,
        expires: expires_in_days(1),
        meta: ts_meta,
    };
    let timestamp_meta = sign_metadata(&timestamp_signed_payload, &timestamp_key);
    let timestamp_json = serde_json::to_vec_pretty(&timestamp_meta).unwrap();
    println!("✓");

    println!();
    println!("repository ready");
    println!();

    let root_key_hex = root_key.public_hex.clone();
    let root_key_id = root_key.key_id.clone();

    Repo {
        root_json,
        targets_json,
        snapshot_json,
        timestamp_json,
        firmware: firmware.to_vec(),
        root_key_hex,
        root_key_id,
    }
}

// ── Save repository to disk ────────────────────────────────────────────────

fn save_repo(repo: &Repo) {
    use std::fs;
    use std::path::Path;

    // Save to publisher-repo/ for semihosting transport
    let repo_dir = Path::new("stuf-examples/publisher-repo");
    fs::create_dir_all(repo_dir).expect("create publisher-repo");

    fs::write(repo_dir.join("root.json"), &repo.root_json).expect("write root.json");
    fs::write(repo_dir.join("timestamp.json"), &repo.timestamp_json).expect("write timestamp.json");
    fs::write(repo_dir.join("snapshot.json"), &repo.snapshot_json).expect("write snapshot.json");
    fs::write(repo_dir.join("targets.json"), &repo.targets_json).expect("write targets.json");
    fs::write(repo_dir.join("toaster-firmware-1.1.0.bin"), &repo.firmware).expect("write firmware");

    // Also save root.json to toaster factory/ for manufacture burn
    let factory_dir = Path::new("stuf-examples/toaster/factory");
    fs::create_dir_all(factory_dir).expect("create factory dir");
    fs::write(factory_dir.join("root.json"), &repo.root_json).expect("write factory root.json");

    println!("saved to stuf-examples/publisher-repo/");
    println!("saved root to stuf-examples/toaster/factory/");
    println!();
}

// ── Main ───────────────────────────────────────────────────────────────────

fn main() {
    let repo = build_repo();
    save_repo(&repo);
}
