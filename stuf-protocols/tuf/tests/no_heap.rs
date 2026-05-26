#![cfg(feature = "no-heap")]

use std::fs;
use std::path::PathBuf;

use stuf_env::clock::FixedClock;
use stuf_env::transport::Transport;
use stuf_tuf::verify::no_heap::TrustAnchor;

const NOW: u64 = 1_700_000_000;

#[derive(Clone, Copy, Debug)]
struct NoTransport;

#[derive(Clone, Copy, Debug)]
struct NoTransportError;

impl Transport for NoTransport {
    type Buffer = &'static [u8];
    type Error = NoTransportError;

    fn fetch(&self, _id: &str) -> Result<Self::Buffer, Self::Error> {
        Err(NoTransportError)
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .canonicalize()
        .expect("workspace root")
}

fn read(path: &str) -> Vec<u8> {
    fs::read(repo_root().join(path)).unwrap_or_else(|e| {
        panic!("failed to read {path}: {e}");
    })
}

#[test]
fn no_heap_root_verifies_against_publisher_output() {
    let root = read("stuf-examples/toaster/factory/root.json");

    let _anchor = TrustAnchor::new(&root, NoTransport, FixedClock(NOW))
        .expect("no-heap root should verify");
}

#[test]
fn no_heap_full_chain_verifies_against_publisher_output() {
    let root = read("stuf-examples/toaster/factory/root.json");
    let timestamp = read("stuf-examples/.generated/publisher-repo/timestamp.json");
    let snapshot = read("stuf-examples/.generated/publisher-repo/snapshot.json");
    let targets = read("stuf-examples/.generated/publisher-repo/targets.json");
    let firmware = read("stuf-examples/.generated/publisher-repo/toaster-firmware-1.1.0.bin");

    let anchor = TrustAnchor::new(&root, NoTransport, FixedClock(NOW))
        .expect("no-heap root should verify");

    let timestamp = anchor
        .verify_timestamp_bytes(&timestamp)
        .expect("no-heap timestamp should verify");

    let snapshot = timestamp
        .verify_snapshot_bytes(&snapshot)
        .expect("no-heap snapshot should verify");

    let targets = snapshot
        .verify_targets_bytes(&targets)
        .expect("no-heap targets should verify");

    let verified = targets
        .verify_target_bytes("toaster-firmware-1.1.0.bin", &firmware)
        .expect("no-heap firmware should verify");

    assert_eq!(verified.into_inner().length, firmware.len() as u64);
}
