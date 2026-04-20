mod common;

use common::*;
use stuf_env::crypto::Ed25519Verifier;
use stuf_tuf::error::Error;
use stuf_tuf::verify::chain::TrustAnchor;
use stuf_tuf::verify::state::FixedClock;

fn build_chain(firmware_in_targets: &[u8], firmware_served: &[u8]) -> (Vec<u8>, MockTransport) {
    let rk = TestKey::generate();
    let tk = TestKey::generate();
    let sk = TestKey::generate();
    let tsk = TestKey::generate();

    let root = make_root(&rk, &tk, &sk, &tsk, FAR_FUTURE, 1);
    let root_bytes = sign_root(&root, &rk);
    let targets = make_targets(firmware_in_targets, FAR_FUTURE, 1);
    let ts = make_timestamp(1, FAR_FUTURE, 1);
    let snap = make_snapshot(1, FAR_FUTURE, 1);

    let transport = MockTransport::new()
        .with("timestamp.json", sign_timestamp(&ts, &tsk))
        .with("snapshot.json", sign_snapshot(&snap, &sk))
        .with("targets.json", sign_targets(&targets, &tk))
        .with("firmware.bin", firmware_served.to_vec());

    (root_bytes, transport)
}

#[test]
fn correct_hash_passes() {
    let (root_bytes, transport) = build_chain(FIRMWARE, FIRMWARE);
    let anchor = TrustAnchor::new(
        &root_bytes,
        Ed25519Verifier,
        transport,
        FixedClock(NOW),
        JsonEncoding,
    )
    .unwrap();
    let result = anchor
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets()
        .unwrap()
        .verify_target("firmware.bin");
    assert!(result.is_ok());
}

#[test]
fn tampered_firmware_hash_rejected() {
    let tampered = b"TAMPERED_FIRMWARE_EVIL_EVIL_EVIL";
    let (root_bytes, transport) = build_chain(FIRMWARE, tampered);
    let anchor = TrustAnchor::new(
        &root_bytes,
        Ed25519Verifier,
        transport,
        FixedClock(NOW),
        JsonEncoding,
    )
    .unwrap();
    let result = anchor
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets()
        .unwrap()
        .verify_target("firmware.bin");
    assert!(matches!(result, Err(Error::TargetHashMismatch)));
}

#[test]
fn length_mismatch_rejected() {
    let longer = b"FIRMWARE_V1.1.0_GOLDEN_BROWN_PLUS_EXTRA_BYTES_APPENDED";
    let (root_bytes, transport) = build_chain(FIRMWARE, longer);
    let anchor = TrustAnchor::new(
        &root_bytes,
        Ed25519Verifier,
        transport,
        FixedClock(NOW),
        JsonEncoding,
    )
    .unwrap();
    let result = anchor
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets()
        .unwrap()
        .verify_target("firmware.bin");
    assert!(matches!(result, Err(Error::TargetLengthMismatch { .. })));
}

#[test]
fn unknown_target_rejected() {
    let (root_bytes, transport) = build_chain(FIRMWARE, FIRMWARE);
    let anchor = TrustAnchor::new(
        &root_bytes,
        Ed25519Verifier,
        transport,
        FixedClock(NOW),
        JsonEncoding,
    )
    .unwrap();
    let result = anchor
        .verify_timestamp()
        .unwrap()
        .verify_snapshot()
        .unwrap()
        .verify_targets()
        .unwrap()
        .verify_target("does-not-exist.bin");
    assert!(matches!(result, Err(Error::TargetNotFound)));
}
