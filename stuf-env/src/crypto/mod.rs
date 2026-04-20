//! Crypto implementations for stuf-env.
//!
//! Ed25519 signature verification using ed25519-dalek.
//! Implements stuf-tuf::sign::traits::Verifier and verify_hash.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use stuf_tuf::{
    schema::{keys::{KeyType, PublicKey}, targets::Hashes},
    sign::traits::{VerifyError, Verifier},
};

/// Ed25519 verifier using ed25519-dalek.
/// Implements the Verifier trait defined in stuf-tuf.
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(
        &self,
        key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), VerifyError> {
        if key.keytype != KeyType::Ed25519 {
            return Err(VerifyError);
        }

        let key_bytes = hex::decode(&key.keyval.public).map_err(|_| VerifyError)?;
        let key_array: [u8; 32] = key_bytes.try_into().map_err(|_| VerifyError)?;
        let verifying_key = VerifyingKey::from_bytes(&key_array).map_err(|_| VerifyError)?;

        let sig_array: [u8; 64] = signature.try_into().map_err(|_| VerifyError)?;
        let sig = Signature::from_bytes(&sig_array);

        use ed25519_dalek::Verifier as _;
        verifying_key.verify(message, &sig).map_err(|_| VerifyError)
    }

    fn verify_hash(
        &self,
        bytes: &[u8],
        hashes: &Hashes,
    ) -> Result<(), VerifyError> {
        if let Some(expected_hex) = &hashes.sha256 {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            let actual = hasher.finalize();
            let actual_hex = hex::encode(actual);
            if actual_hex != *expected_hex {
                return Err(VerifyError);
            }
        }
        Ok(())
    }
}
