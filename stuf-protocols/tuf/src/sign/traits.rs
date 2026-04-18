use crate::schema::keys::PublicKey;

/// Signature verification abstraction.
///
/// Implemented by stuf-env (e.g. using ring or rustcrypto).
/// The library uses this to verify signatures during the trust chain
/// without owning any crypto primitives directly.
pub trait Verifier: Send + Sync {
    /// Verify that `signature` over `message` was produced by `key`.
    /// Returns Ok(()) if valid, Err if not.
    fn verify(
        &self,
        key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> crate::error::Result<()>;
}

/// Signing abstraction — used by the build/ side.
///
/// Implemented by stuf-env for software keys, or by an app-supplied
/// impl that delegates to an HSM, KMS, or other external signer.
/// The library never holds key material directly.
pub trait Signer: Send + Sync {
    /// The key ID this signer produces signatures for.
    fn key_id(&self) -> &crate::schema::keys::KeyId;

    /// The public key corresponding to this signer.
    fn public_key(&self) -> &PublicKey;

    /// Sign `message` and return the raw signature bytes.
    fn sign(&self, message: &[u8]) -> crate::error::Result<Vec<u8>>;
}

