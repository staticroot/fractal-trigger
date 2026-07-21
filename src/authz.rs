//! Activation authorization: a single Ed25519 signature over the trigger-issued
//! nonce and the store path. The trigger verifies only *authorization and
//! freshness* — whether the bytes at the path are trustworthy is Nix's job, not
//! ours. Nonce freshness (pending, unexpired, burn) is handled by the caller in
//! `trigger.rs`; this function is the pure signature check.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::encoding;
use crate::error::Error;

/// Verify that `signature` (hex, 64 bytes) authorizes activating `store_path`
/// with `nonce`, under at least one trusted key. `verify_strict` rejects
/// malleable and small-order signatures.
pub fn verify(
    keys: &[VerifyingKey],
    store_path: &str,
    signature: &str,
    nonce: &str,
) -> Result<(), Error> {
    let sig_bytes = hex::decode(signature)
        .map_err(|_| Error::NotAuthorized("signature is not valid hex".to_string()))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| Error::NotAuthorized("signature is not 64 bytes".to_string()))?;

    let msg = encoding::activation_message(store_path, nonce);
    for key in keys {
        if key.verify_strict(&msg, &sig).is_ok() {
            return Ok(());
        }
    }
    Err(Error::NotAuthorized(
        "no trusted key verifies this signature".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // Frozen KAT — mirrored in fractal-signer so signer and verifier can't drift.
    const KAT_SEED: [u8; 32] = [7u8; 32];
    const KAT_STORE: &str = "/nix/store/00000000000000000000000000000000-x";
    const KAT_NONCE: &str = "deadbeef";
    const KAT_SIGNATURE_HEX: &str = "eb0cf6e0622b2d460f741d222b04715329f773c585d47eb493955e9eaf98ac0ef274653dc16c7e025d3f67b197f2fe8319d89fa34707a1e558a80a0f13eead06";

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&KAT_SEED)
    }

    fn sign(sk: &SigningKey, store: &str, nonce: &str) -> String {
        hex::encode(sk.sign(&encoding::activation_message(store, nonce)).to_bytes())
    }

    #[test]
    fn frozen_signature_kat() {
        // Ed25519 is deterministic, so a fixed key + message is a stable vector.
        assert_eq!(sign(&signing_key(), KAT_STORE, KAT_NONCE), KAT_SIGNATURE_HEX);
    }

    #[test]
    fn accepts_valid_signature() {
        let sk = signing_key();
        let keys = vec![sk.verifying_key()];
        let sig = sign(&sk, KAT_STORE, KAT_NONCE);
        assert!(verify(&keys, KAT_STORE, &sig, KAT_NONCE).is_ok());
    }

    #[test]
    fn rejects_tampered_path() {
        let sk = signing_key();
        let keys = vec![sk.verifying_key()];
        let sig = sign(&sk, KAT_STORE, KAT_NONCE);
        assert!(verify(&keys, "/nix/store/11111111111111111111111111111111-x", &sig, KAT_NONCE).is_err());
    }

    #[test]
    fn rejects_tampered_nonce() {
        let sk = signing_key();
        let keys = vec![sk.verifying_key()];
        let sig = sign(&sk, KAT_STORE, KAT_NONCE);
        assert!(verify(&keys, KAT_STORE, &sig, "beefdead").is_err());
    }

    #[test]
    fn rejects_wrong_key() {
        let signer = signing_key();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let keys = vec![other.verifying_key()];
        let sig = sign(&signer, KAT_STORE, KAT_NONCE);
        assert!(verify(&keys, KAT_STORE, &sig, KAT_NONCE).is_err());
    }

    #[test]
    fn rejects_garbage_signature() {
        let keys = vec![signing_key().verifying_key()];
        assert!(verify(&keys, KAT_STORE, &"00".repeat(64), KAT_NONCE).is_err());
        assert!(verify(&keys, KAT_STORE, "not-hex", KAT_NONCE).is_err());
        assert!(verify(&keys, KAT_STORE, "abcd", KAT_NONCE).is_err()); // wrong length
    }
}
