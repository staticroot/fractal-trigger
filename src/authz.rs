//! Signature authorization: a single Ed25519 signature over a domain-separated
//! `encoding` message. The trigger verifies only authorization and freshness;
//! whether the bytes at an activation path are trustworthy is Nix's job, not
//! ours. Nonce freshness and building the per-operation message live in the
//! caller (`trigger.rs`); this is the pure signature check.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::Error;

/// Verify that `signature` (hex, 64 bytes) is valid over `message` under at
/// least one trusted key. `verify_strict` rejects malleable and small-order
/// signatures. The domain separation that keeps an activation signature from
/// authorizing a lock (or vice versa) lives in `message`, not here.
pub fn verify(keys: &[VerifyingKey], message: &[u8], signature: &str) -> Result<(), Error> {
    let sig_bytes = hex::decode(signature)
        .map_err(|_| Error::NotAuthorized("signature is not valid hex".to_string()))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| Error::NotAuthorized("signature is not 64 bytes".to_string()))?;

    for key in keys {
        if key.verify_strict(message, &sig).is_ok() {
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

    use crate::encoding;

    // Frozen KAT, mirrored in fractal-signer so signer and verifier can't drift.
    const KAT_SEED: [u8; 32] = [7u8; 32];
    const KAT_STORE: &str = "/nix/store/00000000000000000000000000000000-x";
    const KAT_NONCE: &str = "deadbeef";
    const KAT_ACTIVATION_SIGNATURE_HEX: &str = "eb0cf6e0622b2d460f741d222b04715329f773c585d47eb493955e9eaf98ac0ef274653dc16c7e025d3f67b197f2fe8319d89fa34707a1e558a80a0f13eead06";
    // No in-repo signer counterpart: the managed control plane signs locks. Frozen
    // here so the lock encoding can never silently change out from under the trigger.
    const KAT_LOCK_SIGNATURE_HEX: &str = "5bc3139499ce918f730d7c73dd74e7d32cd79e17505f31c6a6936d4724d9e6ea5d155d0a2a4016d938e77619c40f4fddc8ce9d8722579d995f13eb05490a7709";

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&KAT_SEED)
    }

    fn sign(sk: &SigningKey, message: &[u8]) -> String {
        hex::encode(sk.sign(message).to_bytes())
    }

    #[test]
    fn frozen_activation_signature_kat() {
        // Ed25519 is deterministic, so a fixed key + message is a stable vector.
        let msg = encoding::activation_message(KAT_STORE, KAT_NONCE);
        assert_eq!(sign(&signing_key(), &msg), KAT_ACTIVATION_SIGNATURE_HEX);
    }

    #[test]
    fn frozen_lock_signature_kat() {
        let msg = encoding::lock_message(KAT_NONCE);
        assert_eq!(sign(&signing_key(), &msg), KAT_LOCK_SIGNATURE_HEX);
    }

    #[test]
    fn accepts_valid_signature() {
        let sk = signing_key();
        let keys = vec![sk.verifying_key()];
        let msg = encoding::activation_message(KAT_STORE, KAT_NONCE);
        let sig = sign(&sk, &msg);
        assert!(verify(&keys, &msg, &sig).is_ok());
    }

    #[test]
    fn rejects_tampered_message() {
        let sk = signing_key();
        let keys = vec![sk.verifying_key()];
        let sig = sign(&sk, &encoding::activation_message(KAT_STORE, KAT_NONCE));
        let tampered = encoding::activation_message(KAT_STORE, "beefdead");
        assert!(verify(&keys, &tampered, &sig).is_err());
    }

    /// A signature good for an activation must not verify against the lock
    /// message with the same nonce: the domain-separated context is the barrier.
    #[test]
    fn context_separation_blocks_cross_use() {
        let sk = signing_key();
        let keys = vec![sk.verifying_key()];
        let activation_sig = sign(&sk, &encoding::activation_message(KAT_STORE, KAT_NONCE));
        assert!(verify(&keys, &encoding::lock_message(KAT_NONCE), &activation_sig).is_err());

        let lock_sig = sign(&sk, &encoding::lock_message(KAT_NONCE));
        let activation_msg = encoding::activation_message(KAT_STORE, KAT_NONCE);
        assert!(verify(&keys, &activation_msg, &lock_sig).is_err());
    }

    #[test]
    fn rejects_wrong_key() {
        let signer = signing_key();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let keys = vec![other.verifying_key()];
        let msg = encoding::activation_message(KAT_STORE, KAT_NONCE);
        let sig = sign(&signer, &msg);
        assert!(verify(&keys, &msg, &sig).is_err());
    }

    #[test]
    fn rejects_garbage_signature() {
        let keys = vec![signing_key().verifying_key()];
        let msg = encoding::activation_message(KAT_STORE, KAT_NONCE);
        assert!(verify(&keys, &msg, &"00".repeat(64)).is_err());
        assert!(verify(&keys, &msg, "not-hex").is_err());
        assert!(verify(&keys, &msg, "abcd").is_err()); // wrong length
    }
}
