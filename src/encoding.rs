//! Domain-separated, length-prefixed encoding of the message a signature
//! authorizes. The signer and the verifier must agree on these bytes exactly;
//! the known-answer tests below are mirrored in the agent's `fractal-signer` so
//! the two implementations cannot silently drift.

/// Context-and-version tag for an activation. Bump the version suffix if the
/// layout ever changes, so a signature can never be valid under two encodings.
pub const ACTIVATION_CONTEXT: &[u8] = b"systems.staticroot.trigger/activation/v1";

/// Context-and-version tag for a screen lock. Distinct from `ACTIVATION_CONTEXT`
/// so a signature that authorizes one operation can never verify as the other,
/// even though both are checked against the same trusted keys.
pub const LOCK_CONTEXT: &[u8] = b"systems.staticroot.trigger/lock/v1";

/// `ACTIVATION_CONTEXT ‖ len(store) ‖ store ‖ len(nonce) ‖ nonce`, each length a
/// little-endian `u64`. Length-prefixing makes the boundary between the path and
/// the nonce unambiguous, so no two distinct pairs share an encoding.
pub fn activation_message(store_path: &str, nonce: &str) -> Vec<u8> {
    let store = store_path.as_bytes();
    let nonce = nonce.as_bytes();
    let mut msg = Vec::with_capacity(ACTIVATION_CONTEXT.len() + 16 + store.len() + nonce.len());
    msg.extend_from_slice(ACTIVATION_CONTEXT);
    msg.extend_from_slice(&(store.len() as u64).to_le_bytes());
    msg.extend_from_slice(store);
    msg.extend_from_slice(&(nonce.len() as u64).to_le_bytes());
    msg.extend_from_slice(nonce);
    msg
}

/// `LOCK_CONTEXT ‖ len(nonce) ‖ nonce`, the length a little-endian `u64`. A lock
/// carries no store path: the trigger-issued nonce is the whole authorization,
/// so a captured signature dies with its single-use, device-local nonce.
pub fn lock_message(nonce: &str) -> Vec<u8> {
    let nonce = nonce.as_bytes();
    let mut msg = Vec::with_capacity(LOCK_CONTEXT.len() + 8 + nonce.len());
    msg.extend_from_slice(LOCK_CONTEXT);
    msg.extend_from_slice(&(nonce.len() as u64).to_le_bytes());
    msg.extend_from_slice(nonce);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    // Frozen vectors. The activation message must match the identical KAT in
    // fractal-signer; the lock message has no in-repo counterpart (the managed
    // control plane signs locks) but is frozen here so it cannot drift.
    const KAT_STORE: &str = "/nix/store/00000000000000000000000000000000-x";
    const KAT_NONCE: &str = "deadbeef";
    const KAT_ACTIVATION_MESSAGE_HEX: &str = "73797374656d732e737461746963726f6f742e747269676765722f61637469766174696f6e2f76312d000000000000002f6e69782f73746f72652f30303030303030303030303030303030303030303030303030303030303030302d7808000000000000006465616462656566";
    const KAT_LOCK_MESSAGE_HEX: &str = "73797374656d732e737461746963726f6f742e747269676765722f6c6f636b2f763108000000000000006465616462656566";

    #[test]
    fn activation_message_kat() {
        assert_eq!(
            hex::encode(activation_message(KAT_STORE, KAT_NONCE)),
            KAT_ACTIVATION_MESSAGE_HEX
        );
    }

    #[test]
    fn lock_message_kat() {
        assert_eq!(hex::encode(lock_message(KAT_NONCE)), KAT_LOCK_MESSAGE_HEX);
    }

    #[test]
    fn contexts_are_disjoint_prefixes() {
        // Neither context tag is a prefix of the other, so no lock message can
        // ever coincide with an activation message under any inputs.
        assert!(!ACTIVATION_CONTEXT.starts_with(LOCK_CONTEXT));
        assert!(!LOCK_CONTEXT.starts_with(ACTIVATION_CONTEXT));
    }

    #[test]
    fn length_prefix_prevents_ambiguity() {
        // Same concatenation, different split: must not collide.
        assert_ne!(activation_message("ab", "c"), activation_message("a", "bc"));
    }
}
