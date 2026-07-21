//! Domain-separated, length-prefixed encoding of the message a signature
//! authorizes. The signer and the verifier must agree on these bytes exactly;
//! the known-answer tests below are mirrored in the agent's `fractal-signer` so
//! the two implementations cannot silently drift.

/// Context-and-version tag. Bump the version suffix if the layout ever changes,
/// so a signature can never be valid under two different encodings.
pub const CONTEXT: &[u8] = b"systems.staticroot.trigger/activation/v1";

/// `CONTEXT ‖ len(store) ‖ store ‖ len(nonce) ‖ nonce`, each length a
/// little-endian `u64`. Length-prefixing makes the boundary between the path and
/// the nonce unambiguous, so no two distinct pairs share an encoding.
pub fn activation_message(store_path: &str, nonce: &str) -> Vec<u8> {
    let store = store_path.as_bytes();
    let nonce = nonce.as_bytes();
    let mut msg = Vec::with_capacity(CONTEXT.len() + 16 + store.len() + nonce.len());
    msg.extend_from_slice(CONTEXT);
    msg.extend_from_slice(&(store.len() as u64).to_le_bytes());
    msg.extend_from_slice(store);
    msg.extend_from_slice(&(nonce.len() as u64).to_le_bytes());
    msg.extend_from_slice(nonce);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    // Frozen vector — must match the identical KAT in fractal-signer.
    const KAT_STORE: &str = "/nix/store/00000000000000000000000000000000-x";
    const KAT_NONCE: &str = "deadbeef";
    const KAT_MESSAGE_HEX: &str = "73797374656d732e737461746963726f6f742e747269676765722f61637469766174696f6e2f76312d000000000000002f6e69782f73746f72652f30303030303030303030303030303030303030303030303030303030303030302d7808000000000000006465616462656566";

    #[test]
    fn message_kat() {
        assert_eq!(
            hex::encode(activation_message(KAT_STORE, KAT_NONCE)),
            KAT_MESSAGE_HEX
        );
    }

    #[test]
    fn length_prefix_prevents_ambiguity() {
        // Same concatenation, different split: must not collide.
        assert_ne!(activation_message("ab", "c"), activation_message("a", "bc"));
    }
}
