use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::VerifyingKey;
use zbus::object_server::SignalEmitter;
use zbus::{interface, Connection};

use crate::error::Error;
use crate::nonce::NonceStore;
use crate::{activate, authz, lock};

pub struct Trigger {
    /// Trusted keys, any of which may authorize an activation. The root-owned
    /// trusted-keys file that supplies them is the trust boundary.
    keys: Vec<VerifyingKey>,
    nonces: NonceStore,
    activating: AtomicBool,
}

/// Releases the activation flag on drop, so a failed or panicking switch can't
/// leave the trigger wedged in `Busy`.
struct ActivationGuard<'a>(&'a AtomicBool);

impl Drop for ActivationGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Trigger {
    pub fn new(keys: Vec<VerifyingKey>) -> Self {
        Self {
            keys,
            nonces: NonceStore::new(),
            activating: AtomicBool::new(false),
        }
    }

    fn try_activate(&self) -> Option<ActivationGuard<'_>> {
        self.activating
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Acquire)
            .ok()
            .map(|_| ActivationGuard(&self.activating))
    }

    /// Verify before burning: a bad signature must never spend a victim's
    /// pending nonce. The burn is the single-use guarantee, so it lands exactly
    /// once and only after the signature checks out.
    fn authorize(&self, store_path: &str, signature: &str, nonce: &str) -> Result<(), Error> {
        authz::verify(&self.keys, store_path, signature, nonce)?;
        if !self.nonces.burn(nonce) {
            return Err(Error::NotAuthorized(
                "nonce not recognized, already used, or expired".to_string(),
            ));
        }
        Ok(())
    }
}

#[interface(name = "systems.staticroot.Trigger")]
impl Trigger {
    /// Issue a fresh single-use nonce. The caller signs it with the store path
    /// and hands both back to `switch_to_store_path`.
    async fn issue_nonce(&self) -> Result<String, Error> {
        self.nonces
            .issue()
            .ok_or_else(|| Error::Busy("too many outstanding nonces".to_string()))
    }

    /// Authorize, then switch. The trigger knows nothing about who signed or
    /// why, only that a trusted key authorized this exact path with a nonce it
    /// issued and has not yet burned. Burning before the switch keeps a crash
    /// mid-switch from stranding a reusable nonce.
    async fn switch_to_store_path(
        &self,
        store_path: String,
        signature: String,
        nonce: String,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), Error> {
        let _guard = self
            .try_activate()
            .ok_or_else(|| Error::Busy("an activation is already in progress".to_string()))?;

        self.authorize(&store_path, &signature, &nonce)?;

        let conn = conn.clone();
        blocking::unblock(move || activate::run(&store_path, &conn)).await
    }

    /// Machine-wide screen lock. Gated to the agent by the D-Bus policy and
    /// carries no activation authority, so it needs no signature.
    async fn lock_screen(&self, #[zbus(connection)] conn: &Connection) -> Result<(), Error> {
        lock::lock_sessions(conn).await
    }

    /// Streamed line-by-line `switch-to-configuration` output. The agent owns
    /// all user-facing presentation.
    #[zbus(signal)]
    async fn progress(emitter: &SignalEmitter<'_>, line: &str) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    use crate::encoding;

    const STORE: &str = "/nix/store/00000000000000000000000000000000-x";

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sign(sk: &SigningKey, store: &str, nonce: &str) -> String {
        hex::encode(sk.sign(&encoding::activation_message(store, nonce)).to_bytes())
    }

    #[test]
    fn try_activate_is_exclusive() {
        let t = Trigger::new(vec![]);
        let guard = t.try_activate().expect("first acquires");
        assert!(t.try_activate().is_none(), "refused while one is held");
        drop(guard);
        assert!(t.try_activate().is_some(), "released on drop");
    }

    #[test]
    fn authorize_spends_a_valid_nonce_once() {
        let sk = signing_key();
        let t = Trigger::new(vec![sk.verifying_key()]);
        let nonce = t.nonces.issue().unwrap();
        let sig = sign(&sk, STORE, &nonce);

        assert!(t.authorize(STORE, &sig, &nonce).is_ok());
        // Replaying the same signature no longer authorizes: the nonce is burned.
        assert!(matches!(
            t.authorize(STORE, &sig, &nonce),
            Err(Error::NotAuthorized(_))
        ));
    }

    #[test]
    fn bad_signature_spares_the_nonce() {
        let sk = signing_key();
        let t = Trigger::new(vec![sk.verifying_key()]);
        let nonce = t.nonces.issue().unwrap();

        assert!(matches!(
            t.authorize(STORE, &"00".repeat(64), &nonce),
            Err(Error::NotAuthorized(_))
        ));
        // The rejected signature never reached the burn, so the nonce still lives.
        assert!(t.nonces.burn(&nonce), "pending nonce survives a rejected signature");
    }
}
