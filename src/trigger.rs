use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::VerifyingKey;
use zbus::object_server::SignalEmitter;
use zbus::{interface, Connection};

use crate::error::Error;
use crate::nonce::NonceStore;
use crate::{activate, authz, encoding, lock};

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

    /// Verify a signature over `message`, then burn `nonce`. Verify before
    /// burning: a bad signature must never spend a victim's pending nonce. The
    /// burn is the single-use guarantee, so it lands exactly once and only after
    /// the signature checks out. `nonce` must be the one bound into `message`;
    /// the caller builds the domain-separated message for its operation.
    fn authorize(&self, message: &[u8], signature: &str, nonce: &str) -> Result<(), Error> {
        authz::verify(&self.keys, message, signature)?;
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

        let message = encoding::activation_message(&store_path, &nonce);
        self.authorize(&message, &signature, &nonce)?;

        let conn = conn.clone();
        blocking::unblock(move || activate::run(&store_path, &conn)).await
    }

    /// Machine-wide screen lock. Enterprise-only: the managed control plane signs
    /// a fresh trigger-issued nonce under its trusted key, exactly as an
    /// activation is signed. The trigger stays mode-agnostic — a standalone
    /// device simply has no party holding a key to sign a lock, so none verifies.
    /// The D-Bus caller policy still gates *reachability*; the signature gates
    /// *authority*. `IssueNonce` cannot itself be signed, so the two are not
    /// redundant.
    async fn lock_screen(
        &self,
        signature: String,
        nonce: String,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), Error> {
        let message = encoding::lock_message(&nonce);
        self.authorize(&message, &signature, &nonce)?;

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

    fn sign_activation(sk: &SigningKey, store: &str, nonce: &str) -> String {
        hex::encode(sk.sign(&encoding::activation_message(store, nonce)).to_bytes())
    }

    fn sign_lock(sk: &SigningKey, nonce: &str) -> String {
        hex::encode(sk.sign(&encoding::lock_message(nonce)).to_bytes())
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
        let msg = encoding::activation_message(STORE, &nonce);
        let sig = sign_activation(&sk, STORE, &nonce);

        assert!(t.authorize(&msg, &sig, &nonce).is_ok());
        // Replaying the same signature no longer authorizes: the nonce is burned.
        assert!(matches!(
            t.authorize(&msg, &sig, &nonce),
            Err(Error::NotAuthorized(_))
        ));
    }

    #[test]
    fn bad_signature_spares_the_nonce() {
        let sk = signing_key();
        let t = Trigger::new(vec![sk.verifying_key()]);
        let nonce = t.nonces.issue().unwrap();
        let msg = encoding::activation_message(STORE, &nonce);

        assert!(matches!(
            t.authorize(&msg, &"00".repeat(64), &nonce),
            Err(Error::NotAuthorized(_))
        ));
        // The rejected signature never reached the burn, so the nonce still lives.
        assert!(t.nonces.burn(&nonce), "pending nonce survives a rejected signature");
    }

    #[test]
    fn lock_signature_authorizes_and_burns() {
        let sk = signing_key();
        let t = Trigger::new(vec![sk.verifying_key()]);
        let nonce = t.nonces.issue().unwrap();
        let msg = encoding::lock_message(&nonce);
        let sig = sign_lock(&sk, &nonce);

        assert!(t.authorize(&msg, &sig, &nonce).is_ok());
        assert!(matches!(
            t.authorize(&msg, &sig, &nonce),
            Err(Error::NotAuthorized(_))
        ));
    }

    /// An activation signature must not authorize a lock on the same nonce, and
    /// the failed attempt must not burn that nonce.
    #[test]
    fn activation_signature_cannot_authorize_a_lock() {
        let sk = signing_key();
        let t = Trigger::new(vec![sk.verifying_key()]);
        let nonce = t.nonces.issue().unwrap();
        let activation_sig = sign_activation(&sk, STORE, &nonce);

        assert!(matches!(
            t.authorize(&encoding::lock_message(&nonce), &activation_sig, &nonce),
            Err(Error::NotAuthorized(_))
        ));
        assert!(t.nonces.burn(&nonce), "cross-context rejection spares the nonce");
    }
}
