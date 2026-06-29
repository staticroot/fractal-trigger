use std::sync::atomic::{AtomicBool, Ordering};

use zbus::message::Header;
use zbus::object_server::SignalEmitter;
use zbus::{interface, Connection};

use crate::error::Error;
use crate::{activate, authz, lock};

#[derive(Clone, Copy)]
pub enum Mode {
    /// Consumer: authorize via polkit (local presence).
    Standalone,
    /// Enterprise: authorize via offline signature + nonce.
    Enrolled,
}

pub struct Trigger {
    mode: Mode,
    activating: AtomicBool,
}

/// Releases the activation flag on drop, so a failed/panicking switch never
/// leaves the trigger wedged in `Busy`.
struct ActivationGuard<'a>(&'a AtomicBool);

impl Drop for ActivationGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Trigger {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            activating: AtomicBool::new(false),
        }
    }

    fn try_activate(&self) -> Option<ActivationGuard<'_>> {
        self.activating
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Acquire)
            .ok()
            .map(|_| ActivationGuard(&self.activating))
    }

    async fn check(&self, conn: &Connection, hdr: &Header<'_>, action: &str) -> Result<(), Error> {
        match self.mode {
            Mode::Standalone => {
                let caller = hdr.sender().ok_or_else(|| {
                    Error::NotAuthorized("caller has no bus name".to_string())
                })?;
                authz::authorize(conn, caller.as_str(), action).await
            }
            // LockScreen/SwitchToStorePath callers are already gated to the agent
            // by the D-Bus policy; enrolled switches additionally verify the
            // signature in the method body.
            Mode::Enrolled => Ok(()),
        }
    }
}

#[interface(name = "systems.staticroot.Trigger")]
impl Trigger {
    async fn switch_to_store_path(
        &self,
        store_path: String,
        signature: String,
        nonce: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), Error> {
        let _guard = self
            .try_activate()
            .ok_or_else(|| Error::Busy("an activation is already in progress".to_string()))?;

        self.check(conn, &hdr, "systems.staticroot.trigger.switch")
            .await?;
        if let Mode::Enrolled = self.mode {
            authz::verify(&signature, &nonce)?;
        }

        let conn = conn.clone();
        blocking::unblock(move || activate::run(&store_path, &conn)).await
    }

    async fn lock_screen(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), Error> {
        self.check(conn, &hdr, "systems.staticroot.trigger.lock")
            .await?;
        lock::lock_sessions(conn).await
    }

    /// Streamed line-by-line `switch-to-configuration` output. The agent owns
    /// all user-facing presentation.
    #[zbus(signal)]
    async fn progress(emitter: &SignalEmitter<'_>, line: &str) -> zbus::Result<()>;
}
