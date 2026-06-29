use zbus::Connection;

use crate::error::Error;

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait Logind {
    fn lock_sessions(&self) -> zbus::Result<()>;
}

/// Ask logind to lock every active session (machine-wide screen lock).
pub async fn lock_sessions(conn: &Connection) -> Result<(), Error> {
    let logind = LogindProxy::new(conn)
        .await
        .map_err(|e| Error::LockFailed(e.to_string()))?;
    logind
        .lock_sessions()
        .await
        .map_err(|e| Error::LockFailed(e.to_string()))
}
