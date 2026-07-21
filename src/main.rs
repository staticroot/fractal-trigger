mod activate;
mod authz;
mod encoding;
mod error;
mod keys;
mod lock;
mod names;
mod nonce;
mod trigger;

use std::path::PathBuf;

use zbus::connection;

use names::{BUS_NAME, OBJECT_PATH};
use trigger::Trigger;

/// Root-owned, root-only-writable file holding the trusted public keys. Its
/// provisioning and permissions are the real trust boundary.
fn trusted_keys_path() -> PathBuf {
    std::env::var_os("FRACTAL_TRIGGER_TRUSTED_KEYS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/fractal-trigger/trusted-keys"))
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let keys = keys::load(&trusted_keys_path())?;

    let _conn = connection::Builder::system()?
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, Trigger::new(keys))?
        .build()
        .await?;

    std::future::pending::<()>().await;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    async_io::block_on(run())
}
