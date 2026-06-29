mod activate;
mod authz;
mod error;
mod lock;
mod names;
mod trigger;

use zbus::connection;

use names::{BUS_NAME, OBJECT_PATH};
use trigger::{Mode, Trigger};

fn mode_from_env() -> Mode {
    match std::env::var("FRACTAL_TRIGGER_MODE").as_deref() {
        Ok("deployed") => Mode::Deployed,
        _ => Mode::Personal,
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let _conn = connection::Builder::system()?
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, Trigger::new(mode_from_env()))?
        .build()
        .await?;

    std::future::pending::<()>().await;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    async_io::block_on(run())
}
