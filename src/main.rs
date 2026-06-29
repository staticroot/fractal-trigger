mod activate;
mod authz;
mod error;
mod lock;
mod trigger;

use zbus::connection;

use trigger::{Mode, Trigger};

const BUS_NAME: &str = "systems.staticroot.Trigger";
const OBJECT_PATH: &str = "/systems/staticroot/Trigger";

fn mode_from_env() -> Mode {
    match std::env::var("FRACTAL_TRIGGER_MODE").as_deref() {
        Ok("enrolled") => Mode::Enrolled,
        _ => Mode::Standalone,
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
