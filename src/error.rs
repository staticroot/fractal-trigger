use zbus::DBusError;

#[derive(Debug, DBusError)]
#[zbus(prefix = "systems.staticroot.Trigger.Error")]
pub enum Error {
    #[zbus(error)]
    ZBus(zbus::Error),
    InvalidStorePath(String),
    NotAuthorized(String),
    ActivationFailed(String),
    LockFailed(String),
    Busy(String),
}
