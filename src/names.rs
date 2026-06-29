//! Canonical D-Bus names: one source of truth for the well-known name, object
//! path, interface, signal, and polkit action ids.

pub const INTERFACE: &str = "systems.staticroot.Trigger";
pub const BUS_NAME: &str = INTERFACE;
pub const OBJECT_PATH: &str = "/systems/staticroot/Trigger";
pub const PROGRESS_SIGNAL: &str = "Progress";

pub const ACTION_SWITCH: &str = "systems.staticroot.trigger.switch";
pub const ACTION_LOCK: &str = "systems.staticroot.trigger.lock";
