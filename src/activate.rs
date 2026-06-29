use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zbus::Connection;

use crate::error::Error;

const STORE_PREFIX: &str = "/nix/store/";
const SYSTEM_PROFILE: &str = "/nix/var/nix/profiles/system";
const OBJECT_PATH: &str = "/systems/staticroot/Trigger";
const INTERFACE: &str = "systems.staticroot.Trigger";

/// Reject anything that isn't a plausible top-level store path before touching
/// the filesystem. Kept pure so it is unit-testable off-Linux.
fn check_shape(store_path: &str) -> Result<(), Error> {
    let bad = |why: &str| Err(Error::InvalidStorePath(format!("{why}: {store_path}")));

    if !store_path.starts_with(STORE_PREFIX) {
        return bad("not under /nix/store");
    }
    let name = &store_path[STORE_PREFIX.len()..];
    if name.is_empty() || name.contains('/') {
        return bad("not a top-level store path");
    }
    if store_path.split('/').any(|c| c == "..") {
        return bad("path traversal");
    }
    Ok(())
}

/// Full validation: well-formed shape, exists, and carries an activation script.
fn validate(store_path: &str) -> Result<PathBuf, Error> {
    check_shape(store_path)?;
    let path = Path::new(store_path);
    let stc = path.join("bin/switch-to-configuration");
    if !stc.is_file() {
        return Err(Error::InvalidStorePath(format!(
            "no activation script at {}",
            stc.display()
        )));
    }
    Ok(path.to_path_buf())
}

fn emit_progress(conn: &Connection, line: &str) {
    let _ = async_io::block_on(conn.emit_signal(
        None::<&str>,
        OBJECT_PATH,
        INTERFACE,
        "Progress",
        &(line,),
    ));
}

/// Run a command, streaming each stdout line back as a `Progress` signal and
/// failing with stderr on a non-zero exit.
fn run_streaming(mut cmd: Command, conn: &Connection) -> Result<(), Error> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::ActivationFailed(e.to_string()))?;

    if let Some(out) = child.stdout.take() {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            emit_progress(conn, &line);
        }
    }

    let status = child
        .wait_with_output()
        .map_err(|e| Error::ActivationFailed(e.to_string()))?;
    if !status.status.success() {
        let stderr = String::from_utf8_lossy(&status.stderr);
        return Err(Error::ActivationFailed(stderr.trim().to_string()));
    }
    Ok(())
}

/// Make `store_path` the current system: register it as a new generation of the
/// system profile, then activate it. Blocking; call off the bus executor thread.
pub fn run(store_path: &str, conn: &Connection) -> Result<(), Error> {
    let path = validate(store_path)?;

    let mut set = Command::new("nix-env");
    set.args(["--profile", SYSTEM_PROFILE, "--set"]).arg(&path);
    run_streaming(set, conn)?;

    let mut switch = Command::new(path.join("bin/switch-to-configuration"));
    switch.arg("switch");
    run_streaming(switch, conn)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_shape;

    #[test]
    fn rejects_relative() {
        assert!(check_shape("nix/store/abc-foo").is_err());
        assert!(check_shape("abc-foo").is_err());
    }

    #[test]
    fn rejects_outside_store() {
        assert!(check_shape("/etc/passwd").is_err());
        assert!(check_shape("/nix/store").is_err());
        assert!(check_shape("/nix/store/").is_err());
    }

    #[test]
    fn rejects_traversal() {
        assert!(check_shape("/nix/store/../etc").is_err());
        assert!(check_shape("/nix/store/abc/../../etc").is_err());
    }

    #[test]
    fn rejects_subpath() {
        assert!(check_shape("/nix/store/abc-foo/bin/sh").is_err());
    }

    #[test]
    fn accepts_top_level() {
        assert!(check_shape("/nix/store/0n9k1d2abc-nixos-system-host-25.11").is_ok());
    }
}
