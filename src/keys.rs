//! The trusted-keys file is the real root of trust — it matters more than the
//! cryptography. Whoever can write it controls what the trigger accepts, so we
//! require it to be root-owned and not writable by group or other, and refuse to
//! start otherwise. The set of keys is what enables rotation and fixes override
//! posture: a device that trusts only the org key cannot be overridden locally.

use std::io::Error;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ed25519_dalek::VerifyingKey;

fn bad(msg: impl Into<String>) -> Error {
    Error::other(msg.into())
}

/// Load the trusted Ed25519 public keys: one hex-encoded 32-byte key per line,
/// with `#` comments and blank lines ignored. Fails loudly rather than starting
/// with an empty or unsafe trust store.
pub fn load(path: &Path) -> Result<Vec<VerifyingKey>, Error> {
    let meta = std::fs::metadata(path)
        .map_err(|e| bad(format!("cannot stat trusted-keys file {}: {e}", path.display())))?;
    if meta.uid() != 0 {
        return Err(bad(format!(
            "trusted-keys file {} must be owned by root",
            path.display()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(bad(format!(
            "trusted-keys file {} must not be writable by group or other",
            path.display()
        )));
    }

    let text = std::fs::read_to_string(path)
        .map_err(|e| bad(format!("cannot read trusted-keys file {}: {e}", path.display())))?;

    let mut keys = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let bytes = hex::decode(line)
            .map_err(|_| bad(format!("trusted-keys line {}: not valid hex", i + 1)))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| bad(format!("trusted-keys line {}: not a 32-byte key", i + 1)))?;
        let key = VerifyingKey::from_bytes(&arr)
            .map_err(|_| bad(format!("trusted-keys line {}: not a valid Ed25519 key", i + 1)))?;
        keys.push(key);
    }

    if keys.is_empty() {
        return Err(bad(format!(
            "trusted-keys file {} holds no keys; nothing could ever activate",
            path.display()
        )));
    }
    Ok(keys)
}
