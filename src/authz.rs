use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zbus::zvariant::{Type, Value};
use zbus::Connection;

use crate::error::Error;

#[derive(Serialize, Type)]
struct Subject<'a> {
    kind: &'a str,
    details: HashMap<&'a str, Value<'a>>,
}

#[derive(Deserialize, Type)]
struct AuthResult {
    is_authorized: bool,
    #[allow(dead_code)]
    is_challenge: bool,
    #[allow(dead_code)]
    details: HashMap<String, String>,
}

#[zbus::proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
trait Authority {
    fn check_authorization(
        &self,
        subject: &Subject<'_>,
        action_id: &str,
        details: HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<AuthResult>;
}

/// `personal` mode: ask polkit whether `caller` may perform `action_id`. No
/// interactive flag — the polkit rule grants the agent uid non-interactively;
/// anyone else is refused.
pub async fn authorize(conn: &Connection, caller: &str, action_id: &str) -> Result<(), Error> {
    let authority = AuthorityProxy::new(conn)
        .await
        .map_err(|e| Error::NotAuthorized(e.to_string()))?;

    let mut details = HashMap::new();
    details.insert("name", Value::from(caller));
    let subject = Subject {
        kind: "system-bus-name",
        details,
    };

    let result = authority
        .check_authorization(&subject, action_id, HashMap::new(), 0, "")
        .await
        .map_err(|e| Error::NotAuthorized(e.to_string()))?;

    if result.is_authorized {
        Ok(())
    } else {
        Err(Error::NotAuthorized(format!("polkit denied {action_id}")))
    }
}

/// `deployed` mode seam: verify that `signature` authorizes activating
/// `store_path`, with `nonce` for replay protection. The signed payload must
/// cover `store_path` so a signature can't be replayed against a different one.
/// STUB — always accepts. Real verification lands here.
pub fn verify(_store_path: &str, _signature: &str, _nonce: &str) -> Result<(), Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::verify;

    #[test]
    fn verify_stub_accepts() {
        assert!(verify("", "", "").is_ok());
        assert!(verify("/nix/store/abc-foo", "sig", "nonce").is_ok());
    }
}
