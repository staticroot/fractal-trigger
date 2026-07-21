//! The trigger is the nonce authority. It hands out random, single-use nonces
//! and holds them in memory only, with a short time-to-live and a small cap.
//!
//! Memory-only is what makes replay defence fall out for free: a nonce is valid
//! only while it sits in the live set, burning it removes it, and a restart
//! clears the set so a replayed old nonce simply is not pending. Restart is
//! fail-safe — the worst case is a lost pending activation that must be
//! re-requested.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long an issued nonce stays usable. Human-paced signing fits comfortably.
const TTL: Duration = Duration::from_secs(300);
/// Bound on outstanding nonces, so nobody can grow the set without limit.
const CAP: usize = 64;

pub struct NonceStore {
    pending: Mutex<HashMap<String, Instant>>,
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Issue a fresh random nonce, or `None` if too many are already outstanding
    /// (bounded memory; the caller surfaces this as a transient error).
    pub fn issue(&self) -> Option<String> {
        let mut pending = self.pending.lock().unwrap();
        prune(&mut pending);
        if pending.len() >= CAP {
            return None;
        }
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).ok()?;
        let nonce = hex::encode(bytes);
        pending.insert(nonce.clone(), Instant::now());
        Some(nonce)
    }

    /// Burn `nonce`: returns `true` exactly once, and only if it is currently
    /// pending and unexpired. Removal *is* the burn, so a second attempt fails.
    pub fn burn(&self, nonce: &str) -> bool {
        let mut pending = self.pending.lock().unwrap();
        prune(&mut pending);
        pending.remove(nonce).is_some()
    }
}

fn prune(pending: &mut HashMap<String, Instant>) {
    let now = Instant::now();
    pending.retain(|_, issued| now.duration_since(*issued) < TTL);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_distinct_nonces() {
        let store = NonceStore::new();
        let a = store.issue().unwrap();
        let b = store.issue().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64); // 32 bytes hex
    }

    #[test]
    fn burns_exactly_once() {
        let store = NonceStore::new();
        let n = store.issue().unwrap();
        assert!(store.burn(&n));
        assert!(!store.burn(&n));
    }

    #[test]
    fn rejects_unknown_nonce() {
        let store = NonceStore::new();
        assert!(!store.burn("never-issued"));
    }

    #[test]
    fn enforces_cap() {
        let store = NonceStore::new();
        for _ in 0..CAP {
            assert!(store.issue().is_some());
        }
        assert!(store.issue().is_none());
    }

    #[test]
    fn prunes_expired() {
        let now = Instant::now();
        let Some(stale) = now.checked_sub(TTL + Duration::from_secs(1)) else {
            return; // monotonic clock too young to subtract; skip
        };
        let mut m = HashMap::new();
        m.insert("old".to_string(), stale);
        m.insert("new".to_string(), now);
        prune(&mut m);
        assert!(!m.contains_key("old"));
        assert!(m.contains_key("new"));
    }
}
