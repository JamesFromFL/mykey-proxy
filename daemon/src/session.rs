// session.rs — Session token issuance, storage, and revocation.
//
// Each connected native host process gets a unique 32-byte CSPRNG token.
// Tokens are kept in a heap-allocated, mlocked buffer so they are never
// swapped to disk.  All token memory is zeroized on drop.

use std::collections::HashMap;
use log::{debug, warn};
use rand::RngCore;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// SessionToken
// ---------------------------------------------------------------------------

/// A 32-byte session token in a heap-allocated, mlocked, zeroizing buffer.
pub struct SessionToken {
    data: Box<Zeroizing<[u8; 32]>>,
}

impl SessionToken {
    fn new() -> Self {
        let mut raw = Box::new(Zeroizing::new([0u8; 32]));
        rand::rngs::OsRng.fill_bytes(raw.as_mut().as_mut());

        // mlock the heap page containing the token so it is never swapped.
        // Safety: we hold a stable heap pointer inside the Box.
        unsafe {
            libc::mlock(
                raw.as_ptr() as *const libc::c_void,
                std::mem::size_of::<[u8; 32]>(),
            );
        }

        SessionToken { data: raw }
    }

    /// Borrow the raw token bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }
}

impl Drop for SessionToken {
    fn drop(&mut self) {
        // Unlock the mlocked page; zeroize happens via Zeroizing<> on drop.
        unsafe {
            libc::munlock(
                self.data.as_ptr() as *const libc::c_void,
                std::mem::size_of::<[u8; 32]>(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// SessionStore
// ---------------------------------------------------------------------------

/// Thread-safe store of live session tokens, keyed by caller PID.
pub struct SessionStore {
    tokens: RwLock<HashMap<u32, SessionToken>>,
}

impl SessionStore {
    pub fn new() -> Self {
        SessionStore {
            tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Generate and store a fresh session token for `pid`.
    /// If a token already exists for this pid it is replaced.
    pub async fn issue_token(&self, pid: u32) -> [u8; 32] {
        let token = SessionToken::new();
        let bytes = *token.as_bytes();
        let mut guard = self.tokens.write().await;
        guard.insert(pid, token);
        debug!("Issued session token for pid={}", pid);
        bytes
    }

    /// Run a closure with a read-only reference to the token bytes for `pid`.
    /// Returns None if no token exists for that pid.
    pub async fn with_token<F, R>(&self, pid: u32, f: F) -> Option<R>
    where
        F: FnOnce(&[u8; 32]) -> R,
    {
        let guard = self.tokens.read().await;
        guard.get(&pid).map(|t| f(t.as_bytes()))
    }

    /// Revoke and zeroize the session token for `pid`.
    pub async fn revoke_token(&self, pid: u32) {
        let mut guard = self.tokens.write().await;
        if guard.remove(&pid).is_some() {
            debug!("Revoked session token for pid={}", pid);
        } else {
            warn!("revoke_token called for unknown pid={}", pid);
        }
    }

    /// Number of active sessions (for diagnostics).
    pub async fn session_count(&self) -> usize {
        self.tokens.read().await.len()
    }
}

// ---------------------------------------------------------------------------
// Bootstrap key (used to encrypt session tokens returned to callers)
// ---------------------------------------------------------------------------

/// Load the 32-byte bootstrap key from /etc/webauthn-proxy/bootstrap.key
/// (hex-encoded).  If the file is missing or invalid, an ephemeral key is
/// generated and the daemon warns loudly.
pub fn load_bootstrap_key() -> Zeroizing<[u8; 32]> {
    const KEY_PATH: &str = "/etc/webauthn-proxy/bootstrap.key";

    let result: Option<Zeroizing<[u8; 32]>> = (|| {
        let raw = std::fs::read(KEY_PATH).ok()?;
        let hex_str = std::str::from_utf8(&raw).ok()?.trim();
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Some(Zeroizing::new(key))
    })();

    match result {
        Some(key) => {
            debug!("Bootstrap key loaded from {}", KEY_PATH);
            key
        }
        None => {
            warn!(
                "⚠ Bootstrap key not found or invalid at {}. \
                 Using an ephemeral key — callers will not be able to decrypt \
                 session tokens across daemon restarts. Run install.sh to set up \
                 a persistent bootstrap key.",
                KEY_PATH
            );
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            Zeroizing::new(key)
        }
    }
}
