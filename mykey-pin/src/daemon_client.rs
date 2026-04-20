// daemon_client.rs — Async D-Bus client for com.mykey.Daemon on the system bus.
//
// Uses the zbus async API (not zbus::blocking) so it is safe to call from
// within tokio async handlers without blocking the runtime or deadlocking.
//
// Every proxy is created with CacheProperties::No.  The default
// CacheProperties::Lazily causes zbus to call block_on internally when
// setting up PropertiesChanged signal subscriptions for the cache, which
// panics if a tokio runtime is already running on the current thread.
// The daemon interface exposes no D-Bus properties, so caching is useless.

use log::{debug, info};
use zbus::{CacheProperties, Connection};

// ---------------------------------------------------------------------------
// D-Bus proxy definition
// ---------------------------------------------------------------------------

/// Generated async proxy for the com.mykey.Daemon interface.
///
/// Method names are automatically mapped to D-Bus PascalCase:
///   connect       → Connect
///   seal_secret   → SealSecret
///   unseal_secret → UnsealSecret
///   disconnect    → Disconnect
#[zbus::proxy(
    interface = "com.mykey.Daemon",
    default_service = "com.mykey.Daemon",
    default_path = "/com/mykey/Daemon"
)]
trait DaemonIface {
    async fn connect(&self, pid: u32) -> zbus::Result<Vec<u8>>;
    async fn confirm_user_presence(&self, pid: u32) -> zbus::Result<bool>;
    async fn pin_status(&self, pid: u32, target_uid: u32) -> zbus::Result<(bool, u64, u32)>;
    async fn pin_enroll(&self, pid: u32, target_uid: u32, pin: Vec<u8>) -> zbus::Result<()>;
    async fn pin_verify(&self, pid: u32, target_uid: u32, pin: Vec<u8>) -> zbus::Result<bool>;
    async fn pin_change(
        &self,
        pid: u32,
        target_uid: u32,
        old_pin: Vec<u8>,
        new_pin: Vec<u8>,
    ) -> zbus::Result<bool>;
    async fn pin_reset(&self, pid: u32, target_uid: u32) -> zbus::Result<()>;
    async fn disconnect(&self, pid: u32) -> zbus::Result<()>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a DaemonIfaceProxy with property caching disabled.
///
/// Using `DaemonIfaceProxy::new()` would default to `CacheProperties::Lazily`,
/// which causes an internal `block_on` call and panics inside a running tokio
/// runtime.  The builder lets us opt out of caching entirely.
async fn make_proxy(conn: &Connection) -> Result<DaemonIfaceProxy<'_>, String> {
    DaemonIfaceProxy::builder(conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .map_err(|e| format!("D-Bus proxy creation failed: {e}"))
}

// ---------------------------------------------------------------------------
// DaemonClient
// ---------------------------------------------------------------------------

/// Client connected to com.mykey.Daemon on the system bus.
pub struct DaemonClient {
    conn: Connection,
    pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinStatus {
    pub is_set: bool,
    pub cooldown_remaining_secs: u64,
    pub failed_sessions: u32,
}

impl DaemonClient {
    /// Connect to the system bus and call Connect(pid) to establish a session.
    pub async fn connect() -> Result<Self, String> {
        let pid = std::process::id();
        info!("[daemon_client] Connecting to com.mykey.Daemon (pid={pid})");

        let conn = Connection::system()
            .await
            .map_err(|e| format!("D-Bus system connection failed: {e}"))?;

        make_proxy(&conn)
            .await?
            .connect(pid)
            .await
            .map_err(|e| format!("D-Bus Connect failed: {e}"))?;

        info!("[daemon_client] Session established with mykey-daemon");
        Ok(DaemonClient { conn, pid })
    }

    /// Return daemon-owned PIN state for `target_uid`.
    pub async fn pin_status(&self, target_uid: u32) -> Result<PinStatus, String> {
        debug!("[daemon_client] PinStatus (target_uid={target_uid})");
        let (is_set, cooldown_remaining_secs, failed_sessions) = make_proxy(&self.conn)
            .await?
            .pin_status(self.pid, target_uid)
            .await
            .map_err(|e| format!("D-Bus PinStatus failed: {e}"))?;
        Ok(PinStatus {
            is_set,
            cooldown_remaining_secs,
            failed_sessions,
        })
    }

    /// Trigger a fresh polkit user-presence check for this frontend.
    pub async fn confirm_user_presence(&self) -> Result<bool, String> {
        debug!("[daemon_client] ConfirmUserPresence");
        make_proxy(&self.conn)
            .await?
            .confirm_user_presence(self.pid)
            .await
            .map_err(|e| format!("D-Bus ConfirmUserPresence failed: {e}"))
    }

    /// Enroll a new PIN for `target_uid` through the daemon.
    pub async fn pin_enroll(&self, target_uid: u32, pin: &[u8]) -> Result<(), String> {
        debug!(
            "[daemon_client] PinEnroll (target_uid={target_uid}, {} bytes)",
            pin.len()
        );
        make_proxy(&self.conn)
            .await?
            .pin_enroll(self.pid, target_uid, pin.to_vec())
            .await
            .map_err(|e| format!("D-Bus PinEnroll failed: {e}"))
    }

    /// Verify a PIN for `target_uid` through the daemon.
    pub async fn pin_verify(&self, target_uid: u32, pin: &[u8]) -> Result<bool, String> {
        debug!(
            "[daemon_client] PinVerify (target_uid={target_uid}, {} bytes)",
            pin.len()
        );
        make_proxy(&self.conn)
            .await?
            .pin_verify(self.pid, target_uid, pin.to_vec())
            .await
            .map_err(|e| format!("D-Bus PinVerify failed: {e}"))
    }

    /// Change the enrolled PIN for `target_uid` through the daemon.
    pub async fn pin_change(
        &self,
        target_uid: u32,
        old_pin: &[u8],
        new_pin: &[u8],
    ) -> Result<bool, String> {
        debug!(
            "[daemon_client] PinChange (target_uid={target_uid}, old={} bytes, new={} bytes)",
            old_pin.len(),
            new_pin.len()
        );
        make_proxy(&self.conn)
            .await?
            .pin_change(self.pid, target_uid, old_pin.to_vec(), new_pin.to_vec())
            .await
            .map_err(|e| format!("D-Bus PinChange failed: {e}"))
    }

    /// Remove PIN state for `target_uid` through the daemon.
    pub async fn pin_reset(&self, target_uid: u32) -> Result<(), String> {
        debug!("[daemon_client] PinReset (target_uid={target_uid})");
        make_proxy(&self.conn)
            .await?
            .pin_reset(self.pid, target_uid)
            .await
            .map_err(|e| format!("D-Bus PinReset failed: {e}"))
    }

    /// Disconnect from the daemon, revoking the session token.
    ///
    /// Best-effort: errors are silently ignored since this is cleanup.
    pub async fn disconnect(self) {
        if let Ok(proxy) = make_proxy(&self.conn).await {
            let _ = proxy.disconnect(self.pid).await;
        }
    }
}
