// cli_daemon_client.rs — Async D-Bus client for the interactive mykey-pin CLI.

use log::{debug, info};
use zbus::{CacheProperties, Connection};

#[zbus::proxy(
    interface = "com.mykey.Daemon",
    default_service = "com.mykey.Daemon",
    default_path = "/com/mykey/Daemon"
)]
trait DaemonIface {
    async fn connect(&self, pid: u32) -> zbus::Result<Vec<u8>>;
    async fn pin_status(&self, pid: u32, target_uid: u32) -> zbus::Result<(bool, u64, u32)>;
    async fn pin_enroll(&self, pid: u32, target_uid: u32, pin: Vec<u8>) -> zbus::Result<()>;
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

async fn make_proxy(conn: &Connection) -> Result<DaemonIfaceProxy<'_>, String> {
    DaemonIfaceProxy::builder(conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .map_err(|e| format!("D-Bus proxy creation failed: {e}"))
}

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

    pub async fn pin_reset(&self, target_uid: u32) -> Result<(), String> {
        debug!("[daemon_client] PinReset (target_uid={target_uid})");
        make_proxy(&self.conn)
            .await?
            .pin_reset(self.pid, target_uid)
            .await
            .map_err(|e| format!("D-Bus PinReset failed: {e}"))
    }

    pub async fn disconnect(self) {
        if let Ok(proxy) = make_proxy(&self.conn).await {
            let _ = proxy.disconnect(self.pid).await;
        }
    }
}
