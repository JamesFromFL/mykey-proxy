// elevated_daemon_client.rs — Async D-Bus client for MyKey elevated auth.
//
// This client is intentionally narrow so the dedicated elevated-password
// helper only compiles the daemon methods it actually needs.

use log::{debug, info};
use zbus::{CacheProperties, Connection};

#[zbus::proxy(
    interface = "com.mykey.Daemon",
    default_service = "com.mykey.Daemon",
    default_path = "/com/mykey/Daemon"
)]
trait DaemonIface {
    async fn connect(&self, pid: u32) -> zbus::Result<Vec<u8>>;
    async fn elevated_auth_status(&self, pid: u32, target_uid: u32) -> zbus::Result<(u64, u32)>;
    async fn record_elevated_auth_failure(
        &self,
        pid: u32,
        target_uid: u32,
    ) -> zbus::Result<(u64, u32)>;
    async fn grant_elevated_auth(
        &self,
        pid: u32,
        target_uid: u32,
        purpose: String,
    ) -> zbus::Result<()>;
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
pub struct ElevatedAuthStatus {
    pub retry_after_secs: u64,
    pub failed_attempts: u32,
}

impl DaemonClient {
    pub async fn connect() -> Result<Self, String> {
        let pid = std::process::id();
        info!("[mykey-auth] Connecting to com.mykey.Daemon (pid={pid})");

        let conn = Connection::system()
            .await
            .map_err(|e| format!("D-Bus system connection failed: {e}"))?;

        make_proxy(&conn)
            .await?
            .connect(pid)
            .await
            .map_err(|e| format!("D-Bus Connect failed: {e}"))?;

        Ok(Self { conn, pid })
    }

    pub async fn elevated_auth_status(
        &self,
        target_uid: u32,
    ) -> Result<ElevatedAuthStatus, String> {
        debug!("[mykey-auth] ElevatedAuthStatus (target_uid={target_uid})");
        let (retry_after_secs, failed_attempts) = make_proxy(&self.conn)
            .await?
            .elevated_auth_status(self.pid, target_uid)
            .await
            .map_err(|e| format!("D-Bus ElevatedAuthStatus failed: {e}"))?;
        Ok(ElevatedAuthStatus {
            retry_after_secs,
            failed_attempts,
        })
    }

    pub async fn record_elevated_auth_failure(
        &self,
        target_uid: u32,
    ) -> Result<ElevatedAuthStatus, String> {
        debug!("[mykey-auth] RecordElevatedAuthFailure (target_uid={target_uid})");
        let (retry_after_secs, failed_attempts) = make_proxy(&self.conn)
            .await?
            .record_elevated_auth_failure(self.pid, target_uid)
            .await
            .map_err(|e| format!("D-Bus RecordElevatedAuthFailure failed: {e}"))?;
        Ok(ElevatedAuthStatus {
            retry_after_secs,
            failed_attempts,
        })
    }

    pub async fn grant_elevated_auth(&self, target_uid: u32, purpose: &str) -> Result<(), String> {
        debug!("[mykey-auth] GrantElevatedAuth (target_uid={target_uid}, purpose={purpose})");
        make_proxy(&self.conn)
            .await?
            .grant_elevated_auth(self.pid, target_uid, purpose.to_string())
            .await
            .map_err(|e| format!("D-Bus GrantElevatedAuth failed: {e}"))
    }

    pub async fn disconnect(self) {
        if let Ok(proxy) = make_proxy(&self.conn).await {
            let _ = proxy.disconnect(self.pid).await;
        }
    }
}
