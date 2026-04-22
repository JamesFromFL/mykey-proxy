// daemon_client.rs — Async D-Bus client for the unified MyKey auth helper.
//
// This is intentionally small for Phase A of pam_mykey: connect to the daemon,
// query PIN state, verify a PIN, and disconnect.

use log::{debug, info};
use zbus::{CacheProperties, Connection};

#[zbus::proxy(
    interface = "com.mykey.Daemon",
    default_service = "com.mykey.Daemon",
    default_path = "/com/mykey/Daemon"
)]
trait DaemonIface {
    async fn connect(&self, pid: u32) -> zbus::Result<Vec<u8>>;
    async fn confirm_user_presence(&self, pid: u32) -> zbus::Result<bool>;
    async fn local_auth_status(
        &self,
        pid: u32,
        target_uid: u32,
    ) -> zbus::Result<(bool, String, bool, String)>;
    async fn seal_secret(&self, pid: u32, data: Vec<u8>) -> zbus::Result<Vec<u8>>;
    async fn unseal_secret(&self, pid: u32, blob: Vec<u8>) -> zbus::Result<Vec<u8>>;
    async fn enable_biometric_backend(
        &self,
        pid: u32,
        target_uid: u32,
        backend: String,
    ) -> zbus::Result<()>;
    async fn disable_biometric_backend(&self, pid: u32, target_uid: u32) -> zbus::Result<()>;
    async fn pin_status(&self, pid: u32, target_uid: u32) -> zbus::Result<(bool, u64, u32)>;
    async fn pin_verify(&self, pid: u32, target_uid: u32, pin: Vec<u8>) -> zbus::Result<bool>;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAuthStatus {
    pub enabled: bool,
    pub primary_method: String,
    pub pin_fallback_enabled: bool,
    pub biometric_backend: Option<String>,
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

    pub async fn pin_status(&self, target_uid: u32) -> Result<PinStatus, String> {
        debug!("[mykey-auth] PinStatus (target_uid={target_uid})");
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

    pub async fn local_auth_status(&self, target_uid: u32) -> Result<LocalAuthStatus, String> {
        debug!("[mykey-auth] LocalAuthStatus (target_uid={target_uid})");
        let (enabled, primary_method, pin_fallback_enabled, biometric_backend) =
            make_proxy(&self.conn)
                .await?
                .local_auth_status(self.pid, target_uid)
                .await
                .map_err(|e| format!("D-Bus LocalAuthStatus failed: {e}"))?;
        Ok(LocalAuthStatus {
            enabled,
            primary_method,
            pin_fallback_enabled,
            biometric_backend: if biometric_backend.is_empty() {
                None
            } else {
                Some(biometric_backend)
            },
        })
    }

    pub async fn confirm_user_presence(&self) -> Result<bool, String> {
        debug!("[mykey-auth] ConfirmUserPresence");
        make_proxy(&self.conn)
            .await?
            .confirm_user_presence(self.pid)
            .await
            .map_err(|e| format!("D-Bus ConfirmUserPresence failed: {e}"))
    }

    pub async fn seal_secret(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        debug!("[mykey-auth] SealSecret ({} bytes)", data.len());
        make_proxy(&self.conn)
            .await?
            .seal_secret(self.pid, data.to_vec())
            .await
            .map_err(|e| format!("D-Bus SealSecret failed: {e}"))
    }

    pub async fn unseal_secret(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        debug!("[mykey-auth] UnsealSecret ({} bytes)", blob.len());
        make_proxy(&self.conn)
            .await?
            .unseal_secret(self.pid, blob.to_vec())
            .await
            .map_err(|e| format!("D-Bus UnsealSecret failed: {e}"))
    }

    pub async fn enable_biometric_backend(
        &self,
        target_uid: u32,
        backend: &str,
    ) -> Result<(), String> {
        debug!("[mykey-auth] EnableBiometricBackend (target_uid={target_uid}, backend={backend})");
        make_proxy(&self.conn)
            .await?
            .enable_biometric_backend(self.pid, target_uid, backend.to_string())
            .await
            .map_err(|e| format!("D-Bus EnableBiometricBackend failed: {e}"))
    }

    pub async fn disable_biometric_backend(&self, target_uid: u32) -> Result<(), String> {
        debug!("[mykey-auth] DisableBiometricBackend (target_uid={target_uid})");
        make_proxy(&self.conn)
            .await?
            .disable_biometric_backend(self.pid, target_uid)
            .await
            .map_err(|e| format!("D-Bus DisableBiometricBackend failed: {e}"))
    }

    pub async fn pin_verify(&self, target_uid: u32, pin: &[u8]) -> Result<bool, String> {
        debug!(
            "[mykey-auth] PinVerify (target_uid={target_uid}, {} bytes)",
            pin.len()
        );
        make_proxy(&self.conn)
            .await?
            .pin_verify(self.pid, target_uid, pin.to_vec())
            .await
            .map_err(|e| format!("D-Bus PinVerify failed: {e}"))
    }

    pub async fn disconnect(self) {
        if let Ok(proxy) = make_proxy(&self.conn).await {
            let _ = proxy.disconnect(self.pid).await;
        }
    }
}
