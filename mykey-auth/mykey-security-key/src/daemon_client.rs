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
    async fn local_auth_status(
        &self,
        pid: u32,
        target_uid: u32,
    ) -> zbus::Result<(bool, Vec<String>, Vec<String>, bool, bool, u8)>;
    async fn enable_security_key_auth(&self, pid: u32, target_uid: u32) -> zbus::Result<()>;
    async fn disable_security_key_auth(&self, pid: u32, target_uid: u32) -> zbus::Result<()>;
    async fn seal_secret(&self, pid: u32, data: Vec<u8>) -> zbus::Result<Vec<u8>>;
    async fn unseal_secret(&self, pid: u32, blob: Vec<u8>) -> zbus::Result<Vec<u8>>;
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAuthStatus {
    pub enabled: bool,
    pub auth_chain: Vec<String>,
    pub biometric_backends: Vec<String>,
    pub password_fallback_allowed: bool,
}

impl LocalAuthStatus {
    pub fn has_stage(&self, stage: &str) -> bool {
        self.auth_chain.iter().any(|candidate| candidate == stage)
    }
}

impl DaemonClient {
    pub async fn connect() -> Result<Self, String> {
        let pid = std::process::id();
        info!("[mykey-security-key] Connecting to com.mykey.Daemon (pid={pid})");

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
        debug!("[mykey-security-key] PinStatus (target_uid={target_uid})");
        let (is_set, cooldown_remaining_secs, _failed_sessions) = make_proxy(&self.conn)
            .await?
            .pin_status(self.pid, target_uid)
            .await
            .map_err(|e| format!("D-Bus PinStatus failed: {e}"))?;
        Ok(PinStatus {
            is_set,
            cooldown_remaining_secs,
        })
    }

    pub async fn local_auth_status(&self, target_uid: u32) -> Result<LocalAuthStatus, String> {
        debug!("[mykey-security-key] LocalAuthStatus (target_uid={target_uid})");
        let (
            enabled,
            auth_chain,
            biometric_backends,
            password_fallback_allowed,
            _elevated_password_required,
            _biometric_attempt_limit,
        ) = make_proxy(&self.conn)
            .await?
            .local_auth_status(self.pid, target_uid)
            .await
            .map_err(|e| format!("D-Bus LocalAuthStatus failed: {e}"))?;
        Ok(LocalAuthStatus {
            enabled,
            auth_chain,
            biometric_backends,
            password_fallback_allowed,
        })
    }

    pub async fn enable_security_key_auth(&self, target_uid: u32) -> Result<(), String> {
        debug!("[mykey-security-key] EnableSecurityKeyAuth (target_uid={target_uid})");
        make_proxy(&self.conn)
            .await?
            .enable_security_key_auth(self.pid, target_uid)
            .await
            .map_err(|e| format!("D-Bus EnableSecurityKeyAuth failed: {e}"))
    }

    pub async fn disable_security_key_auth(&self, target_uid: u32) -> Result<(), String> {
        debug!("[mykey-security-key] DisableSecurityKeyAuth (target_uid={target_uid})");
        make_proxy(&self.conn)
            .await?
            .disable_security_key_auth(self.pid, target_uid)
            .await
            .map_err(|e| format!("D-Bus DisableSecurityKeyAuth failed: {e}"))
    }

    pub async fn seal_secret(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        make_proxy(&self.conn)
            .await?
            .seal_secret(self.pid, data.to_vec())
            .await
            .map_err(|e| format!("D-Bus SealSecret failed: {e}"))
    }

    pub async fn unseal_secret(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        make_proxy(&self.conn)
            .await?
            .unseal_secret(self.pid, blob.to_vec())
            .await
            .map_err(|e| format!("D-Bus UnsealSecret failed: {e}"))
    }

    pub async fn disconnect(self) {
        if let Ok(proxy) = make_proxy(&self.conn).await {
            let _ = proxy.disconnect(self.pid).await;
        }
    }
}
