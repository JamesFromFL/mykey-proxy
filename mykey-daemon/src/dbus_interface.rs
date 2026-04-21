// dbus_interface.rs — zbus D-Bus interface for the MyKey Proxy daemon.
//
// Interface name:  com.mykey.Daemon
// Object path:     /com/mykey/Daemon
//
// Methods:
//   Connect(pid)                      → session token bytes (Vec<u8>)
//   Register(pid, encrypted_request)  → encrypted response (JSON)
//   Authenticate(pid, encrypted_request) → encrypted response (JSON)
//   SealSecret(pid, data)             → sealed blob bytes (Vec<u8>)
//   UnsealSecret(pid, blob)           → plaintext bytes (Vec<u8>)
//   Disconnect(pid)                   → ()
//
// Callers supply their own PID, but the daemon cross-checks it against the
// D-Bus sender's Unix credentials before accepting the request.

use std::sync::Arc;
use log::{debug, info, warn};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zbus::{message::Header, Connection};

use crate::authentication;
use crate::crypto;
use crate::local_auth_policy::{LocalAuthMethod, LocalAuthPolicyStore};
use crate::pam;
use crate::pin_store::PinStore;
use crate::protocol::{CreateRequest, GetRequest};
use crate::registration;
use crate::replay::AsyncReplayCache;
use crate::session::SessionStore;
use crate::tpm;
use crate::validator;

// ---------------------------------------------------------------------------
// Shared daemon state
// ---------------------------------------------------------------------------

/// State shared by the D-Bus interface across all D-Bus method calls.
pub struct DaemonState {
    pub sessions:     SessionStore,
    pub replay_cache: AsyncReplayCache,
    pub pin_store:    PinStore,
    pub local_auth_policy_store: LocalAuthPolicyStore,
}

impl DaemonState {
    pub fn new() -> Self {
        DaemonState {
            sessions:     SessionStore::new(),
            replay_cache: AsyncReplayCache::new(),
            pin_store:    PinStore::default(),
            local_auth_policy_store: LocalAuthPolicyStore::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// D-Bus interface struct
// ---------------------------------------------------------------------------

/// Implements the com.mykey.Daemon D-Bus interface.
///
/// Holds an `Arc<DaemonState>` so all method calls share the same session store
/// and replay cache.  `Arc` is used (not `Mutex<DaemonState>`) because the
/// individual fields already carry their own async locks.
pub struct DaemonInterface {
    state: Arc<DaemonState>,
}

#[derive(Debug, Clone)]
struct CallerIdentity {
    uid: u32,
    mykey_program: Option<&'static str>,
}

impl DaemonInterface {
    pub fn new(state: Arc<DaemonState>) -> Self {
        DaemonInterface { state }
    }
}

// ---------------------------------------------------------------------------
// zbus interface implementation
// ---------------------------------------------------------------------------

#[zbus::interface(name = "com.mykey.Daemon")]
impl DaemonInterface {
    // ── Connect ─────────────────────────────────────────────────────────────
    /// Called by a trusted MyKey or browser-side process on startup.
    ///
    /// Cross-checks the claimed `pid` against the D-Bus sender's Unix
    /// credentials, validates that the process is a recognised browser or
    /// trusted MyKey binary, then issues a fresh session token and returns the
    /// raw 32-byte token over the kernel-mediated D-Bus system bus.
    async fn connect(
        &self,
        pid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<u8>, zbus::fdo::Error> {
        info!("[dbus] Connect called from pid={pid}");

        self.authorize_call(conn, &header, pid).await?;

        let token_bytes = self.state.sessions.issue_token(pid).await;

        // Reset the replay cache so the new session's sequence counter (which
        // starts at 1) does not collide with numbers seen in a previous session.
        self.state.replay_cache.clear_for_session().await;

        info!("[dbus] Connect successful for pid={pid}");
        Ok(token_bytes.to_vec())
    }

    // ── Register ─────────────────────────────────────────────────────────────
    /// Handle a WebAuthn registration (create) request from the native host.
    ///
    /// The request is AES-GCM encrypted with the session token.  The response
    /// is returned encrypted with the same token.
    async fn register(
        &self,
        pid: u32,
        encrypted_request: Vec<u8>,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<u8>, zbus::fdo::Error> {
        debug!("[dbus] Register called from pid={pid}");

        self.authorize_call(conn, &header, pid).await?;

        // Decrypt request using this pid's session token
        let plaintext = self
            .decrypt_with_session(pid, &encrypted_request)
            .await
            .map_err(|e| zbus::fdo::Error::AccessDenied(e))?;

        // Parse the request envelope: { sequence, timestamp, hmac, payload }
        let envelope: RequestEnvelope = serde_json::from_slice(&plaintext)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("Bad request JSON: {e}")))?;

        // Replay protection
        self.state
            .replay_cache
            .check_and_record(envelope.sequence, envelope.timestamp_secs)
            .await
            .map_err(|e| zbus::fdo::Error::AccessDenied(format!("Replay check: {e}")))?;

        // HMAC verification
        let hmac_valid = self
            .verify_hmac_with_session(pid, &envelope.payload, &envelope.hmac)
            .await;
        if !hmac_valid {
            warn!("[dbus] Register HMAC verification failed for pid={pid}");
            return Err(zbus::fdo::Error::AccessDenied(
                "HMAC verification failed".to_string(),
            ));
        }

        // Deserialise and dispatch to the registration handler
        let create_req: CreateRequest = serde_json::from_slice(&envelope.payload)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("Bad CreateRequest: {e}")))?;

        info!("[dbus] Register: dispatching registration for pid={pid}");
        let create_resp = registration::handle_create(create_req, pid)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("Registration failed: {e}")))?;

        let response_bytes = serde_json::to_vec(&create_resp)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Serialise CreateResponse: {e}")))?;

        // Encrypt response
        self.encrypt_with_session(pid, &response_bytes)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e))
    }

    // ── Authenticate ─────────────────────────────────────────────────────────
    /// Handle a WebAuthn authentication (get) request from the native host.
    async fn authenticate(
        &self,
        pid: u32,
        encrypted_request: Vec<u8>,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<u8>, zbus::fdo::Error> {
        debug!("[dbus] Authenticate called from pid={pid}");

        self.authorize_call(conn, &header, pid).await?;

        let plaintext = self
            .decrypt_with_session(pid, &encrypted_request)
            .await
            .map_err(|e| zbus::fdo::Error::AccessDenied(e))?;

        let envelope: RequestEnvelope = serde_json::from_slice(&plaintext)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("Bad request JSON: {e}")))?;

        self.state
            .replay_cache
            .check_and_record(envelope.sequence, envelope.timestamp_secs)
            .await
            .map_err(|e| zbus::fdo::Error::AccessDenied(format!("Replay check: {e}")))?;

        let hmac_valid = self
            .verify_hmac_with_session(pid, &envelope.payload, &envelope.hmac)
            .await;
        if !hmac_valid {
            warn!("[dbus] Authenticate HMAC verification failed for pid={pid}");
            return Err(zbus::fdo::Error::AccessDenied(
                "HMAC verification failed".to_string(),
            ));
        }

        // Deserialise and dispatch to the authentication handler
        let get_req: GetRequest = serde_json::from_slice(&envelope.payload)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("Bad GetRequest: {e}")))?;

        info!("[dbus] Authenticate: dispatching authentication for pid={pid}");
        let get_resp = authentication::handle_get(get_req, pid)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("Authentication failed: {e}")))?;

        let response_bytes = serde_json::to_vec(&get_resp)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Serialise GetResponse: {e}")))?;

        self.encrypt_with_session(pid, &response_bytes)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e))
    }

    // ── SealSecret ───────────────────────────────────────────────────────────
    /// Seal arbitrary bytes via the TPM2 (or software fallback) and return the
    /// sealed blob.
    ///
    /// The caller must have an active session established via Connect.  The
    /// daemon logs byte counts only — never the data content.
    async fn seal_secret(
        &self,
        pid: u32,
        data: Vec<u8>,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<u8>, zbus::fdo::Error> {
        info!("[dbus] SealSecret called from pid={pid} ({} bytes)", data.len());

        self.authorize_call(conn, &header, pid).await?;

        if self.state.sessions.with_token(pid, |_| ()).await.is_none() {
            warn!("[dbus] SealSecret rejected: no session for pid={pid}");
            return Err(zbus::fdo::Error::AccessDenied(
                format!("No session for pid={pid} — call Connect first"),
            ));
        }

        let blob = tpm::seal_blob(&data)
            .map_err(|e| zbus::fdo::Error::Failed(format!("SealSecret failed: {e}")))?;

        info!("[dbus] SealSecret complete for pid={pid} (blob {} bytes)", blob.len());
        Ok(blob)
    }

    // ── UnsealSecret ─────────────────────────────────────────────────────────
    /// Unseal a blob previously produced by SealSecret.
    ///
    /// The caller must have an active session.  Fails if PCR values have
    /// changed since sealing.  The daemon logs byte counts only — never the
    /// plaintext content.
    async fn unseal_secret(
        &self,
        pid: u32,
        blob: Vec<u8>,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Vec<u8>, zbus::fdo::Error> {
        info!("[dbus] UnsealSecret called from pid={pid} ({} bytes)", blob.len());

        self.authorize_call(conn, &header, pid).await?;

        if self.state.sessions.with_token(pid, |_| ()).await.is_none() {
            warn!("[dbus] UnsealSecret rejected: no session for pid={pid}");
            return Err(zbus::fdo::Error::AccessDenied(
                format!("No session for pid={pid} — call Connect first"),
            ));
        }

        let plaintext = tpm::unseal_blob(&blob)
            .map_err(|e| zbus::fdo::Error::Failed(format!("UnsealSecret failed: {e}")))?;

        info!("[dbus] UnsealSecret complete for pid={pid} ({} bytes)", plaintext.len());
        Ok(plaintext.to_vec())
    }

    // ── Disconnect ────────────────────────────────────────────────────────────
    /// Revoke the session token for `pid` and clean up state.
    async fn disconnect(
        &self,
        pid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), zbus::fdo::Error> {
        info!("[dbus] Disconnect called from pid={pid}");

        self.authorize_call(conn, &header, pid).await?;

        self.state.sessions.revoke_token(pid).await;
        Ok(())
    }

    // ── PinStatus ────────────────────────────────────────────────────────────
    /// Return basic PIN state for `target_uid`.
    ///
    /// Tuple layout:
    ///   `(pin_is_set, cooldown_remaining_secs, failed_sessions)`
    async fn pin_status(
        &self,
        pid: u32,
        target_uid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(bool, u64, u32), zbus::fdo::Error> {
        let _identity = self
            .authorize_pin_call(conn, &header, pid, target_uid)
            .await?;
        self.pin_status_for_uid(target_uid)
    }

    // ── LocalAuthStatus ──────────────────────────────────────────────────────
    /// Return local-auth policy state for `target_uid`.
    ///
    /// Tuple layout:
    ///   `(enabled, primary_method, pin_fallback_enabled, biometric_backend)`
    async fn local_auth_status(
        &self,
        pid: u32,
        target_uid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(bool, String, bool, String), zbus::fdo::Error> {
        let _identity = self
            .authorize_pin_call(conn, &header, pid, target_uid)
            .await?;
        self.local_auth_status_for_uid(target_uid)
    }

    // ── PinEnroll ────────────────────────────────────────────────────────────
    /// Enroll a new PIN for `target_uid`.
    ///
    /// This low-level daemon method does not implement final UX policy. It is
    /// intended to be called by trusted MyKey frontends after they have
    /// completed any higher-level enrollment checks.
    async fn pin_enroll(
        &self,
        pid: u32,
        target_uid: u32,
        pin: Vec<u8>,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), zbus::fdo::Error> {
        let _identity = self
            .authorize_pin_call(conn, &header, pid, target_uid)
            .await?;
        self.pin_enroll_for_uid(target_uid, pin)
    }

    // ── PinVerify ────────────────────────────────────────────────────────────
    /// Verify the PIN for `target_uid`.
    ///
    /// Returns `true` on success, `false` on mismatch or active PIN lockout.
    async fn pin_verify(
        &self,
        pid: u32,
        target_uid: u32,
        pin: Vec<u8>,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<bool, zbus::fdo::Error> {
        let _identity = self
            .authorize_pin_call(conn, &header, pid, target_uid)
            .await?;
        self.pin_verify_for_uid(target_uid, pin)
    }

    // ── PinChange ────────────────────────────────────────────────────────────
    /// Change the PIN for `target_uid`.
    ///
    /// Returns `true` if the current PIN verified and the new PIN was written.
    /// Returns `false` on mismatch or active PIN lockout.
    async fn pin_change(
        &self,
        pid: u32,
        target_uid: u32,
        old_pin: Vec<u8>,
        new_pin: Vec<u8>,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<bool, zbus::fdo::Error> {
        let _identity = self
            .authorize_pin_call(conn, &header, pid, target_uid)
            .await?;
        self.pin_change_for_uid(target_uid, old_pin, new_pin)
    }

    // ── PinReset ─────────────────────────────────────────────────────────────
    /// Remove all stored PIN state for `target_uid`.
    async fn pin_reset(
        &self,
        pid: u32,
        target_uid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), zbus::fdo::Error> {
        let _identity = self
            .authorize_pin_call(conn, &header, pid, target_uid)
            .await?;
        self.pin_reset_for_uid(target_uid)
    }

    // ── ConfirmUserPresence ────────────────────────────────────────────────
    /// Trigger a fresh polkit user-presence check for the calling process.
    ///
    /// Intended for management actions such as first-time PIN enrollment and
    /// PIN reset, where the current PIN is not available as a gate.
    async fn confirm_user_presence(
        &self,
        pid: u32,
        #[zbus(connection)] conn: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<bool, zbus::fdo::Error> {
        let _identity = self
            .authorize_pin_management_call(conn, &header, pid)
            .await?;
        pam::verify_user_presence(pid)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("User presence verification failed: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers (not exposed on D-Bus)
// ---------------------------------------------------------------------------

impl DaemonInterface {
    async fn authorize_call(
        &self,
        conn: &Connection,
        header: &Header<'_>,
        pid: u32,
    ) -> Result<CallerIdentity, zbus::fdo::Error> {
        let sender = header.sender().ok_or_else(|| {
            zbus::fdo::Error::AccessDenied("D-Bus message is missing sender identity".to_string())
        })?;

        let dbus = zbus::fdo::DBusProxy::new(conn)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("Cannot create DBus proxy: {e}")))?;
        let credentials = dbus
            .get_connection_credentials(sender.to_owned().into())
            .await
            .map_err(|e| {
                zbus::fdo::Error::AccessDenied(format!(
                    "Cannot resolve D-Bus credentials for sender {sender}: {e}"
                ))
            })?;

        let actual_pid = credentials.process_id().ok_or_else(|| {
            zbus::fdo::Error::AccessDenied(format!(
                "D-Bus did not provide a process ID for sender {sender}"
            ))
        })?;
        if actual_pid != pid {
            warn!(
                "[dbus] Caller PID mismatch: sender={sender} supplied pid={pid} actual pid={actual_pid}"
            );
            return Err(zbus::fdo::Error::AccessDenied(format!(
                "Caller PID mismatch: sender {sender} is process {actual_pid}, not {pid}"
            )));
        }

        let uid = credentials.unix_user_id().ok_or_else(|| {
            zbus::fdo::Error::AccessDenied(format!(
                "D-Bus did not provide a Unix user ID for sender {sender}"
            ))
        })?;

        let browser_ok = validator::verify_caller_process(pid);
        let mykey_program = if !browser_ok {
            validator::trusted_mykey_program(pid)
        } else {
            None
        };
        if !browser_ok && mykey_program.is_none() {
            warn!("[dbus] Authorize rejected: pid={pid} failed caller verification");
            return Err(zbus::fdo::Error::AccessDenied(format!(
                "pid={pid} is not a recognised browser or MyKey process"
            )));
        }

        Ok(CallerIdentity {
            uid,
            mykey_program,
        })
    }

    async fn ensure_session(&self, pid: u32) -> Result<(), zbus::fdo::Error> {
        if self.state.sessions.with_token(pid, |_| ()).await.is_none() {
            warn!("[dbus] Request rejected: no session for pid={pid}");
            return Err(zbus::fdo::Error::AccessDenied(format!(
                "No session for pid={pid} — call Connect first"
            )));
        }
        Ok(())
    }

    async fn authorize_pin_call(
        &self,
        conn: &Connection,
        header: &Header<'_>,
        pid: u32,
        target_uid: u32,
    ) -> Result<CallerIdentity, zbus::fdo::Error> {
        let identity = self.authorize_call(conn, header, pid).await?;
        self.ensure_session(pid).await?;
        self.ensure_pin_api_caller(&identity)?;
        self.ensure_target_uid_access(&identity, target_uid)?;
        Ok(identity)
    }

    async fn authorize_pin_management_call(
        &self,
        conn: &Connection,
        header: &Header<'_>,
        pid: u32,
    ) -> Result<CallerIdentity, zbus::fdo::Error> {
        let identity = self.authorize_call(conn, header, pid).await?;
        self.ensure_session(pid).await?;
        self.ensure_pin_management_caller(&identity)?;
        Ok(identity)
    }

    fn ensure_pin_api_caller(&self, identity: &CallerIdentity) -> Result<(), zbus::fdo::Error> {
        match identity.mykey_program {
            Some("mykey-pin")
            | Some("mykey-pin-auth")
            | Some("mykey-manager")
            | Some("mykey-auth") => Ok(()),
            Some(other) => Err(zbus::fdo::Error::AccessDenied(format!(
                "PIN APIs are not available to {other}"
            ))),
            None => Err(zbus::fdo::Error::AccessDenied(
                "PIN APIs are only available to trusted MyKey frontends".to_string(),
            )),
        }
    }

    fn ensure_pin_management_caller(
        &self,
        identity: &CallerIdentity,
    ) -> Result<(), zbus::fdo::Error> {
        match identity.mykey_program {
            Some("mykey-pin") | Some("mykey-manager") => Ok(()),
            Some(other) => Err(zbus::fdo::Error::AccessDenied(format!(
                "User-presence confirmation is not available to {other}"
            ))),
            None => Err(zbus::fdo::Error::AccessDenied(
                "User-presence confirmation is only available to trusted MyKey frontends"
                    .to_string(),
            )),
        }
    }

    fn ensure_target_uid_access(
        &self,
        identity: &CallerIdentity,
        target_uid: u32,
    ) -> Result<(), zbus::fdo::Error> {
        if identity.uid == 0 || identity.uid == target_uid {
            Ok(())
        } else {
            Err(zbus::fdo::Error::AccessDenied(format!(
                "Caller uid={} may not access PIN state for uid={target_uid}",
                identity.uid
            )))
        }
    }

    fn pin_status_for_uid(&self, uid: u32) -> Result<(bool, u64, u32), zbus::fdo::Error> {
        let is_set = self
            .state
            .pin_store
            .pin_is_set(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN status failed: {e}")))?;
        let attempts = self
            .state
            .pin_store
            .read_attempts(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN attempts read failed: {e}")))?;
        let cooldown_remaining = self
            .state
            .pin_store
            .lockout_remaining(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN lockout check failed: {e}")))?
            .unwrap_or(0);
        Ok((is_set, cooldown_remaining, attempts.failed_sessions))
    }

    fn validate_new_pin(pin: &[u8]) -> Result<(), zbus::fdo::Error> {
        let len = pin.len();
        if len < 4 {
            return Err(zbus::fdo::Error::InvalidArgs(
                "PIN must be at least 4 digits.".to_string(),
            ));
        }
        if len > 12 {
            return Err(zbus::fdo::Error::InvalidArgs(
                "PIN must be no more than 12 digits.".to_string(),
            ));
        }
        if !pin.iter().all(u8::is_ascii_digit) {
            return Err(zbus::fdo::Error::InvalidArgs(
                "PIN must contain digits only.".to_string(),
            ));
        }
        Ok(())
    }

    fn pin_enroll_for_uid(&self, uid: u32, pin: Vec<u8>) -> Result<(), zbus::fdo::Error> {
        if self
            .state
            .pin_store
            .pin_is_set(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN status failed: {e}")))?
        {
            return Err(zbus::fdo::Error::Failed(format!(
                "A MyKey PIN is already set for uid={uid}"
            )));
        }

        Self::validate_new_pin(&pin)?;

        let pin = Zeroizing::new(pin);
        let pin_hash = Zeroizing::new(hash_pin_bytes(pin.as_slice()));
        let sealed = tpm::seal_blob(pin_hash.as_slice())
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN seal failed: {e}")))?;
        self.state
            .pin_store
            .write_pin_blob(uid, &sealed)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN write failed: {e}")))?;
        self.state
            .pin_store
            .record_success(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN attempts reset failed: {e}")))?;
        self.state
            .local_auth_policy_store
            .enable_pin_only(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Local auth policy update failed: {e}")))?;
        Ok(())
    }

    fn pin_verify_for_uid(&self, uid: u32, pin: Vec<u8>) -> Result<bool, zbus::fdo::Error> {
        if self
            .state
            .pin_store
            .lockout_remaining(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN lockout check failed: {e}")))?
            .is_some()
        {
            return Ok(false);
        }

        let sealed = self
            .state
            .pin_store
            .read_pin_blob(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN read failed: {e}")))?
            .ok_or_else(|| zbus::fdo::Error::Failed(format!("No MyKey PIN is set for uid={uid}")))?;
        let stored_hash = tpm::unseal_blob(&sealed)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN unseal failed: {e}")))?;
        let pin = Zeroizing::new(pin);
        let entered_hash = Zeroizing::new(hash_pin_bytes(pin.as_slice()));

        if entered_hash.as_slice() == stored_hash.as_slice() {
            self.state
                .pin_store
                .record_success(uid)
                .map_err(|e| zbus::fdo::Error::Failed(format!("PIN attempts reset failed: {e}")))?;
            Ok(true)
        } else {
            self.state
                .pin_store
                .record_failed_attempt(uid)
                .map_err(|e| zbus::fdo::Error::Failed(format!("PIN attempt write failed: {e}")))?;
            Ok(false)
        }
    }

    fn pin_change_for_uid(
        &self,
        uid: u32,
        old_pin: Vec<u8>,
        new_pin: Vec<u8>,
    ) -> Result<bool, zbus::fdo::Error> {
        if !self
            .state
            .pin_store
            .pin_is_set(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN status failed: {e}")))?
        {
            return Err(zbus::fdo::Error::Failed(format!(
                "No MyKey PIN is set for uid={uid}"
            )));
        }

        if !self.pin_verify_for_uid(uid, old_pin)? {
            return Ok(false);
        }

        Self::validate_new_pin(&new_pin)?;

        let new_pin = Zeroizing::new(new_pin);
        let pin_hash = Zeroizing::new(hash_pin_bytes(new_pin.as_slice()));
        let sealed = tpm::seal_blob(pin_hash.as_slice())
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN seal failed: {e}")))?;
        self.state
            .pin_store
            .write_pin_blob(uid, &sealed)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN write failed: {e}")))?;
        self.state
            .pin_store
            .record_success(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN attempts reset failed: {e}")))?;
        Ok(true)
    }

    fn pin_reset_for_uid(&self, uid: u32) -> Result<(), zbus::fdo::Error> {
        self.state
            .pin_store
            .clear_pin(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("PIN reset failed: {e}")))?;
        self.state
            .local_auth_policy_store
            .on_pin_reset(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Local auth policy update failed: {e}")))?;
        Ok(())
    }

    fn local_auth_status_for_uid(
        &self,
        uid: u32,
    ) -> Result<(bool, String, bool, String), zbus::fdo::Error> {
        let mut policy = self
            .state
            .local_auth_policy_store
            .repair_policy(uid)
            .map_err(|e| zbus::fdo::Error::Failed(format!("Local auth policy read failed: {e}")))?;

        // Backfill existing pin-only deployments that predate daemon-owned
        // local-auth policy. If a PIN exists and no explicit policy has been
        // written yet, treat that as enabled pin-only local auth and persist it.
        if !policy.enabled
            && policy.primary_method == LocalAuthMethod::Pin
            && !policy.pin_fallback_enabled
            && policy.biometric_backend.is_none()
            && self
                .state
                .pin_store
                .pin_is_set(uid)
                .map_err(|e| zbus::fdo::Error::Failed(format!("PIN status failed: {e}")))?
        {
            self.state
                .local_auth_policy_store
                .enable_pin_only(uid)
                .map_err(|e| {
                    zbus::fdo::Error::Failed(format!(
                        "Local auth policy backfill failed: {e}"
                    ))
                })?;
            policy = self
                .state
                .local_auth_policy_store
                .repair_policy(uid)
                .map_err(|e| {
                    zbus::fdo::Error::Failed(format!(
                        "Local auth policy read failed after backfill: {e}"
                    ))
                })?;
        }

        let biometric_backend = policy
            .biometric_backend
            .map(|backend| backend.as_str().to_string())
            .unwrap_or_default();
        Ok((
            policy.enabled,
            policy.primary_method.as_str().to_string(),
            policy.pin_fallback_enabled,
            biometric_backend,
        ))
    }

    /// Decrypt `ciphertext` (JSON-serialised EncryptedPayload) using the
    /// session token for `pid`.
    async fn decrypt_with_session(&self, pid: u32, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let json_str = std::str::from_utf8(ciphertext)
            .map_err(|_| format!("Encrypted request for pid={pid} is not valid UTF-8"))?;

        let envelope: crypto::EncryptedPayload = serde_json::from_str(json_str)
            .map_err(|e| format!("Cannot parse EncryptedPayload for pid={pid}: {e}"))?;

        let result = self
            .state
            .sessions
            .with_token(pid, |token| crypto::decrypt_payload(token, envelope))
            .await;

        match result {
            None => Err(format!("No session for pid={pid} — call Connect first")),
            Some(Ok(plaintext)) => Ok(plaintext.to_vec()),
            Some(Err(e)) => Err(e),
        }
    }

    /// Encrypt `plaintext` using the session token for `pid`.
    async fn encrypt_with_session(&self, pid: u32, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let result = self
            .state
            .sessions
            .with_token(pid, |token| crypto::encrypt_payload(token, plaintext))
            .await;

        match result {
            None => Err(format!("No session for pid={pid}")),
            Some(Ok(envelope)) => serde_json::to_vec(&envelope)
                .map_err(|e| format!("Cannot serialise response envelope: {e}")),
            Some(Err(e)) => Err(e),
        }
    }

    /// Verify the HMAC on `payload` using the session token for `pid`.
    async fn verify_hmac_with_session(&self, pid: u32, payload: &[u8], hmac: &[u8]) -> bool {
        let result = self
            .state
            .sessions
            .with_token(pid, |token| {
                validator::verify_request_hmac(token, payload, hmac)
            })
            .await;
        result.unwrap_or(false)
    }
}

fn hash_pin_bytes(pin: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(pin);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Request envelope (authenticated + replay-protected)
// ---------------------------------------------------------------------------

/// The structure every Register/Authenticate request must use.
#[derive(serde::Deserialize)]
struct RequestEnvelope {
    /// Monotonically increasing counter chosen by the caller.
    sequence: u64,
    /// Unix timestamp (seconds) when the request was created.
    timestamp_secs: u64,
    /// HMAC-SHA256(session_token, payload) — hex-encoded.
    hmac: Vec<u8>,
    /// The actual request payload (JSON bytes).
    payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_auth_policy::LocalAuthPolicyStore;
    use crate::replay::AsyncReplayCache;
    use crate::session::SessionStore;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_root(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    fn test_interface() -> DaemonInterface {
        DaemonInterface::new(Arc::new(DaemonState {
            sessions: SessionStore::new(),
            replay_cache: AsyncReplayCache::new(),
            pin_store: PinStore::new(unique_test_root("mykey-dbus-pin-test")),
            local_auth_policy_store: LocalAuthPolicyStore::new(unique_test_root(
                "mykey-dbus-local-auth-test",
            )),
        }))
    }

    fn identity(uid: u32, mykey_program: Option<&'static str>) -> CallerIdentity {
        CallerIdentity { uid, mykey_program }
    }

    #[test]
    fn pin_apis_only_allow_expected_frontends() {
        let interface = test_interface();

        assert!(interface
            .ensure_pin_api_caller(&identity(1000, Some("mykey-pin")))
            .is_ok());
        assert!(interface
            .ensure_pin_api_caller(&identity(1000, Some("mykey-pin-auth")))
            .is_ok());
        assert!(interface
            .ensure_pin_api_caller(&identity(1000, Some("mykey-manager")))
            .is_ok());
        assert!(interface
            .ensure_pin_api_caller(&identity(1000, Some("mykey-auth")))
            .is_ok());

        assert!(interface
            .ensure_pin_api_caller(&identity(1000, Some("mykey-migrate")))
            .is_err());
        assert!(interface
            .ensure_pin_api_caller(&identity(1000, None))
            .is_err());
    }

    #[test]
    fn pin_uid_access_is_bound_to_caller_uid_or_root() {
        let interface = test_interface();

        assert!(interface
            .ensure_target_uid_access(&identity(1000, Some("mykey-pin")), 1000)
            .is_ok());
        assert!(interface
            .ensure_target_uid_access(&identity(0, Some("mykey-pin-auth")), 1000)
            .is_ok());
        assert!(interface
            .ensure_target_uid_access(&identity(1001, Some("mykey-pin")), 1000)
            .is_err());
    }

    #[test]
    fn user_presence_confirmation_is_limited_to_management_frontends() {
        let interface = test_interface();

        assert!(interface
            .ensure_pin_management_caller(&identity(1000, Some("mykey-pin")))
            .is_ok());
        assert!(interface
            .ensure_pin_management_caller(&identity(1000, Some("mykey-manager")))
            .is_ok());

        assert!(interface
            .ensure_pin_management_caller(&identity(1000, Some("mykey-pin-auth")))
            .is_err());
        assert!(interface
            .ensure_pin_management_caller(&identity(1000, Some("mykey-migrate")))
            .is_err());
        assert!(interface
            .ensure_pin_management_caller(&identity(1000, None))
            .is_err());
    }

    #[test]
    fn pin_policy_accepts_only_numeric_values_in_range() {
        assert!(DaemonInterface::validate_new_pin(b"1234").is_ok());
        assert!(DaemonInterface::validate_new_pin(b"123456789012").is_ok());

        assert!(DaemonInterface::validate_new_pin(b"123").is_err());
        assert!(DaemonInterface::validate_new_pin(b"1234567890123").is_err());
        assert!(DaemonInterface::validate_new_pin(b"12ab").is_err());
        assert!(DaemonInterface::validate_new_pin(b"12 4").is_err());
    }

    #[test]
    fn local_auth_status_backfills_existing_pin_only_state() {
        let interface = test_interface();
        interface
            .state
            .pin_store
            .write_pin_blob(1000, b"dummy-sealed-pin")
            .expect("write dummy pin blob");

        let status = interface
            .local_auth_status_for_uid(1000)
            .expect("read local auth status");

        assert_eq!(status, (true, "pin".to_string(), true, String::new()));
    }

    #[test]
    fn local_auth_status_repairs_invalid_biometric_policy() {
        let interface = test_interface();
        let policy_path = interface
            .state
            .local_auth_policy_store
            .policy_path_for_test(1000);
        std::fs::create_dir_all(policy_path.parent().expect("policy parent"))
            .expect("create policy parent");
        std::fs::write(
            &policy_path,
            r#"{
  "enabled": true,
  "primary_method": "biometric",
  "pin_fallback_enabled": false,
  "biometric_backend": "fprintd"
}"#,
        )
        .expect("write invalid policy");

        let status = interface
            .local_auth_status_for_uid(1000)
            .expect("read local auth status");

        assert_eq!(status, (false, "pin".to_string(), false, String::new()));
    }
}
