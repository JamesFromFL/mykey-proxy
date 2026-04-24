use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::auth_backoff::password_backoff_secs;

const DEFAULT_AUTH_ROOT: &str = "/etc/mykey/auth";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PasswordFallbackAttemptsState {
    pub failed_attempts: u32,
    pub retry_after_until: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordFallbackStatus {
    pub retry_after_secs: u64,
    pub failed_attempts: u32,
}

pub struct PasswordFallbackStore {
    root: PathBuf,
}

impl Default for PasswordFallbackStore {
    fn default() -> Self {
        Self::new(DEFAULT_AUTH_ROOT)
    }
}

impl PasswordFallbackStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn status(&self, uid: u32) -> Result<PasswordFallbackStatus, String> {
        let state = self.read_attempts(uid)?;
        let now = now_secs();
        Ok(PasswordFallbackStatus {
            retry_after_secs: state.retry_after_until.saturating_sub(now),
            failed_attempts: state.failed_attempts,
        })
    }

    pub fn record_failure(&self, uid: u32) -> Result<PasswordFallbackStatus, String> {
        let mut state = self.read_attempts(uid)?;
        state.failed_attempts = state.failed_attempts.saturating_add(1);
        state.retry_after_until = now_secs() + password_backoff_secs(state.failed_attempts);
        self.write_attempts(uid, &state)?;
        self.status(uid)
    }

    pub fn clear_failures(&self, uid: u32) -> Result<(), String> {
        self.write_attempts(uid, &PasswordFallbackAttemptsState::default())
    }

    fn ensure_user_dir(&self, uid: u32) -> Result<(), String> {
        std::fs::create_dir_all(self.user_dir(uid))
            .map_err(|e| format!("Cannot create auth directory for uid={uid}: {e}"))?;
        set_mode_if_supported(self.user_dir(uid), 0o700)
    }

    fn user_dir(&self, uid: u32) -> PathBuf {
        self.root.join(uid.to_string())
    }

    fn attempts_path(&self, uid: u32) -> PathBuf {
        self.user_dir(uid).join("password_fallback_attempts.json")
    }

    fn read_attempts(&self, uid: u32) -> Result<PasswordFallbackAttemptsState, String> {
        let path = self.attempts_path(uid);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                format!("Cannot parse password fallback attempts state for uid={uid}: {e}")
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(PasswordFallbackAttemptsState::default())
            }
            Err(e) => Err(format!(
                "Cannot read password fallback attempts state for uid={uid}: {e}"
            )),
        }
    }

    fn write_attempts(
        &self,
        uid: u32,
        state: &PasswordFallbackAttemptsState,
    ) -> Result<(), String> {
        self.ensure_user_dir(uid)?;
        let json = serde_json::to_vec(state).map_err(|e| {
            format!("Cannot serialise password fallback attempts state for uid={uid}: {e}")
        })?;
        self.write_bytes_atomic(&self.attempts_path(uid), &json, 0o600)
            .map_err(|e| {
                format!("Cannot write password fallback attempts state for uid={uid}: {e}")
            })
    }

    fn write_bytes_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| format!("Path {} has no parent directory", path.display()))?;
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create {}: {e}", parent.display()))?;

        let temp_path = parent.join(format!(
            ".{}.tmp-{}-{}",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("password-fallback"),
            std::process::id(),
            now_nanos(),
        ));

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&temp_path)
            .map_err(|e| format!("Cannot open temp file {}: {e}", temp_path.display()))?;
        file.write_all(bytes)
            .map_err(|e| format!("Cannot write temp file {}: {e}", temp_path.display()))?;
        file.sync_all()
            .map_err(|e| format!("Cannot sync temp file {}: {e}", temp_path.display()))?;

        std::fs::rename(&temp_path, path).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            format!(
                "Cannot move temp file {} into {}: {e}",
                temp_path.display(),
                path.display()
            )
        })?;
        set_mode_if_supported(path, mode)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn set_mode_if_supported(path: impl AsRef<Path>, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {}: {e}", path.as_ref().display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRoot {
        path: PathBuf,
    }

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "mykey-password-fallback-test-{}-{}",
                std::process::id(),
                now_nanos()
            ));
            std::fs::create_dir_all(&path).expect("create temp root");
            Self { path }
        }

        fn store(&self) -> PasswordFallbackStore {
            PasswordFallbackStore::new(&self.path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn failed_password_fallback_attempts_accumulate_backoff() {
        let root = TestRoot::new();
        let store = root.store();

        let first = store.record_failure(1000).expect("first failure");
        assert_eq!(first.failed_attempts, 1);
        assert_eq!(first.retry_after_secs, 0);

        let second = store.record_failure(1000).expect("second failure");
        assert_eq!(second.failed_attempts, 2);
        assert!(second.retry_after_secs >= 5);
    }

    #[test]
    fn clearing_password_fallback_failures_resets_status() {
        let root = TestRoot::new();
        let store = root.store();

        store.record_failure(1000).expect("record failure");
        store.clear_failures(1000).expect("clear failures");
        let status = store.status(1000).expect("read status");

        assert_eq!(status.failed_attempts, 0);
        assert_eq!(status.retry_after_secs, 0);
    }
}
