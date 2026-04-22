use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const DEFAULT_PIN_ROOT: &str = "/etc/mykey/pin";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AttemptsState {
    pub failed_sessions: u32,
    pub cooldown_until: u64,
}

pub struct PinStore {
    root: PathBuf,
}

impl Default for PinStore {
    fn default() -> Self {
        Self::new(DEFAULT_PIN_ROOT)
    }
}

impl PinStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn pin_is_set(&self, uid: u32) -> Result<bool, String> {
        match std::fs::metadata(self.pin_path(uid)) {
            Ok(meta) => Ok(meta.len() > 0),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("Cannot stat PIN blob for uid={uid}: {e}")),
        }
    }

    pub fn read_pin_blob(&self, uid: u32) -> Result<Option<Vec<u8>>, String> {
        let path = self.pin_path(uid);
        match std::fs::read(&path) {
            Ok(bytes) if bytes.is_empty() => Ok(None),
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("Cannot read PIN blob for uid={uid}: {e}")),
        }
    }

    pub fn write_pin_blob(&self, uid: u32, blob: &[u8]) -> Result<(), String> {
        if blob.is_empty() {
            return Err(format!("Refusing to write empty PIN blob for uid={uid}"));
        }

        self.ensure_user_dir(uid)?;
        self.write_bytes_atomic(&self.pin_path(uid), blob, 0o600)
            .map_err(|e| format!("Cannot write PIN blob for uid={uid}: {e}"))
    }

    pub fn clear_pin(&self, uid: u32) -> Result<(), String> {
        remove_if_exists(&self.pin_path(uid))
            .map_err(|e| format!("Cannot remove PIN blob for uid={uid}: {e}"))?;
        remove_if_exists(&self.attempts_path(uid))
            .map_err(|e| format!("Cannot remove attempts state for uid={uid}: {e}"))?;
        remove_dir_if_empty(&self.user_dir(uid))
            .map_err(|e| format!("Cannot clean PIN directory for uid={uid}: {e}"))?;
        Ok(())
    }

    pub fn read_attempts(&self, uid: u32) -> Result<AttemptsState, String> {
        let path = self.attempts_path(uid);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("Cannot parse attempts state for uid={uid}: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AttemptsState::default()),
            Err(e) => Err(format!("Cannot read attempts state for uid={uid}: {e}")),
        }
    }

    pub fn write_attempts(&self, uid: u32, state: &AttemptsState) -> Result<(), String> {
        self.ensure_user_dir(uid)?;
        let json = serde_json::to_vec(state)
            .map_err(|e| format!("Cannot serialise attempts state for uid={uid}: {e}"))?;
        self.write_bytes_atomic(&self.attempts_path(uid), &json, 0o600)
            .map_err(|e| format!("Cannot write attempts state for uid={uid}: {e}"))
    }

    pub fn lockout_remaining(&self, uid: u32) -> Result<Option<u64>, String> {
        let state = self.read_attempts(uid)?;
        let now = now_secs();
        if state.cooldown_until > now {
            Ok(Some(state.cooldown_until - now))
        } else {
            Ok(None)
        }
    }

    pub fn record_failed_attempt(&self, uid: u32) -> Result<AttemptsState, String> {
        let mut state = self.read_attempts(uid)?;
        state.failed_sessions = state.failed_sessions.saturating_add(1);
        state.cooldown_until = now_secs() + cooldown_secs(state.failed_sessions);
        self.write_attempts(uid, &state)?;
        Ok(state)
    }

    pub fn record_success(&self, uid: u32) -> Result<(), String> {
        self.write_attempts(uid, &AttemptsState::default())
    }

    fn ensure_user_dir(&self, uid: u32) -> Result<(), String> {
        std::fs::create_dir_all(self.user_dir(uid))
            .map_err(|e| format!("Cannot create PIN directory for uid={uid}: {e}"))?;
        set_mode_if_supported(self.user_dir(uid), 0o700)
    }

    fn user_dir(&self, uid: u32) -> PathBuf {
        self.root.join(uid.to_string())
    }

    fn pin_path(&self, uid: u32) -> PathBuf {
        self.user_dir(uid).join("sealed_pin")
    }

    fn attempts_path(&self, uid: u32) -> PathBuf {
        self.user_dir(uid).join("attempts.json")
    }

    fn write_bytes_atomic(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| format!("Path {} has no parent directory", path.display()))?;
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create {}: {e}", parent.display()))?;

        let temp_path = parent.join(format!(
            ".{}.tmp-{}-{}",
            path.file_name().and_then(|s| s.to_str()).unwrap_or("pin"),
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

pub fn cooldown_secs(failed_sessions: u32) -> u64 {
    match failed_sessions {
        0..=3 => 0,
        4 => 60,
        5 => 5 * 60,
        6 => 15 * 60,
        7 => 30 * 60,
        8 => 60 * 60,
        9 => 2 * 60 * 60,
        _ => 5 * 60 * 60,
    }
}

fn remove_if_exists(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn remove_dir_if_empty(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.kind() == std::io::ErrorKind::DirectoryNotEmpty =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
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
                "mykey-pin-store-test-{}-{}",
                std::process::id(),
                now_nanos()
            ));
            std::fs::create_dir_all(&path).expect("create temp root");
            Self { path }
        }

        fn store(&self) -> PinStore {
            PinStore::new(&self.path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn stores_pin_blobs_per_user() {
        let root = TestRoot::new();
        let store = root.store();

        store
            .write_pin_blob(1000, b"alpha")
            .expect("write uid 1000");
        store.write_pin_blob(1001, b"beta").expect("write uid 1001");

        assert_eq!(
            store.read_pin_blob(1000).expect("read uid 1000"),
            Some(b"alpha".to_vec())
        );
        assert_eq!(
            store.read_pin_blob(1001).expect("read uid 1001"),
            Some(b"beta".to_vec())
        );
        assert_ne!(store.pin_path(1000), store.pin_path(1001));
    }

    #[test]
    fn tracks_attempts_per_user_and_resets() {
        let root = TestRoot::new();
        let store = root.store();

        assert_eq!(
            store.read_attempts(1000).expect("initial attempts"),
            AttemptsState::default()
        );
        let state = store.record_failed_attempt(1000).expect("failed attempt");
        assert_eq!(state.failed_sessions, 1);
        assert_eq!(
            store.lockout_remaining(1000).expect("lockout remaining"),
            None
        );
        assert_eq!(
            store.read_attempts(1001).expect("other user"),
            AttemptsState::default()
        );

        store
            .record_failed_attempt(1000)
            .expect("second failed attempt");
        store
            .record_failed_attempt(1000)
            .expect("third failed attempt");
        assert_eq!(
            store
                .lockout_remaining(1000)
                .expect("lockout before threshold"),
            None
        );

        let state = store
            .record_failed_attempt(1000)
            .expect("fourth failed attempt");
        assert_eq!(state.failed_sessions, 4);
        assert!(store
            .lockout_remaining(1000)
            .expect("lockout at threshold")
            .is_some());

        store.record_success(1000).expect("record success");
        assert_eq!(
            store.read_attempts(1000).expect("reset attempts"),
            AttemptsState::default()
        );
        assert_eq!(store.lockout_remaining(1000).expect("reset lockout"), None);
    }

    #[test]
    fn cooldown_schedule_matches_policy() {
        assert_eq!(cooldown_secs(0), 0);
        assert_eq!(cooldown_secs(1), 0);
        assert_eq!(cooldown_secs(2), 0);
        assert_eq!(cooldown_secs(3), 0);
        assert_eq!(cooldown_secs(4), 60);
        assert_eq!(cooldown_secs(5), 5 * 60);
        assert_eq!(cooldown_secs(6), 15 * 60);
        assert_eq!(cooldown_secs(7), 30 * 60);
        assert_eq!(cooldown_secs(8), 60 * 60);
        assert_eq!(cooldown_secs(9), 2 * 60 * 60);
        assert_eq!(cooldown_secs(10), 5 * 60 * 60);
        assert_eq!(cooldown_secs(50), 5 * 60 * 60);
    }

    #[test]
    fn clears_user_pin_state() {
        let root = TestRoot::new();
        let store = root.store();

        store.write_pin_blob(1000, b"alpha").expect("write pin");
        store.record_failed_attempt(1000).expect("record attempt");
        store.clear_pin(1000).expect("clear pin");

        assert_eq!(store.pin_is_set(1000).expect("pin status"), false);
        assert_eq!(store.read_pin_blob(1000).expect("pin blob"), None);
        assert_eq!(
            store.read_attempts(1000).expect("attempts"),
            AttemptsState::default()
        );
    }
}
