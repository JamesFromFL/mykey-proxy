use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const DEFAULT_AUTH_ROOT: &str = "/etc/mykey/auth";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalAuthMethod {
    Pin,
    Biometric,
}

impl LocalAuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pin => "pin",
            Self::Biometric => "biometric",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BiometricBackend {
    Fprintd,
    Howdy,
}

impl BiometricBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fprintd => "fprintd",
            Self::Howdy => "howdy",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalAuthPolicy {
    pub enabled: bool,
    pub primary_method: LocalAuthMethod,
    pub pin_fallback_enabled: bool,
    pub biometric_backend: Option<BiometricBackend>,
}

impl Default for LocalAuthPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            primary_method: LocalAuthMethod::Pin,
            pin_fallback_enabled: false,
            biometric_backend: None,
        }
    }
}

pub struct LocalAuthPolicyStore {
    root: PathBuf,
}

impl Default for LocalAuthPolicyStore {
    fn default() -> Self {
        Self::new(DEFAULT_AUTH_ROOT)
    }
}

impl LocalAuthPolicyStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn read_policy(&self, uid: u32) -> Result<LocalAuthPolicy, String> {
        let (policy, _) = self.read_policy_internal(uid)?;
        Ok(normalise_policy(policy))
    }

    pub fn repair_policy(&self, uid: u32) -> Result<LocalAuthPolicy, String> {
        let (policy, existed) = self.read_policy_internal(uid)?;
        let normalised = normalise_policy(policy.clone());
        if existed && normalised != policy {
            self.write_policy(uid, &normalised)?;
        }
        Ok(normalised)
    }

    pub fn write_policy(&self, uid: u32, policy: &LocalAuthPolicy) -> Result<(), String> {
        self.ensure_user_dir(uid)?;
        let normalised = normalise_policy(policy.clone());
        let json = serde_json::to_vec_pretty(&normalised)
            .map_err(|e| format!("Cannot serialise local auth policy for uid={uid}: {e}"))?;
        self.write_bytes_atomic(&self.policy_path(uid), &json, 0o600)
            .map_err(|e| format!("Cannot write local auth policy for uid={uid}: {e}"))
    }

    pub fn clear_policy(&self, uid: u32) -> Result<(), String> {
        remove_if_exists(&self.policy_path(uid))
            .map_err(|e| format!("Cannot remove local auth policy for uid={uid}: {e}"))?;
        remove_dir_if_empty(&self.user_dir(uid))
            .map_err(|e| format!("Cannot clean local auth directory for uid={uid}: {e}"))?;
        Ok(())
    }

    pub fn enable_pin_only(&self, uid: u32) -> Result<(), String> {
        let mut policy = self.read_policy(uid)?;
        policy.enabled = true;
        policy.primary_method = LocalAuthMethod::Pin;
        policy.pin_fallback_enabled = true;
        self.write_policy(uid, &policy)
    }

    pub fn on_pin_reset(&self, uid: u32) -> Result<(), String> {
        self.write_policy(uid, &LocalAuthPolicy::default())
    }

    fn ensure_user_dir(&self, uid: u32) -> Result<(), String> {
        std::fs::create_dir_all(self.user_dir(uid))
            .map_err(|e| format!("Cannot create local auth directory for uid={uid}: {e}"))?;
        set_mode_if_supported(self.user_dir(uid), 0o700)
    }

    fn user_dir(&self, uid: u32) -> PathBuf {
        self.root.join(uid.to_string())
    }

    fn policy_path(&self, uid: u32) -> PathBuf {
        self.user_dir(uid).join("policy.json")
    }

    #[cfg(test)]
    pub(crate) fn policy_path_for_test(&self, uid: u32) -> PathBuf {
        self.policy_path(uid)
    }

    fn read_policy_internal(&self, uid: u32) -> Result<(LocalAuthPolicy, bool), String> {
        let path = self.policy_path(uid);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(|policy| (policy, true))
                .map_err(|e| format!("Cannot parse local auth policy for uid={uid}: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok((LocalAuthPolicy::default(), false))
            }
            Err(e) => Err(format!("Cannot read local auth policy for uid={uid}: {e}")),
        }
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
                .unwrap_or("policy"),
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

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
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

fn normalise_policy(mut policy: LocalAuthPolicy) -> LocalAuthPolicy {
    if policy.biometric_backend.is_some() {
        policy.primary_method = LocalAuthMethod::Biometric;
        if !policy.pin_fallback_enabled {
            return LocalAuthPolicy::default();
        }
    } else if policy.primary_method == LocalAuthMethod::Biometric {
        return LocalAuthPolicy::default();
    }

    if policy.primary_method == LocalAuthMethod::Pin && !policy.pin_fallback_enabled {
        policy.enabled = false;
    }

    policy
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
                "mykey-local-auth-policy-test-{}-{}",
                std::process::id(),
                now_nanos()
            ));
            std::fs::create_dir_all(&path).expect("create temp root");
            Self { path }
        }

        fn store(&self) -> LocalAuthPolicyStore {
            LocalAuthPolicyStore::new(&self.path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn default_policy_is_disabled_pin_primary() {
        let root = TestRoot::new();
        let store = root.store();

        let policy = store.read_policy(1000).expect("read default policy");
        assert_eq!(policy, LocalAuthPolicy::default());
    }

    #[test]
    fn pin_only_policy_is_written_and_read_back() {
        let root = TestRoot::new();
        let store = root.store();

        store.enable_pin_only(1000).expect("enable pin-only policy");
        let policy = store.read_policy(1000).expect("read written policy");

        assert!(policy.enabled);
        assert_eq!(policy.primary_method, LocalAuthMethod::Pin);
        assert!(policy.pin_fallback_enabled);
        assert_eq!(policy.biometric_backend, None);
    }

    #[test]
    fn pin_reset_disables_pin_only_policy() {
        let root = TestRoot::new();
        let store = root.store();

        store.enable_pin_only(1000).expect("enable pin-only policy");
        store
            .on_pin_reset(1000)
            .expect("update policy on pin reset");
        let policy = store.read_policy(1000).expect("read updated policy");

        assert!(!policy.enabled);
        assert_eq!(policy.primary_method, LocalAuthMethod::Pin);
        assert!(!policy.pin_fallback_enabled);
    }

    #[test]
    fn pin_reset_disables_biometric_policy_too() {
        let root = TestRoot::new();
        let store = root.store();

        store
            .write_policy(
                1000,
                &LocalAuthPolicy {
                    enabled: true,
                    primary_method: LocalAuthMethod::Biometric,
                    pin_fallback_enabled: true,
                    biometric_backend: Some(BiometricBackend::Fprintd),
                },
            )
            .expect("write biometric policy");

        store
            .on_pin_reset(1000)
            .expect("update policy on pin reset");
        let policy = store.read_policy(1000).expect("read updated policy");

        assert_eq!(policy, LocalAuthPolicy::default());
    }

    #[test]
    fn invalid_biometric_policy_is_sanitised_on_read() {
        let root = TestRoot::new();
        let store = root.store();
        let policy_path = root.path.join("1000").join("policy.json");
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

        let policy = store.read_policy(1000).expect("read sanitised policy");
        assert_eq!(policy, LocalAuthPolicy::default());
    }

    #[test]
    fn repair_policy_persists_sanitised_policy() {
        let root = TestRoot::new();
        let store = root.store();
        let policy_path = root.path.join("1000").join("policy.json");
        std::fs::create_dir_all(policy_path.parent().expect("policy parent"))
            .expect("create policy parent");
        std::fs::write(
            &policy_path,
            r#"{
  "enabled": true,
  "primary_method": "biometric",
  "pin_fallback_enabled": false,
  "biometric_backend": "howdy"
}"#,
        )
        .expect("write invalid policy");

        let repaired = store.repair_policy(1000).expect("repair policy");
        let persisted = store.read_policy(1000).expect("read repaired policy");

        assert_eq!(repaired, LocalAuthPolicy::default());
        assert_eq!(persisted, LocalAuthPolicy::default());
    }
}
