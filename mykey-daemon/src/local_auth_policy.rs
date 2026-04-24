use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize};

const DEFAULT_AUTH_ROOT: &str = "/etc/mykey/auth";
pub const DEFAULT_BIOMETRIC_ATTEMPT_LIMIT: u8 = 3;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum LegacyLocalAuthMethod {
    Pin,
    Biometric,
    SecurityKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAuthStage {
    Biometric,
    SecurityKey,
    Pin,
}

impl LocalAuthStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Biometric => "biometric",
            Self::SecurityKey => "security_key",
            Self::Pin => "pin",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LocalAuthPolicy {
    pub enabled: bool,
    pub pin_fallback_enabled: bool,
    #[serde(default)]
    pub biometric_backends: Vec<BiometricBackend>,
    #[serde(default)]
    pub security_key_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveLocalAuthPolicy {
    pub enabled: bool,
    pub auth_chain: Vec<LocalAuthStage>,
    pub biometric_backends: Vec<BiometricBackend>,
    pub security_key_enabled: bool,
    pub pin_enabled: bool,
    pub password_fallback_allowed: bool,
    pub elevated_password_required: bool,
    pub biometric_attempt_limit: u8,
}

impl Default for LocalAuthPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            pin_fallback_enabled: false,
            biometric_backends: Vec::new(),
            security_key_enabled: false,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawLocalAuthPolicy {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    pin_fallback_enabled: bool,
    #[serde(default)]
    biometric_backends: Vec<BiometricBackend>,
    #[serde(default)]
    security_key_enabled: bool,
    #[serde(default)]
    primary_method: Option<LegacyLocalAuthMethod>,
    #[serde(default)]
    biometric_backend: Option<BiometricBackend>,
}

impl From<RawLocalAuthPolicy> for LocalAuthPolicy {
    fn from(raw: RawLocalAuthPolicy) -> Self {
        let mut biometric_backends = raw.biometric_backends;
        if biometric_backends.is_empty() {
            if let Some(backend) = raw.biometric_backend {
                biometric_backends.push(backend);
            }
        }

        Self {
            enabled: raw.enabled,
            pin_fallback_enabled: raw.pin_fallback_enabled,
            biometric_backends,
            security_key_enabled: raw.security_key_enabled
                || raw.primary_method == Some(LegacyLocalAuthMethod::SecurityKey),
        }
    }
}

impl<'de> Deserialize<'de> for LocalAuthPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        RawLocalAuthPolicy::deserialize(deserializer).map(Into::into)
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

    #[cfg(test)]
    pub fn read_policy(&self, uid: u32) -> Result<LocalAuthPolicy, String> {
        let (policy, _) = self.read_policy_internal(uid)?;
        Ok(normalise_policy(policy))
    }

    #[cfg(test)]
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
        self.write_policy(uid, &pin_only_policy())
    }

    pub fn on_pin_reset(&self, uid: u32) -> Result<(), String> {
        self.write_policy(uid, &LocalAuthPolicy::default())
    }

    pub fn sync_effective_policy(
        &self,
        uid: u32,
        pin_is_set: bool,
    ) -> Result<EffectiveLocalAuthPolicy, String> {
        let (policy, existed) = self.read_policy_internal(uid)?;
        let mut normalised = normalise_policy(policy.clone());
        let mut should_persist = existed && normalised != policy;

        if pin_is_set {
            if should_backfill_pin_only(&normalised) {
                normalised = pin_only_policy();
                should_persist = true;
            }
        } else if normalised != LocalAuthPolicy::default() {
            normalised = LocalAuthPolicy::default();
            should_persist = true;
        }

        if should_persist {
            self.write_policy(uid, &normalised)?;
        }

        Ok(effective_policy_from_state(normalised, pin_is_set))
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
    policy.biometric_backends.sort();
    policy.biometric_backends.dedup();

    if !policy.enabled {
        return LocalAuthPolicy::default();
    }

    if !policy.pin_fallback_enabled {
        return LocalAuthPolicy::default();
    }

    if !policy.security_key_enabled && policy.biometric_backends.is_empty() {
        return pin_only_policy();
    }

    policy
}

fn pin_only_policy() -> LocalAuthPolicy {
    LocalAuthPolicy {
        enabled: true,
        pin_fallback_enabled: true,
        biometric_backends: Vec::new(),
        security_key_enabled: false,
    }
}

fn should_backfill_pin_only(policy: &LocalAuthPolicy) -> bool {
    !policy.enabled
        && !policy.pin_fallback_enabled
        && !policy.security_key_enabled
        && policy.biometric_backends.is_empty()
}

fn effective_policy_from_state(
    policy: LocalAuthPolicy,
    pin_is_set: bool,
) -> EffectiveLocalAuthPolicy {
    let mut auth_chain = Vec::new();
    if policy.enabled {
        if !policy.biometric_backends.is_empty() {
            auth_chain.push(LocalAuthStage::Biometric);
        }
        if policy.security_key_enabled {
            auth_chain.push(LocalAuthStage::SecurityKey);
        }
        if policy.pin_fallback_enabled {
            auth_chain.push(LocalAuthStage::Pin);
        }
    }

    let biometric_attempt_limit = if !policy.biometric_backends.is_empty() {
        DEFAULT_BIOMETRIC_ATTEMPT_LIMIT
    } else {
        0
    };

    EffectiveLocalAuthPolicy {
        enabled: !auth_chain.is_empty(),
        auth_chain,
        biometric_backends: policy.biometric_backends,
        security_key_enabled: policy.security_key_enabled,
        pin_enabled: policy.pin_fallback_enabled,
        password_fallback_allowed: !policy.enabled || !pin_is_set,
        elevated_password_required: true,
        biometric_attempt_limit,
    }
}

impl EffectiveLocalAuthPolicy {
    pub fn as_persisted_policy(&self) -> LocalAuthPolicy {
        if !self.enabled {
            return LocalAuthPolicy::default();
        }

        LocalAuthPolicy {
            enabled: true,
            pin_fallback_enabled: self.pin_enabled,
            biometric_backends: self.biometric_backends.clone(),
            security_key_enabled: self.security_key_enabled,
        }
    }
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
        assert!(policy.pin_fallback_enabled);
        assert!(policy.biometric_backends.is_empty());
        assert!(!policy.security_key_enabled);
    }

    #[test]
    fn effective_pin_only_policy_blocks_normal_password_fallback() {
        let root = TestRoot::new();
        let store = root.store();

        store.enable_pin_only(1000).expect("enable pin-only policy");
        let effective = store
            .sync_effective_policy(1000, true)
            .expect("read effective policy");

        assert!(effective.enabled);
        assert_eq!(effective.auth_chain, vec![LocalAuthStage::Pin]);
        assert!(effective.pin_enabled);
        assert!(!effective.password_fallback_allowed);
        assert!(effective.elevated_password_required);
        assert_eq!(effective.biometric_attempt_limit, 0);
    }

    #[test]
    fn disabled_policy_allows_normal_password_fallback() {
        let root = TestRoot::new();
        let store = root.store();

        let effective = store
            .sync_effective_policy(1000, false)
            .expect("read effective default policy");

        assert!(!effective.enabled);
        assert!(effective.password_fallback_allowed);
        assert!(effective.elevated_password_required);
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

        assert_eq!(policy, LocalAuthPolicy::default());
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
                    pin_fallback_enabled: true,
                    biometric_backends: vec![BiometricBackend::Fprintd],
                    security_key_enabled: false,
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

    #[test]
    fn missing_pin_forces_biometric_policy_back_to_default() {
        let root = TestRoot::new();
        let store = root.store();

        store
            .write_policy(
                1000,
                &LocalAuthPolicy {
                    enabled: true,
                    pin_fallback_enabled: true,
                    biometric_backends: vec![BiometricBackend::Fprintd],
                    security_key_enabled: false,
                },
            )
            .expect("write biometric policy");

        let effective = store
            .sync_effective_policy(1000, false)
            .expect("repair missing-pin policy");
        let persisted = store.read_policy(1000).expect("read repaired policy");

        assert!(!effective.enabled);
        assert!(effective.password_fallback_allowed);
        assert!(effective.auth_chain.is_empty());
        assert!(effective.biometric_backends.is_empty());
        assert_eq!(persisted, LocalAuthPolicy::default());
    }

    #[test]
    fn security_key_policy_requires_pin_fallback() {
        let root = TestRoot::new();
        let store = root.store();

        store
            .write_policy(
                1000,
                &LocalAuthPolicy {
                    enabled: true,
                    pin_fallback_enabled: false,
                    biometric_backends: Vec::new(),
                    security_key_enabled: true,
                },
            )
            .expect("write invalid security-key policy");

        let policy = store.read_policy(1000).expect("read sanitised policy");
        assert_eq!(policy, LocalAuthPolicy::default());
    }

    #[test]
    fn effective_security_key_policy_blocks_normal_password_fallback() {
        let root = TestRoot::new();
        let store = root.store();

        store
            .write_policy(
                1000,
                &LocalAuthPolicy {
                    enabled: true,
                    pin_fallback_enabled: true,
                    biometric_backends: Vec::new(),
                    security_key_enabled: true,
                },
            )
            .expect("write security-key policy");

        let effective = store
            .sync_effective_policy(1000, true)
            .expect("read effective policy");

        assert!(effective.enabled);
        assert_eq!(
            effective.auth_chain,
            vec![LocalAuthStage::SecurityKey, LocalAuthStage::Pin]
        );
        assert!(effective.pin_enabled);
        assert!(effective.security_key_enabled);
        assert!(!effective.password_fallback_allowed);
        assert_eq!(effective.biometric_attempt_limit, 0);
    }

    #[test]
    fn biometric_policy_uses_default_attempt_limit() {
        let root = TestRoot::new();
        let store = root.store();

        store
            .write_policy(
                1000,
                &LocalAuthPolicy {
                    enabled: true,
                    pin_fallback_enabled: true,
                    biometric_backends: vec![BiometricBackend::Howdy],
                    security_key_enabled: false,
                },
            )
            .expect("write biometric policy");

        let effective = store
            .sync_effective_policy(1000, true)
            .expect("read effective biometric policy");

        assert!(effective.enabled);
        assert_eq!(
            effective.auth_chain,
            vec![LocalAuthStage::Biometric, LocalAuthStage::Pin]
        );
        assert_eq!(
            effective.biometric_attempt_limit,
            DEFAULT_BIOMETRIC_ATTEMPT_LIMIT
        );
        assert!(!effective.password_fallback_allowed);
        assert!(effective.elevated_password_required);
    }

    #[test]
    fn legacy_primary_method_biometric_is_read_into_backend_set_model() {
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
  "pin_fallback_enabled": true,
  "biometric_backend": "fprintd"
}"#,
        )
        .expect("write legacy policy");

        let policy = store.read_policy(1000).expect("read upgraded policy");
        assert_eq!(
            policy,
            LocalAuthPolicy {
                enabled: true,
                pin_fallback_enabled: true,
                biometric_backends: vec![BiometricBackend::Fprintd],
                security_key_enabled: false,
            }
        );
    }

    #[test]
    fn effective_policy_orders_biometrics_before_security_key_and_pin() {
        let root = TestRoot::new();
        let store = root.store();

        store
            .write_policy(
                1000,
                &LocalAuthPolicy {
                    enabled: true,
                    pin_fallback_enabled: true,
                    biometric_backends: vec![BiometricBackend::Fprintd],
                    security_key_enabled: true,
                },
            )
            .expect("write staged policy");

        let effective = store
            .sync_effective_policy(1000, true)
            .expect("read staged policy");

        assert_eq!(
            effective.auth_chain,
            vec![
                LocalAuthStage::Biometric,
                LocalAuthStage::SecurityKey,
                LocalAuthStage::Pin
            ]
        );
        assert_eq!(effective.biometric_backends, vec![BiometricBackend::Fprintd]);
        assert!(effective.security_key_enabled);
        assert!(effective.pin_enabled);
    }
}
