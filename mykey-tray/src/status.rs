use std::fmt;
use std::path::Path;
use std::process::Command;

const TRAY_UNIT: &str = "mykey-tray.service";
const DAEMON_UNIT: &str = "mykey-daemon.service";
const SECRETS_UNIT: &str = "mykey-secrets.service";
const AUTH_PATHS: &[&str] = &["/usr/local/bin/mykey-auth", "/usr/bin/mykey-auth"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub tray_enabled: UnitEnabledState,
    pub tray_runtime: UnitRuntimeState,
    pub daemon_runtime: UnitRuntimeState,
    pub secrets_runtime: UnitRuntimeState,
    pub auth_status: AuthStatus,
}

impl StatusSnapshot {
    pub fn gather() -> Self {
        Self {
            tray_enabled: query_enabled(UnitScope::User, TRAY_UNIT),
            tray_runtime: query_runtime(UnitScope::User, TRAY_UNIT),
            daemon_runtime: query_runtime(UnitScope::System, DAEMON_UNIT),
            secrets_runtime: query_runtime(UnitScope::User, SECRETS_UNIT),
            auth_status: query_auth_status(),
        }
    }

    pub fn daemon_is_active(&self) -> bool {
        self.daemon_runtime.is_active()
    }

    pub fn lines(&self) -> Vec<String> {
        vec![
            format!(
                "Tray: {} ({})",
                self.tray_enabled.as_on_off(),
                self.tray_runtime
            ),
            format!("mykey-daemon: {}", self.daemon_runtime),
            format!("mykey-secrets: {}", self.secrets_runtime),
            format!("mykey-auth: {}", self.auth_status),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnitEnabledState {
    Enabled,
    Disabled,
    Static,
    Masked,
    Unknown(String),
}

impl UnitEnabledState {
    pub fn as_on_off(&self) -> &'static str {
        match self {
            Self::Enabled | Self::Static => "on",
            Self::Disabled | Self::Masked | Self::Unknown(_) => "off",
        }
    }
}

impl fmt::Display for UnitEnabledState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enabled => write!(f, "enabled"),
            Self::Disabled => write!(f, "disabled"),
            Self::Static => write!(f, "static"),
            Self::Masked => write!(f, "masked"),
            Self::Unknown(value) => write!(f, "{value}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnitRuntimeState {
    Active,
    Inactive,
    Failed,
    Activating,
    Deactivating,
    Unknown(String),
}

impl UnitRuntimeState {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

impl fmt::Display for UnitRuntimeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Inactive => write!(f, "inactive"),
            Self::Failed => write!(f, "failed"),
            Self::Activating => write!(f, "activating"),
            Self::Deactivating => write!(f, "deactivating"),
            Self::Unknown(value) => write!(f, "{value}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthStatus {
    Installed,
    Missing,
}

impl fmt::Display for AuthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Installed => write!(f, "installed"),
            Self::Missing => write!(f, "missing"),
        }
    }
}

#[derive(Clone, Copy)]
enum UnitScope {
    System,
    User,
}

pub fn enable_tray() -> Result<(), String> {
    run_systemctl(
        UnitScope::User,
        &["enable", "--now", TRAY_UNIT],
        "Could not enable mykey-tray",
    )
}

pub fn disable_tray() -> Result<(), String> {
    run_systemctl(
        UnitScope::User,
        &["disable", "--now", TRAY_UNIT],
        "Could not disable mykey-tray",
    )
}

fn query_enabled(scope: UnitScope, unit: &str) -> UnitEnabledState {
    let value = command_output(scope, &["is-enabled", unit]).unwrap_or_else(|| "unknown".into());
    match value.as_str() {
        "enabled" => UnitEnabledState::Enabled,
        "disabled" => UnitEnabledState::Disabled,
        "static" => UnitEnabledState::Static,
        "masked" => UnitEnabledState::Masked,
        other if is_status_token(other) => UnitEnabledState::Unknown(other.to_string()),
        _ => UnitEnabledState::Unknown("unknown".to_string()),
    }
}

fn query_runtime(scope: UnitScope, unit: &str) -> UnitRuntimeState {
    let value = command_output(scope, &["is-active", unit]).unwrap_or_else(|| "unknown".into());
    match value.as_str() {
        "active" => UnitRuntimeState::Active,
        "inactive" => UnitRuntimeState::Inactive,
        "failed" => UnitRuntimeState::Failed,
        "activating" => UnitRuntimeState::Activating,
        "deactivating" => UnitRuntimeState::Deactivating,
        other if is_status_token(other) => UnitRuntimeState::Unknown(other.to_string()),
        _ => UnitRuntimeState::Unknown("unknown".to_string()),
    }
}

fn query_auth_status() -> AuthStatus {
    if AUTH_PATHS
        .iter()
        .any(|path| Path::new(path).is_file() && is_executable(path))
    {
        AuthStatus::Installed
    } else {
        AuthStatus::Missing
    }
}

fn is_executable(path: &str) -> bool {
    std::fs::metadata(path)
        .map(|metadata| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                !metadata.permissions().readonly()
            }
        })
        .unwrap_or(false)
}

fn command_output(scope: UnitScope, args: &[&str]) -> Option<String> {
    let mut command = Command::new("systemctl");
    if matches!(scope, UnitScope::User) {
        command.arg("--user");
    }
    let output = command.args(args).output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.is_empty() {
        Some(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            None
        } else {
            Some(stderr)
        }
    }
}

fn run_systemctl(scope: UnitScope, args: &[&str], context: &str) -> Result<(), String> {
    let mut command = Command::new("systemctl");
    if matches!(scope, UnitScope::User) {
        command.arg("--user");
    }

    let output = command
        .args(args)
        .output()
        .map_err(|e| format!("{context}: {e}"))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("systemctl exited with {}", output.status)
    };
    Err(format!("{context}: {detail}"))
}

fn is_status_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch == '-' || ch == '_')
}
