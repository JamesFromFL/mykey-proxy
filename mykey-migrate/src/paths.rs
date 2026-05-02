use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const APP_DIR: &str = "mykey";

pub fn user_data_root() -> PathBuf {
    if let Some(path) = std::env::var_os("MYKEY_DATA_DIR") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(path).join(APP_DIR);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/share").join(APP_DIR);
    }
    PathBuf::from(".mykey")
}

pub fn user_state_root() -> PathBuf {
    if let Some(path) = std::env::var_os("MYKEY_STATE_DIR") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(path).join(APP_DIR);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/state").join(APP_DIR);
    }
    user_data_root()
}

pub fn secrets_dir() -> PathBuf {
    user_data_root().join("secrets")
}

pub fn migrate_log_path() -> PathBuf {
    user_state_root().join("migrate.log")
}

pub fn provider_dir() -> PathBuf {
    user_data_root().join("provider")
}

pub fn provider_info_path() -> PathBuf {
    provider_dir().join("info.json")
}

pub fn ensure_private_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path)
        .map_err(|e| format!("Cannot create directory {}: {e}", path.display()))?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("Cannot secure directory {}: {e}", path.display()))?;
    Ok(())
}

pub fn write_private_file(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }

    #[cfg(unix)]
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("Cannot open {}: {e}", path.display()))?;

    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("Cannot open {}: {e}", path.display()))?;

    file.write_all(data)
        .map_err(|e| format!("Cannot write {}: {e}", path.display()))?;

    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Cannot secure file {}: {e}", path.display()))?;

    Ok(())
}
