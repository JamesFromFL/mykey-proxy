use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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

pub fn secrets_dir() -> PathBuf {
    user_data_root().join("secrets")
}

pub fn provider_dir() -> PathBuf {
    user_data_root().join("provider")
}

pub fn aliases_file() -> PathBuf {
    provider_dir().join("aliases.json")
}

pub fn ensure_private_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path)
        .map_err(|e| format!("Cannot create directory {}: {e}", path.display()))?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("Cannot secure directory {}: {e}", path.display()))?;
    Ok(())
}
