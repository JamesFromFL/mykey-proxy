// storage.rs — On-disk storage for Secret Service collections and items.
//
// Secrets are stored as TPM2-sealed blobs under the user's MyKey data dir.
// Layout:
//   $XDG_DATA_HOME/mykey/secrets/<collection_id>/collection.json
//   $XDG_DATA_HOME/mykey/secrets/<collection_id>/<item_id>.json
// Fallback:
//   ~/.local/share/mykey/secrets/<collection_id>/...

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::paths;

fn internal_stage_dir_name() -> String {
    format!(".staging-{}", uuid::Uuid::new_v4())
}

fn internal_backup_dir_name() -> String {
    format!(".backup-{}", uuid::Uuid::new_v4())
}

fn is_internal_storage_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|name| name.starts_with(".staging-") || name.starts_with(".backup-"))
        .unwrap_or(false)
}

fn remove_path(path: &Path) -> Result<(), String> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)
            .map_err(|e| format!("Cannot remove directory {}: {e}", path.display()))
    } else {
        std::fs::remove_file(path)
            .map_err(|e| format!("Cannot remove file {}: {e}", path.display()))
    }
}

fn save_collection_in(base_dir: &Path, c: &StoredCollection) -> Result<(), String> {
    let dir = base_dir.join(&c.id);
    paths::ensure_private_dir(&dir)?;
    let path = dir.join("collection.json");
    let data = serde_json::to_vec_pretty(c)
        .map_err(|e| format!("Cannot serialise collection: {e}"))?;
    paths::write_private_file(&path, &data)
}

fn save_item_in(base_dir: &Path, item: &StoredItem) -> Result<(), String> {
    let dir = base_dir.join(&item.collection_id);
    paths::ensure_private_dir(&dir)?;
    let path = dir.join(format!("{}.json", item.id));
    let data = serde_json::to_vec_pretty(item)
        .map_err(|e| format!("Cannot serialise item: {e}"))?;
    paths::write_private_file(&path, &data)
}

/// Metadata for a stored collection (persisted as collection.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCollection {
    pub id: String,
    pub label: String,
    pub created: u64,
    pub modified: u64,
}

/// A stored secret item.  `sealed_value` contains the TPM2-sealed secret bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredItem {
    pub id: String,
    pub collection_id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    /// TPM2-sealed secret bytes produced by mykey-daemon SealSecret.
    pub sealed_value: Vec<u8>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

pub struct StagedStorage {
    path: PathBuf,
}

pub struct ActivatedStorage {
    previous_base: Option<PathBuf>,
}

impl StagedStorage {
    pub fn new() -> Result<Self, String> {
        let base = base_dir();
        paths::ensure_private_dir(&base)?;
        let path = base.join(internal_stage_dir_name());
        paths::ensure_private_dir(&path)?;
        Ok(Self { path })
    }

    pub fn save_collection(&self, c: &StoredCollection) -> Result<(), String> {
        save_collection_in(&self.path, c)
    }

    pub fn save_item(&self, item: &StoredItem) -> Result<(), String> {
        save_item_in(&self.path, item)
    }

    pub fn discard(self) -> Result<(), String> {
        if self.path.exists() {
            std::fs::remove_dir_all(&self.path)
                .map_err(|e| format!("Cannot remove staging dir {}: {e}", self.path.display()))?;
        }
        Ok(())
    }

    pub fn activate(self) -> Result<ActivatedStorage, String> {
        let base = base_dir();
        let backup = base.join(internal_backup_dir_name());
        paths::ensure_private_dir(&backup)?;

        let mut moved_existing: Vec<PathBuf> = Vec::new();
        let existing_entries = std::fs::read_dir(&base)
            .map_err(|e| format!("Cannot list storage dir {}: {e}", base.display()))?;

        for entry in existing_entries {
            let entry = entry
                .map_err(|e| format!("Cannot read storage entry in {}: {e}", base.display()))?;
            let path = entry.path();
            if path == self.path || path == backup || is_internal_storage_dir(&path) {
                continue;
            }
            let backup_target = backup.join(entry.file_name());
            std::fs::rename(&path, &backup_target).map_err(|e| {
                format!(
                    "Cannot move existing storage {} to {}: {e}",
                    path.display(),
                    backup_target.display()
                )
            })?;
            moved_existing.push(backup_target);
        }

        let staged_entries = std::fs::read_dir(&self.path)
            .map_err(|e| format!("Cannot list staging dir {}: {e}", self.path.display()))?;

        for entry in staged_entries {
            let entry = entry.map_err(|e| {
                format!("Cannot read staged entry in {}: {e}", self.path.display())
            })?;
            let staged_path = entry.path();
            let active_path = base.join(entry.file_name());
            if let Err(e) = std::fs::rename(&staged_path, &active_path) {
                for path in std::fs::read_dir(&base)
                    .ok()
                    .into_iter()
                    .flat_map(|iter| iter.flatten())
                    .map(|entry| entry.path())
                    .filter(|path| !is_internal_storage_dir(path))
                {
                    let _ = remove_path(&path);
                }
                for backup_path in &moved_existing {
                    let restore_target = base.join(
                        backup_path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or_default(),
                    );
                    let _ = std::fs::rename(backup_path, restore_target);
                }
                let _ = std::fs::remove_dir_all(&backup);
                let _ = std::fs::remove_dir_all(&self.path);
                return Err(format!(
                    "Cannot activate staged storage {} -> {}: {e}",
                    staged_path.display(),
                    active_path.display()
                ));
            }
        }

        std::fs::remove_dir(&self.path)
            .map_err(|e| format!("Cannot remove empty staging dir {}: {e}", self.path.display()))?;

        let previous_base = if moved_existing.is_empty() {
            let _ = std::fs::remove_dir(&backup);
            None
        } else {
            Some(backup)
        };

        Ok(ActivatedStorage { previous_base })
    }
}

impl ActivatedStorage {
    pub fn commit(self) -> Result<(), String> {
        if let Some(previous_base) = self.previous_base {
            std::fs::remove_dir_all(&previous_base).map_err(|e| {
                format!(
                    "Cannot remove previous storage backup {}: {e}",
                    previous_base.display()
                )
            })?;
        }
        Ok(())
    }

    pub fn rollback(self) -> Result<(), String> {
        let base = base_dir();
        if base.exists() {
            for entry in std::fs::read_dir(&base)
                .map_err(|e| format!("Cannot list active storage {}: {e}", base.display()))?
            {
                let entry = entry.map_err(|e| {
                    format!("Cannot read active storage entry in {}: {e}", base.display())
                })?;
                let path = entry.path();
                if self.previous_base.as_ref() == Some(&path) || is_internal_storage_dir(&path) {
                    continue;
                }
                remove_path(&path)?;
            }
        }
        if let Some(previous_base) = self.previous_base {
            let entries = std::fs::read_dir(&previous_base).map_err(|e| {
                format!(
                    "Cannot list previous storage backup {}: {e}",
                    previous_base.display()
                )
            })?;
            for entry in entries {
                let entry = entry.map_err(|e| {
                    format!(
                        "Cannot read previous storage backup entry in {}: {e}",
                        previous_base.display()
                    )
                })?;
                let restore_target = base.join(entry.file_name());
                std::fs::rename(entry.path(), &restore_target).map_err(|e| {
                    format!(
                        "Cannot restore previous storage {} -> {}: {e}",
                        previous_base.display(),
                        restore_target.display()
                    )
                })?;
            }
            std::fs::remove_dir(&previous_base).map_err(|e| {
                format!(
                    "Cannot remove previous storage backup {}: {e}",
                    previous_base.display()
                )
            })?;
        }
        Ok(())
    }
}

/// Load all collections from disk.  Missing or unreadable entries are skipped.
pub fn load_collections() -> Vec<StoredCollection> {
    let base = base_dir();
    if !base.exists() {
        return Vec::new();
    }
    let mut cols = Vec::new();
    let entries = match std::fs::read_dir(&base) {
        Ok(e) => e,
        Err(_) => return cols,
    };
    for entry in entries.flatten() {
        if is_internal_storage_dir(&entry.path()) {
            continue;
        }
        let col_json = entry.path().join("collection.json");
        if let Ok(data) = std::fs::read(&col_json) {
            if let Ok(col) = serde_json::from_slice::<StoredCollection>(&data) {
                cols.push(col);
            }
        }
    }
    cols
}

/// Load all items belonging to a collection.
pub fn load_items(collection_id: &str) -> Vec<StoredItem> {
    let dir = base_dir().join(collection_id);
    if !dir.exists() {
        return Vec::new();
    }
    let mut items = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return items,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.file_name().and_then(|n| n.to_str()) == Some("collection.json") {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Ok(data) = std::fs::read(&path) {
                if let Ok(item) = serde_json::from_slice::<StoredItem>(&data) {
                    items.push(item);
                }
            }
        }
    }
    items
}

pub fn base_dir() -> PathBuf {
    paths::secrets_dir()
}

pub fn remove_all_storage() -> Result<(), String> {
    let base = base_dir();
    if base.exists() {
        std::fs::remove_dir_all(&base)
            .map_err(|e| format!("Cannot remove {}: {e}", base.display()))?;
    }
    Ok(())
}
