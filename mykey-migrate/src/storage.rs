// storage.rs — On-disk storage for Secret Service collections and items.
//
// Secrets are stored as TPM2-sealed blobs under the user's MyKey data dir.
// Layout:
//   $XDG_DATA_HOME/mykey/secrets/<collection_id>/collection.json
//   $XDG_DATA_HOME/mykey/secrets/<collection_id>/<item_id>.json
// Fallback:
//   ~/.local/share/mykey/secrets/<collection_id>/...

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
    let data =
        serde_json::to_vec_pretty(c).map_err(|e| format!("Cannot serialise collection: {e}"))?;
    paths::write_private_file(&path, &data)
}

fn save_item_in(base_dir: &Path, item: &StoredItem) -> Result<(), String> {
    let dir = base_dir.join(&item.collection_id);
    paths::ensure_private_dir(&dir)?;
    let path = dir.join(format!("{}.json", item.id));
    let data =
        serde_json::to_vec_pretty(item).map_err(|e| format!("Cannot serialise item: {e}"))?;
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

#[derive(Debug, Clone)]
pub struct StorageAuditIssue {
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct StorageAudit {
    pub base_dir: PathBuf,
    pub raw_collection_dirs: usize,
    pub raw_item_files: usize,
    pub parsed_collections: Vec<StoredCollection>,
    pub parsed_items: Vec<StoredItem>,
    pub issues: Vec<StorageAuditIssue>,
}

impl StorageAudit {
    pub fn parsed_item_count(&self) -> usize {
        self.parsed_items.len()
    }

    pub fn raw_entry_count(&self) -> usize {
        self.raw_collection_dirs + self.raw_item_files
    }

    pub fn is_legitimate_empty(&self) -> bool {
        self.raw_entry_count() == 0 && self.issues.is_empty()
    }

    pub fn is_suspicious_empty(&self) -> bool {
        self.parsed_items.is_empty() && (self.raw_entry_count() > 0 || !self.issues.is_empty())
    }
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
            let entry = entry
                .map_err(|e| format!("Cannot read staged entry in {}: {e}", self.path.display()))?;
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

        std::fs::remove_dir(&self.path).map_err(|e| {
            format!(
                "Cannot remove empty staging dir {}: {e}",
                self.path.display()
            )
        })?;

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
                    format!(
                        "Cannot read active storage entry in {}: {e}",
                        base.display()
                    )
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

pub fn audit_storage() -> StorageAudit {
    let base = base_dir();
    let mut audit = StorageAudit {
        base_dir: base.clone(),
        raw_collection_dirs: 0,
        raw_item_files: 0,
        parsed_collections: Vec::new(),
        parsed_items: Vec::new(),
        issues: Vec::new(),
    };

    if !base.exists() {
        return audit;
    }

    let entries = match std::fs::read_dir(&base) {
        Ok(entries) => entries,
        Err(e) => {
            audit.issues.push(StorageAuditIssue {
                path: base,
                message: format!("Cannot list storage directory: {e}"),
            });
            return audit;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                audit.issues.push(StorageAuditIssue {
                    path: base.clone(),
                    message: format!("Cannot read storage directory entry: {e}"),
                });
                continue;
            }
        };
        let path = entry.path();
        if is_internal_storage_dir(&path) {
            continue;
        }
        if !path.is_dir() {
            audit.issues.push(StorageAuditIssue {
                path,
                message: "Unexpected non-directory entry in MyKey secrets storage".to_string(),
            });
            continue;
        }

        audit.raw_collection_dirs += 1;

        let col_json = path.join("collection.json");
        let collection = match std::fs::read(&col_json) {
            Ok(data) => match serde_json::from_slice::<StoredCollection>(&data) {
                Ok(collection) => collection,
                Err(e) => {
                    audit.issues.push(StorageAuditIssue {
                        path: col_json,
                        message: format!("Cannot parse collection metadata: {e}"),
                    });
                    continue;
                }
            },
            Err(e) => {
                audit.issues.push(StorageAuditIssue {
                    path: col_json,
                    message: format!("Cannot read collection metadata: {e}"),
                });
                continue;
            }
        };

        let collection_id = collection.id.clone();
        audit.parsed_collections.push(collection);

        let item_entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(e) => {
                audit.issues.push(StorageAuditIssue {
                    path,
                    message: format!("Cannot list collection directory: {e}"),
                });
                continue;
            }
        };

        for item_entry in item_entries {
            let item_entry = match item_entry {
                Ok(entry) => entry,
                Err(e) => {
                    audit.issues.push(StorageAuditIssue {
                        path: path.clone(),
                        message: format!("Cannot read collection directory entry: {e}"),
                    });
                    continue;
                }
            };
            let item_path = item_entry.path();
            if item_path.file_name().and_then(|n| n.to_str()) == Some("collection.json") {
                continue;
            }
            if item_path.extension().and_then(|e| e.to_str()) != Some("json") {
                audit.issues.push(StorageAuditIssue {
                    path: item_path,
                    message: "Unexpected non-JSON entry in collection directory".to_string(),
                });
                continue;
            }

            audit.raw_item_files += 1;

            match std::fs::read(&item_path) {
                Ok(data) => match serde_json::from_slice::<StoredItem>(&data) {
                    Ok(item) => {
                        if item.collection_id != collection_id {
                            audit.issues.push(StorageAuditIssue {
                                path: item_path,
                                message: format!(
                                    "Item collection_id '{}' does not match directory collection_id '{}'",
                                    item.collection_id, collection_id
                                ),
                            });
                        } else {
                            audit.parsed_items.push(item);
                        }
                    }
                    Err(e) => {
                        audit.issues.push(StorageAuditIssue {
                            path: item_path,
                            message: format!("Cannot parse item: {e}"),
                        });
                    }
                },
                Err(e) => {
                    audit.issues.push(StorageAuditIssue {
                        path: item_path,
                        message: format!("Cannot read item: {e}"),
                    });
                }
            }
        }
    }

    audit
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
