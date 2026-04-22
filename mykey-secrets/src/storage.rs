// storage.rs — On-disk storage for Secret Service collections and items.
//
// Secrets are stored as TPM2-sealed blobs under the user's MyKey data dir.
// Layout:
//   $XDG_DATA_HOME/mykey/secrets/<collection_id>/collection.json
//   $XDG_DATA_HOME/mykey/secrets/<collection_id>/<item_id>.json
// Fallback:
//   ~/.local/share/mykey/secrets/<collection_id>/...

use std::collections::HashMap;
use log::warn;
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::paths;

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

fn write_atomic(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| {
        format!("Cannot determine parent directory for {}", path.display())
    })?;
    paths::ensure_private_dir(parent)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("write"),
        std::process::id(),
        nanos
    ));
    #[cfg(unix)]
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("Cannot open {}: {e}", tmp.display()))?;

    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)
        .map_err(|e| format!("Cannot open {}: {e}", tmp.display()))?;

    use std::io::Write as _;
    file.write_all(data)
        .map_err(|e| format!("Cannot write {}: {e}", tmp.display()))?;

    #[cfg(unix)]
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Cannot secure {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("Cannot move {} into place: {e}", path.display()))
}

/// Load all collections from disk.  Missing or unreadable entries are skipped.
pub fn load_collections() -> Vec<StoredCollection> {
    let base = paths::secrets_dir();
    if !base.exists() {
        return Vec::new();
    }
    let mut cols = Vec::new();
    let entries = match std::fs::read_dir(&base) {
        Ok(e) => e,
        Err(e) => {
            warn!("[storage] Cannot read collections dir {}: {e}", base.display());
            return cols;
        }
    };
    for entry in entries.flatten() {
        let col_json = entry.path().join("collection.json");
        match std::fs::read(&col_json) {
            Ok(data) => match serde_json::from_slice::<StoredCollection>(&data) {
                Ok(col) => cols.push(col),
                Err(e) => warn!("[storage] Skipping malformed collection {}: {e}", col_json.display()),
            },
            Err(e) => warn!("[storage] Skipping unreadable collection {}: {e}", col_json.display()),
        }
    }
    cols
}

pub fn load_collection(collection_id: &str) -> Option<StoredCollection> {
    let path = paths::secrets_dir().join(collection_id).join("collection.json");
    let data = std::fs::read(path).ok()?;
    serde_json::from_slice::<StoredCollection>(&data).ok()
}

/// Persist a collection's metadata to disk.
pub fn save_collection(c: &StoredCollection) -> Result<(), String> {
    let dir = paths::secrets_dir().join(&c.id);
    paths::ensure_private_dir(&dir)?;
    let path = dir.join("collection.json");
    let data = serde_json::to_vec_pretty(c)
        .map_err(|e| format!("Cannot serialise collection: {e}"))?;
    write_atomic(&path, &data)
}

/// Load all items belonging to a collection.
pub fn load_items(collection_id: &str) -> Vec<StoredItem> {
    let dir = paths::secrets_dir().join(collection_id);
    if !dir.exists() {
        return Vec::new();
    }
    let mut items = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("[storage] Cannot read items dir {}: {e}", dir.display());
            return items;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.file_name().and_then(|n| n.to_str()) == Some("collection.json") {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            match std::fs::read(&path) {
                Ok(data) => match serde_json::from_slice::<StoredItem>(&data) {
                    Ok(item) => items.push(item),
                    Err(e) => warn!("[storage] Skipping malformed item {}: {e}", path.display()),
                },
                Err(e) => warn!("[storage] Skipping unreadable item {}: {e}", path.display()),
            }
        }
    }
    items
}

pub fn load_item(collection_id: &str, item_id: &str) -> Option<StoredItem> {
    let path = paths::secrets_dir()
        .join(collection_id)
        .join(format!("{item_id}.json"));
    let data = std::fs::read(path).ok()?;
    serde_json::from_slice::<StoredItem>(&data).ok()
}

/// Persist an item to disk.
pub fn save_item(item: &StoredItem) -> Result<(), String> {
    let dir = paths::secrets_dir().join(&item.collection_id);
    paths::ensure_private_dir(&dir)?;
    let path = dir.join(format!("{}.json", item.id));
    let data = serde_json::to_vec_pretty(item)
        .map_err(|e| format!("Cannot serialise item: {e}"))?;
    write_atomic(&path, &data)
}

pub fn update_collection_modified(collection_id: &str, modified: u64) -> Result<(), String> {
    let mut collection = load_collection(collection_id)
        .ok_or_else(|| format!("Collection {collection_id} not found"))?;
    collection.modified = modified;
    save_collection(&collection)
}

/// Delete an item from disk.
pub fn delete_item(collection_id: &str, item_id: &str) -> Result<(), String> {
    let path = paths::secrets_dir()
        .join(collection_id)
        .join(format!("{item_id}.json"));
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Cannot delete {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Delete the entire collection directory from disk.
pub fn delete_collection_dir(collection_id: &str) -> Result<(), String> {
    let dir = paths::secrets_dir().join(collection_id);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .map_err(|e| format!("Cannot delete collection dir {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// Load alias mappings from disk.  Returns an empty map if the file is absent.
pub fn load_aliases() -> HashMap<String, String> {
    let path = paths::aliases_file();
    if !path.exists() {
        return HashMap::new();
    }
    match std::fs::read(&path) {
        Ok(data) => match serde_json::from_slice::<HashMap<String, String>>(&data) {
            Ok(aliases) => aliases,
            Err(e) => {
                warn!("[storage] Could not parse aliases file {}: {e}", path.display());
                HashMap::new()
            }
        },
        Err(e) => {
            warn!("[storage] Could not read aliases file {}: {e}", path.display());
            HashMap::new()
        }
    }
}

/// Persist alias mappings to disk as a JSON object.
pub fn save_aliases(aliases: &HashMap<String, String>) -> Result<(), String> {
    let path = paths::aliases_file();
    if let Some(parent) = path.parent() {
        paths::ensure_private_dir(parent)?;
    }
    let data = serde_json::to_vec_pretty(aliases)
        .map_err(|e| format!("Cannot serialise aliases: {e}"))?;
    write_atomic(&path, &data)
}
