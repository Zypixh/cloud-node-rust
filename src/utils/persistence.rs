use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::{Mutex, OnceLock};

static PERSISTENCE_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Serialize, Deserialize, Default)]
pub struct PersistentState {
    pub config_version: i64,
    pub task_version: i64,
    pub deleted_content_version: i64,
    pub ocsp_version: i64,
    #[serde(default)]
    pub geoip_city_file_id: i64,
    #[serde(default)]
    pub geoip_city_file_size: u64,
    #[serde(default)]
    pub geoip_city_sha256: String,
}

pub fn load_state() -> PersistentState {
    let node_paths = crate::paths::NodePaths::current();
    for path in node_paths.state_file_candidates() {
        if path.exists()
            && let Ok(content) = fs::read_to_string(&path)
            && let Ok(state) = serde_json::from_str(&content)
        {
            return state;
        }
    }
    PersistentState::default()
}

pub fn save_state(state: &PersistentState) -> std::io::Result<()> {
    let node_paths = crate::paths::NodePaths::current();
    fs::create_dir_all(node_paths.data_dir())?;
    let content = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    atomic_write(&node_paths.state_file(), &content)
}

/// Legacy compatibility writer for pre-Mace firewall snapshots.
///
/// Runtime firewall state is persisted through `firewall::persistence`; new
/// code should not call this as the source of truth.
pub fn save_blocked_ips(ips: Vec<(String, i64, u64)>) {
    let node_paths = crate::paths::NodePaths::current();
    let _ = fs::create_dir_all(node_paths.data_dir());
    if let Ok(content) = serde_json::to_string(&ips) {
        let _ = atomic_write(&node_paths.blocked_ips_file(), content.as_bytes());
    }
}

// Crash-safe write: dump to a sibling `*.tmp` first, fsync, then rename.
// A torn write leaves the previous file intact instead of an empty/corrupt one.
pub fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let _guard = PERSISTENCE_WRITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp_name = std::ffi::OsString::from(name);
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    let mut file = opts.open(&tmp)?;
    use std::io::Write;
    if let Err(err) = file.write_all(data).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    drop(file);
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    sync_parent(path)
}

pub fn sync_parent(path: &std::path::Path) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    fs::File::open(parent)?.sync_all()
}

/// Legacy compatibility reader used by the one-time firewall migration.
pub fn load_blocked_ips() -> Vec<(String, i64, u64)> {
    let node_paths = crate::paths::NodePaths::current();
    for path in node_paths.blocked_ips_file_candidates() {
        if path.exists()
            && let Ok(content) = fs::read_to_string(&path)
            && let Ok(ips) = serde_json::from_str(&content)
        {
            return ips;
        }
    }
    vec![]
}
