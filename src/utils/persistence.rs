use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Default)]
pub struct PersistentState {
    pub config_version: i64,
    pub task_version: i64,
    pub deleted_content_version: i64,
    pub ocsp_version: i64,
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

pub fn save_state(state: &PersistentState) {
    let node_paths = crate::paths::NodePaths::current();
    let _ = fs::create_dir_all(node_paths.data_dir());
    if let Ok(content) = serde_json::to_string_pretty(state) {
        atomic_write(&node_paths.state_file(), content.as_bytes());
    }
}

pub fn save_blocked_ips(ips: Vec<(String, i64, u64)>) {
    let node_paths = crate::paths::NodePaths::current();
    let _ = fs::create_dir_all(node_paths.data_dir());
    if let Ok(content) = serde_json::to_string(&ips) {
        atomic_write(&node_paths.blocked_ips_file(), content.as_bytes());
    }
}

// Crash-safe write: dump to a sibling `*.tmp` first, fsync, then rename.
// A torn write leaves the previous file intact instead of an empty/corrupt one.
fn atomic_write(path: &std::path::Path, data: &[u8]) {
    let tmp = match path.file_name() {
        Some(name) => {
            let mut buf = std::ffi::OsString::from(name);
            buf.push(".tmp");
            path.with_file_name(buf)
        }
        None => return,
    };
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    let Ok(mut file) = opts.open(&tmp) else {
        return;
    };
    use std::io::Write;
    if file.write_all(data).is_err() {
        let _ = fs::remove_file(&tmp);
        return;
    }
    if file.sync_all().is_err() {
        let _ = fs::remove_file(&tmp);
        return;
    }
    drop(file);
    let _ = fs::rename(&tmp, path);
}

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
