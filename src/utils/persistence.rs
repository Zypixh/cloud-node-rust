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
        let _ = fs::write(node_paths.state_file(), content);
    }
}

pub fn save_blocked_ips(ips: Vec<(String, i64, u64)>) {
    let node_paths = crate::paths::NodePaths::current();
    let _ = fs::create_dir_all(node_paths.data_dir());
    if let Ok(content) = serde_json::to_string(&ips) {
        let _ = fs::write(node_paths.blocked_ips_file(), content);
    }
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
