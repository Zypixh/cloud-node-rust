use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Default)]
pub struct PersistentState {
    pub config_version: i64,
    pub task_version: i64,
    pub deleted_content_version: i64,
    pub ocsp_version: i64,
}

pub fn load_state() -> PersistentState {
    let path = "../data/state.json";
    if Path::new(path).exists()
        && let Ok(content) = fs::read_to_string(path)
        && let Ok(state) = serde_json::from_str(&content)
    {
        return state;
    }
    PersistentState::default()
}

pub fn save_state(state: &PersistentState) {
    let _ = fs::create_dir_all("../data");
    if let Ok(content) = serde_json::to_string_pretty(state) {
        let _ = fs::write("../data/state.json", content);
    }
}

pub fn save_blocked_ips(ips: Vec<(String, i64, u64)>) {
    let _ = fs::create_dir_all("../data");
    if let Ok(content) = serde_json::to_string(&ips) {
        let _ = fs::write("../data/blocked_ips.json", content);
    }
}

pub fn load_blocked_ips() -> Vec<(String, i64, u64)> {
    let path = "../data/blocked_ips.json";
    if Path::new(path).exists()
        && let Ok(content) = fs::read_to_string(path)
        && let Ok(ips) = serde_json::from_str(&content)
    {
        return ips;
    }
    vec![]
}
