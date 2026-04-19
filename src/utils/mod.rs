pub mod persistence;
pub mod template;
pub mod time;

use std::time::Duration;
use sysinfo::{Pid, System};
use std::fs;
use std::path::Path;

pub fn ensure_single_instance(pid_file: &str) -> anyhow::Result<()> {
    let path = Path::new(pid_file);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(old_pid_val) = content.trim().parse::<u32>() {
                let mut sys = System::new();
                let pid = Pid::from_u32(old_pid_val);
                sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
                
                if let Some(process) = sys.process(pid) {
                    let exe_name = process.name().to_string_lossy().to_lowercase();
                    if exe_name.contains("cloud-node") || exe_name.contains("rust") {
                        anyhow::bail!(
                            "Instance already running. PID: {}, Name: {}. Please kill it first.",
                            old_pid_val,
                            exe_name
                        );
                    }
                }
            }
        }
    }

    fs::write(path, std::process::id().to_string())?;
    Ok(())
}

pub fn to_duration(v: &serde_json::Value) -> Duration {
    if let Some(count) = v.get("count").and_then(|c| c.as_u64()) {
        let unit = v.get("unit").and_then(|u| u.as_str()).unwrap_or("s");
        let secs = match unit.to_lowercase().as_str() {
            "m" | "min" => count * 60,
            "h" | "hour" => count * 3600,
            "d" | "day" => count * 86400,
            _ => count,
        };
        return Duration::from_secs(secs);
    }
    Duration::from_secs(30)
}

pub fn fnv_hash64(s: &str) -> u64 {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;
    let mut hash = FNV_OFFSET;
    for byte in s.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}
