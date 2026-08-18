use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock as Lazy;
use std::sync::Mutex;
use std::time::Duration;
use tracing::{debug, warn};

const BLOCK_PREFIX: &str = "FWBLK_V1_";
const MIGRATED_LEGACY_JSON_KEY: &str = "FWBLK_META_migrated_blocked_ips_json";
const FLUSH_THRESHOLD: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallBlockRecord {
    pub target: String,
    pub server_id: i64,
    pub scope: String,
    pub source: String,
    pub reason: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub kernel_wanted: bool,
    pub kernel_applied: bool,
    pub kernel_status: String,
}

impl FirewallBlockRecord {
    pub fn runtime(
        target: String,
        server_id: i64,
        scope: String,
        expires_at: i64,
        kernel_wanted: bool,
    ) -> Self {
        let now = crate::utils::time::now_timestamp();
        Self {
            target,
            server_id,
            scope,
            source: "runtime".to_string(),
            reason: "local runtime block".to_string(),
            expires_at,
            created_at: now,
            updated_at: now,
            kernel_wanted,
            kernel_applied: false,
            kernel_status: if kernel_wanted {
                "pending".to_string()
            } else {
                "not_applicable".to_string()
            },
        }
    }

    fn legacy(target: String, server_id: i64, expires_at: i64) -> Self {
        let now = crate::utils::time::now_timestamp();
        let target = normalize_target(&target);
        let kernel_wanted = target.parse::<std::net::IpAddr>().is_ok();
        Self {
            target,
            server_id,
            scope: if server_id == 0 {
                "global".to_string()
            } else {
                "server".to_string()
            },
            source: "legacy_json".to_string(),
            reason: "legacy blocked_ips.json migration".to_string(),
            expires_at,
            created_at: now,
            updated_at: now,
            kernel_wanted,
            kernel_applied: false,
            kernel_status: if kernel_wanted {
                "pending".to_string()
            } else {
                "not_applicable".to_string()
            },
        }
    }

    pub fn key(&self) -> String {
        block_key(&self.scope, self.server_id, &self.target)
    }
}

enum PendingOp {
    Upsert(FirewallBlockRecord),
    Delete {
        scope: String,
        server_id: i64,
        target: String,
    },
}

#[derive(Default)]
struct PendingState {
    upserts: HashMap<String, FirewallBlockRecord>,
    deletes: HashSet<String>,
}

static PENDING: Lazy<Mutex<PendingState>> = Lazy::new(|| Mutex::new(PendingState::default()));

fn block_key(scope: &str, server_id: i64, target: &str) -> String {
    format!("{BLOCK_PREFIX}{scope}_{server_id}_{target}")
}

pub fn enqueue_upsert(record: FirewallBlockRecord) {
    enqueue(PendingOp::Upsert(record));
}

pub fn enqueue_delete(scope: &str, server_id: i64, target: &str) {
    enqueue(PendingOp::Delete {
        scope: scope.to_string(),
        server_id,
        target: target.to_string(),
    });
}

fn enqueue(op: PendingOp) {
    let should_flush = {
        let Ok(mut pending) = PENDING.lock() else {
            return;
        };
        match op {
            PendingOp::Upsert(record) => {
                let key = record.key();
                pending.deletes.remove(&key);
                pending.upserts.insert(key, record);
            }
            PendingOp::Delete {
                scope,
                server_id,
                target,
            } => {
                let key = block_key(&scope, server_id, &target);
                pending.upserts.remove(&key);
                pending.deletes.insert(key);
            }
        }
        pending.upserts.len() + pending.deletes.len() >= FLUSH_THRESHOLD
    };
    if should_flush {
        let _ = flush_pending();
    }
}

pub fn flush_pending() -> bool {
    let (upserts, deletes) = {
        let Ok(mut pending) = PENDING.lock() else {
            return false;
        };
        if pending.upserts.is_empty() && pending.deletes.is_empty() {
            return true;
        }
        let upserts = std::mem::take(&mut pending.upserts);
        let deletes = std::mem::take(&mut pending.deletes);
        (upserts, deletes)
    };

    let upsert_records = upserts.into_iter().collect::<Vec<_>>();
    let delete_records = deletes.into_iter().collect::<Vec<_>>();

    let mut puts = Vec::with_capacity(upsert_records.len());
    for (key, record) in &upsert_records {
        match serde_json::to_vec(&record) {
            Ok(bytes) => puts.push((key.clone(), bytes)),
            Err(err) => warn!("failed to serialize firewall block record: {}", err),
        }
    }
    let ok = crate::metrics::storage::STORAGE.write_raw_batch(puts, delete_records.clone());
    if !ok {
        warn!("failed to flush firewall block records to Mace");
        if let Ok(mut pending) = PENDING.lock() {
            for (key, record) in upsert_records {
                if !pending.deletes.contains(&key) {
                    pending.upserts.insert(key, record);
                }
            }
            for key in delete_records {
                pending.upserts.remove(&key);
                pending.deletes.insert(key);
            }
        }
    }
    ok
}

pub fn start_flush_task() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(err) = tokio::task::spawn_blocking(flush_pending).await {
                warn!(error = %err, "firewall persistence worker failed");
            }
        }
    });
}

pub fn load_active_runtime_blocks(now: i64) -> Vec<FirewallBlockRecord> {
    crate::metrics::storage::STORAGE
        .scan_json_prefix::<FirewallBlockRecord>(BLOCK_PREFIX)
        .into_iter()
        .filter_map(|(_, record)| {
            (record.expires_at > now && is_runtime_source(&record.source)).then_some(record)
        })
        .collect()
}

pub fn load_active_blacklist_records(now: i64) -> Vec<FirewallBlockRecord> {
    crate::metrics::storage::STORAGE
        .scan_json_prefix::<FirewallBlockRecord>(BLOCK_PREFIX)
        .into_iter()
        .filter_map(|(_, record)| (record.expires_at > now).then_some(record))
        .collect()
}

pub fn cleanup_expired(now: i64) -> usize {
    let expired = crate::metrics::storage::STORAGE
        .scan_json_prefix::<FirewallBlockRecord>(BLOCK_PREFIX)
        .into_iter()
        .filter_map(|(key, record)| (record.expires_at <= now).then_some(key))
        .collect::<Vec<_>>();
    let count = expired.len();
    if count > 0 {
        let _ = crate::metrics::storage::STORAGE.write_raw_batch(Vec::new(), expired);
    }
    count
}

pub fn migrate_legacy_blocked_ips_once() -> usize {
    if crate::metrics::storage::STORAGE
        .get_json::<bool>(MIGRATED_LEGACY_JSON_KEY)
        .unwrap_or(false)
    {
        let _ = remove_legacy_blocked_ips_files();
        return 0;
    }

    let now = crate::utils::time::now_timestamp();
    let mut records = HashMap::<String, FirewallBlockRecord>::new();
    for (target, server_id, expiry) in crate::utils::persistence::load_blocked_ips() {
        if expiry <= now as u64 {
            continue;
        }
        let record = FirewallBlockRecord::legacy(target, server_id, expiry as i64);
        records.insert(record.key(), record);
    }

    let mut puts = Vec::with_capacity(records.len() + 1);
    for (key, record) in records {
        if let Ok(bytes) = serde_json::to_vec(&record) {
            puts.push((key, bytes));
        }
    }
    if let Ok(bytes) = serde_json::to_vec(&true) {
        puts.push((MIGRATED_LEGACY_JSON_KEY.to_string(), bytes));
    }
    let migrated = puts.len().saturating_sub(1);
    if crate::metrics::storage::STORAGE.write_raw_batch(puts, Vec::new()) {
        if migrated > 0 {
            debug!("migrated {} legacy blocked IP records to Mace", migrated);
        }
        let removed_files = remove_legacy_blocked_ips_files();
        if removed_files > 0 {
            debug!(
                "removed {} legacy blocked_ips.json migration input files",
                removed_files
            );
        }
        migrated
    } else {
        warn!("failed to mark legacy blocked_ips.json migration");
        0
    }
}

fn is_runtime_source(source: &str) -> bool {
    matches!(source, "runtime" | "legacy_json")
}

fn normalize_target(target: &str) -> String {
    let target = target.trim();
    if let Ok(net) = target.parse::<ipnet::IpNet>() {
        return net.trunc().to_string();
    }
    target.to_string()
}

fn remove_legacy_blocked_ips_files() -> usize {
    let node_paths = crate::paths::NodePaths::current();
    let mut removed = 0usize;
    let mut seen = BTreeSet::new();
    for path in node_paths.blocked_ips_file_candidates() {
        if !seen.insert(path.clone()) || !path.exists() {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {
                removed += 1;
            }
            Err(err) => {
                warn!(
                    "failed to remove legacy blocked IP snapshot {}: {}",
                    path.display(),
                    err
                );
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_persistence_record_key_uses_fixed_namespace() {
        let record = FirewallBlockRecord::runtime(
            "192.0.2.1".to_string(),
            42,
            "server".to_string(),
            99,
            true,
        );
        assert_eq!(record.key(), "FWBLK_V1_server_42_192.0.2.1");
    }
}
