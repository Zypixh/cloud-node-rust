use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

static REPLICA_STATS: Lazy<dashmap::DashMap<String, ReplicaStatsSnapshot>> =
    Lazy::new(dashmap::DashMap::new);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicaStatsSnapshot {
    pub pod_name: String,
    pub seq: u64,
    pub created_at: i64,
    pub traffic_out: u64,
    pub traffic_in: u64,
    pub active_connections: i64,
    pub app_total_requests: u64,
    pub app_attack_requests: u64,
    pub rpc_total_requests: u64,
    pub rpc_total_errors: u64,
    pub rpc_total_cost_ms: u64,
    pub cache_count: usize,
    pub cache_bytes: u64,
    pub cpu_usage: f64,
    pub memory_total: i64,
    pub memory_used: i64,
}

#[derive(Clone, Debug, Default)]
pub struct AggregatedReplicaStats {
    pub replica_count: usize,
    pub traffic_out: u64,
    pub traffic_in: u64,
    pub active_connections: i64,
    pub app_total_requests: u64,
    pub app_attack_requests: u64,
    pub rpc_total_requests: u64,
    pub rpc_total_errors: u64,
    pub rpc_total_cost_ms: u64,
    pub cache_count: usize,
    pub cache_bytes: u64,
    pub cpu_usage_avg: f64,
    pub cpu_usage_max: f64,
    pub memory_total: i64,
    pub memory_used: i64,
}

pub fn start(runtime_config: &crate::runtime_mode::RuntimeConfig) {
    if !runtime_config.is_rke2() {
        return;
    }

    let config = runtime_config.clone();
    tokio::spawn(async move {
        let mut seq = 0_u64;
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            seq = seq.wrapping_add(1);
            if crate::cluster::leader::is_leader() {
                insert_snapshot(local_snapshot(seq));
            } else if let Err(err) = push_snapshot_to_peers(&config, local_snapshot(seq)).await {
                tracing::debug!("CLUSTER_STATS: follower snapshot push failed: {}", err);
            }
        }
    });
}

pub fn insert_snapshot(snapshot: ReplicaStatsSnapshot) {
    REPLICA_STATS.insert(snapshot.pod_name.clone(), snapshot);
}

pub fn aggregate() -> AggregatedReplicaStats {
    let now = crate::utils::time::now_timestamp();
    let mut by_pod: HashMap<String, ReplicaStatsSnapshot> = HashMap::new();
    for entry in REPLICA_STATS.iter() {
        if now - entry.value().created_at <= 30 {
            by_pod.insert(entry.key().clone(), entry.value().clone());
        }
    }

    let mut result = AggregatedReplicaStats {
        replica_count: by_pod.len(),
        ..Default::default()
    };
    let mut cpu_sum = 0.0;
    for snapshot in by_pod.values() {
        result.traffic_out = result.traffic_out.saturating_add(snapshot.traffic_out);
        result.traffic_in = result.traffic_in.saturating_add(snapshot.traffic_in);
        result.active_connections = result
            .active_connections
            .saturating_add(snapshot.active_connections);
        result.app_total_requests = result
            .app_total_requests
            .saturating_add(snapshot.app_total_requests);
        result.app_attack_requests = result
            .app_attack_requests
            .saturating_add(snapshot.app_attack_requests);
        result.rpc_total_requests = result
            .rpc_total_requests
            .saturating_add(snapshot.rpc_total_requests);
        result.rpc_total_errors = result
            .rpc_total_errors
            .saturating_add(snapshot.rpc_total_errors);
        result.rpc_total_cost_ms = result
            .rpc_total_cost_ms
            .saturating_add(snapshot.rpc_total_cost_ms);
        result.cache_count = result.cache_count.max(snapshot.cache_count);
        result.cache_bytes = result.cache_bytes.max(snapshot.cache_bytes);
        result.memory_total = result.memory_total.saturating_add(snapshot.memory_total);
        result.memory_used = result.memory_used.saturating_add(snapshot.memory_used);
        cpu_sum += snapshot.cpu_usage;
        result.cpu_usage_max = result.cpu_usage_max.max(snapshot.cpu_usage);
    }
    if result.replica_count > 0 {
        result.cpu_usage_avg = cpu_sum / result.replica_count as f64;
    }
    result
}

pub fn local_snapshot(seq: u64) -> ReplicaStatsSnapshot {
    let pod_name = crate::runtime_mode::RuntimeConfig::current()
        .and_then(|config| std::env::var(&config.cluster.pod_name_env).ok())
        .unwrap_or_else(|| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_default()
        });
    let (traffic_out, traffic_in, active_connections) = crate::metrics::METRICS.get_node_totals();
    let rpc = crate::metrics::METRICS.rpc.snapshot();
    let snapshots = crate::metrics::METRICS.take_snapshots();
    let app_total_requests = snapshots.iter().map(|s| s.1.total_requests).sum();
    let app_attack_requests = snapshots.iter().map(|s| s.1.count_attack_requests).sum();
    let (cache_count, cache_bytes) = crate::metrics::storage::STORAGE.cache_summary();
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    let (memory_total, memory_used) = process_memory_totals(&sys);
    ReplicaStatsSnapshot {
        pod_name,
        seq,
        created_at: crate::utils::time::now_timestamp(),
        traffic_out,
        traffic_in,
        active_connections,
        app_total_requests,
        app_attack_requests,
        rpc_total_requests: rpc.total_requests,
        rpc_total_errors: rpc.total_errors,
        rpc_total_cost_ms: rpc.total_cost_ms,
        cache_count,
        cache_bytes,
        cpu_usage: sys.global_cpu_usage() as f64 / 100.0,
        memory_total,
        memory_used,
    }
}

fn process_memory_totals(sys: &sysinfo::System) -> (i64, i64) {
    #[allow(unused_mut)]
    let mut total_memory = sys.total_memory() as i64;
    #[allow(unused_mut)]
    let mut used_memory = sys.used_memory() as i64;

    #[cfg(target_os = "linux")]
    {
        if let Ok(limit_str) =
            std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        {
            if let Ok(limit) = limit_str.trim().parse::<i64>() {
                if limit > 0 && limit < 1024 * 1024 * 1024 * 1024 {
                    total_memory = limit;
                    if let Ok(usage_str) =
                        std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes")
                    {
                        if let Ok(usage) = usage_str.trim().parse::<i64>() {
                            used_memory = usage;
                        }
                    }
                }
            }
        } else if let Ok(limit_str) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
            if let Ok(limit) = limit_str.trim().parse::<i64>() {
                if limit > 0 {
                    total_memory = limit;
                    if let Ok(usage_str) = std::fs::read_to_string("/sys/fs/cgroup/memory.current")
                    {
                        if let Ok(usage) = usage_str.trim().parse::<i64>() {
                            used_memory = usage;
                        }
                    }
                }
            }
        }
    }

    (total_memory, used_memory)
}

async fn push_snapshot_to_peers(
    config: &crate::runtime_mode::RuntimeConfig,
    snapshot: ReplicaStatsSnapshot,
) -> anyhow::Result<()> {
    let token = std::env::var(&config.cluster.internal_api.token_env)?;
    let peers = crate::cluster::peers::discover_peer_urls();
    if peers.is_empty() {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;
    let body = serde_json::to_vec(&snapshot)?;
    for peer in peers {
        let url = format!("{}/internal/v1/stats/snapshot", peer);
        let _ = client
            .post(url)
            .bearer_auth(token.trim())
            .header("content-type", "application/json")
            .header("x-cloud-node-cluster", &config.cluster.name)
            .body(body.clone())
            .send()
            .await;
    }
    Ok(())
}
