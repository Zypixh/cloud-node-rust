//! Bounded website/config apply path.
//!
//! The control plane still delivers a full `servers` snapshot as one JSON blob.
//! This module is responsible for turning that snapshot into runtime maps without
//! cloning `ServerConfig` bodies per hostname, without keeping extra full copies
//! alive, and without rebuilding every derived index when only a few sites change.
//!
//! Under memory pressure the apply path:
//! - admits as `BackgroundWork` (backpressure, not a silent drop)
//! - reclaims cache/resident state between chunks
//! - yields so request workers can run
//! - keeps one `Arc<ServerConfig>` per site shared by host indexes

use crate::config::ConfigStore;
use crate::config_models::{GlobalHTTPAllConfig, ParentNodeConfig, ServerConfig};
use crate::health_manager::GlobalHealthManager;
use crate::memory_governor::{AdmissionClass, MEMORY_GOVERNOR, MemoryPressureLevel};
use crate::memory_reclaim::reclaim_for_level;
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MIN_DECODE_BUDGET_BYTES: u64 = 16 * 1024 * 1024;
const CONFIG_SYNC_RETRY_LIMIT: u32 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigApplyLimits {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub pressure: MemoryPressureLevel,
}

impl ConfigApplyLimits {
    pub fn from_governor() -> Self {
        let snapshot = MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads());
        Self {
            total_bytes: snapshot.memory_total_bytes,
            available_bytes: snapshot.memory_available_bytes,
            pressure: snapshot.memory_pressure_level,
        }
    }

    /// In-process governor budget used by tests and by production when the
    /// live snapshot has already been read. `available_bytes` is the working
    /// set the apply path must stay inside — not a cgroup kill switch.
    pub fn synthetic(total_bytes: u64, available_bytes: u64) -> Self {
        Self {
            total_bytes,
            available_bytes,
            pressure: pressure_from_budget(total_bytes, available_bytes),
        }
    }

    pub fn decode_budget_bytes(self) -> u64 {
        let reserve = self.total_bytes.saturating_div(10).max(8 * 1024 * 1024);
        let from_available = self
            .available_bytes
            .saturating_mul(60)
            .saturating_div(100)
            .max(MIN_DECODE_BUDGET_BYTES);
        from_available.min(
            self.available_bytes
                .saturating_sub(reserve)
                .max(MIN_DECODE_BUDGET_BYTES),
        )
    }

    pub fn server_chunk_size(self) -> usize {
        match self.pressure {
            MemoryPressureLevel::Normal => 256,
            MemoryPressureLevel::Elevated => 64,
            MemoryPressureLevel::High => 16,
            MemoryPressureLevel::Critical => 4,
        }
        .max(1)
    }

    pub fn should_reclaim(self) -> bool {
        self.pressure >= MemoryPressureLevel::Elevated
    }

    /// High/Critical snapshots must not keep the previous site generation in
    /// RSS while the next generation is materialized (2x servers + LBs + plans).
    pub fn drop_previous_generation(self) -> bool {
        self.pressure >= MemoryPressureLevel::High
    }
}

pub fn pressure_from_budget(total_bytes: u64, available_bytes: u64) -> MemoryPressureLevel {
    if available_bytes <= total_bytes / 50 || available_bytes <= 64 * 1024 * 1024 {
        MemoryPressureLevel::Critical
    } else if available_bytes < total_bytes / 10 {
        MemoryPressureLevel::High
    } else if available_bytes < total_bytes / 5 {
        MemoryPressureLevel::Elevated
    } else {
        MemoryPressureLevel::Normal
    }
}

#[derive(Clone, Debug, Default)]
pub struct ConfigApplyStats {
    pub servers_in: usize,
    pub servers_indexed: usize,
    pub hosts_indexed: usize,
    pub chunks: usize,
    pub reclaim_runs: usize,
    pub admission_retries: u32,
    pub admitted: bool,
    pub elapsed: Duration,
    pub json_bytes: u64,
    pub released_previous_generation: bool,
}

#[derive(Clone, Default)]
pub struct RuntimeServerMaps {
    pub all_servers: Vec<Arc<ServerConfig>>,
    pub servers: HashMap<String, Arc<ServerConfig>>,
    pub routes: HashMap<String, Arc<crate::lb_factory::AnyLoadBalancer>>,
    pub id_to_lb: HashMap<i64, Arc<crate::lb_factory::AnyLoadBalancer>>,
    pub stats: ConfigApplyStats,
}

struct HashingReader<R> {
    inner: R,
    ctx: md5_legacy::Context,
    bytes: u64,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.ctx.consume(&buf[..n]);
            self.bytes = self.bytes.saturating_add(n as u64);
        }
        Ok(n)
    }
}

/// Parse a node JSON snapshot while hashing the decoded bytes. Callers should
/// drop the input buffer immediately after this returns so the parsed payload
/// is the only remaining copy.
pub fn parse_node_config_json(
    json: &[u8],
) -> Result<(crate::config_models::NodeConfigPayload, String, u64), serde_json::Error> {
    let hash = format!("{:x}", md5_legacy::compute(json));
    let payload = serde_json::from_slice(json)?;
    Ok((payload, hash, json.len() as u64))
}

/// Stream-parse compressed (or otherwise unread) node JSON so the decompressed
/// buffer is never fully materialized next to the parsed structs.
pub fn parse_node_config_from_reader<R: Read>(
    reader: R,
) -> Result<(crate::config_models::NodeConfigPayload, String, u64), serde_json::Error> {
    let mut reader = HashingReader {
        inner: reader,
        ctx: md5_legacy::Context::new(),
        bytes: 0,
    };
    let payload = serde_json::from_reader(&mut reader)?;
    let hash = format!("{:x}", reader.ctx.finalize());
    Ok((payload, hash, reader.bytes))
}

pub fn hash_waf_snapshot(
    firewall_policies: &[crate::config_models::HTTPFirewallPolicy],
    waf_actions: &[crate::config_models::WAFActionConfig],
) -> String {
    format!(
        "{:x}",
        md5_legacy::compute(
            serde_json::to_string(&(firewall_policies, waf_actions)).unwrap_or_default()
        )
    )
}

async fn admit_config_sync() -> (Option<crate::memory_governor::StaticAdmissionPermit>, u32) {
    let mut retries = 0u32;
    for attempt in 0..CONFIG_SYNC_RETRY_LIMIT {
        if let Some(permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::BackgroundWork) {
            return (Some(permit), retries);
        }
        retries = attempt + 1;
        let pressure = MEMORY_GOVERNOR.current_memory_pressure_level();
        if pressure >= MemoryPressureLevel::Elevated {
            reclaim_for_level(pressure);
        }
        tokio::task::yield_now().await;
    }
    (None, retries)
}

fn maybe_reclaim(
    limits: ConfigApplyLimits,
    stats: &mut ConfigApplyStats,
    last_reclaimed: &mut MemoryPressureLevel,
) {
    let live = MEMORY_GOVERNOR.current_memory_pressure_level();
    let pressure = limits.pressure.max(live);
    if pressure < MemoryPressureLevel::Elevated {
        return;
    }
    // One cache/resident teardown per apply (or when live pressure rises).
    // Rebuilding L1/Bloom on every chunk spikes RSS and stalls the snapshot.
    if stats.reclaim_runs > 0 && pressure <= *last_reclaimed {
        return;
    }
    reclaim_for_level(pressure);
    stats.reclaim_runs = stats.reclaim_runs.saturating_add(1);
    *last_reclaimed = pressure;
}

/// Inputs required to turn a full website snapshot into runtime host/LB maps.
pub struct MaterializeRuntimeServersArgs<'a> {
    pub servers: Vec<ServerConfig>,
    pub health_manager: &'a GlobalHealthManager,
    pub node_level: i32,
    pub parent_nodes: Arc<HashMap<i64, Vec<ParentNodeConfig>>>,
    pub tiered_origin_bypass: bool,
    pub allow_lan: bool,
    pub global_http: Option<Arc<GlobalHTTPAllConfig>>,
    pub limits: ConfigApplyLimits,
}

/// Build host/LB maps from an owned server list.
///
/// Each `ServerConfig` is wrapped in `Arc` exactly once. Host indexes clone the
/// `Arc`, not the config body. Disabled servers stay in `all_servers` so SSL
/// collection and compiled plans still see them, matching historical snapshot
/// semantics, but they are omitted from request routing maps.
pub async fn materialize_runtime_servers(
    args: MaterializeRuntimeServersArgs<'_>,
) -> RuntimeServerMaps {
    let MaterializeRuntimeServersArgs {
        servers,
        health_manager,
        node_level,
        parent_nodes,
        tiered_origin_bypass,
        allow_lan,
        global_http,
        limits,
    } = args;
    let started = Instant::now();
    let (permit, admission_retries) = admit_config_sync().await;
    let mut stats = ConfigApplyStats {
        servers_in: servers.len(),
        admitted: permit.is_some(),
        admission_retries,
        ..ConfigApplyStats::default()
    };
    let _permit = permit;
    let mut last_reclaimed = MemoryPressureLevel::Normal;
    maybe_reclaim(limits, &mut stats, &mut last_reclaimed);

    let chunk = limits.server_chunk_size();
    let mut all_servers = Vec::with_capacity(servers.len());
    let mut host_servers = HashMap::new();
    let mut routes = HashMap::new();
    let mut id_to_lb = HashMap::new();

    for (index, server) in servers.into_iter().enumerate() {
        if index > 0 && index % chunk == 0 {
            stats.chunks = stats.chunks.saturating_add(1);
            maybe_reclaim(limits, &mut stats, &mut last_reclaimed);
            tokio::task::yield_now().await;
        }

        server.compile_url_patterns();
        let server_id = server.numeric_id();
        let is_on = server.is_on;
        let server_arc = Arc::new(server);
        all_servers.push(Arc::clone(&server_arc));

        if !is_on {
            continue;
        }

        let (lb_arc, has_hc) = if let Some(rp) = &server_arc.reverse_proxy {
            crate::lb_factory::build_lb_with_global_http(
                server_id,
                rp,
                node_level,
                parent_nodes.as_ref(),
                tiered_origin_bypass,
                allow_lan,
                global_http.as_deref(),
            )
        } else {
            crate::rpc::utils::fallback_runtime_lb()
        };

        if server_id > 0 {
            id_to_lb.insert(server_id, Arc::clone(&lb_arc));
            if has_hc {
                let frequency = std::time::Duration::from_secs(30);
                if limits.drop_previous_generation() {
                    health_manager.register_deferred(server_id, Arc::clone(&lb_arc), frequency);
                } else {
                    health_manager.register(server_id, Arc::clone(&lb_arc), frequency);
                }
            }
        }

        let names = crate::rpc::utils::server_runtime_names(&server_arc);
        if names.is_empty() {
            let synthetic = format!("__id_{}", server_arc.numeric_id());
            host_servers.insert(synthetic.clone(), Arc::clone(&server_arc));
            routes.insert(synthetic, lb_arc);
            stats.hosts_indexed = stats.hosts_indexed.saturating_add(1);
        } else {
            for name in names {
                host_servers.insert(name.clone(), Arc::clone(&server_arc));
                routes.insert(name, Arc::clone(&lb_arc));
                stats.hosts_indexed = stats.hosts_indexed.saturating_add(1);
            }
        }
        stats.servers_indexed = stats.servers_indexed.saturating_add(1);
    }

    stats.chunks = stats.chunks.saturating_add(1);
    stats.elapsed = started.elapsed();
    tracing::info!(
        target: "config_apply",
        servers_in = stats.servers_in,
        servers_indexed = stats.servers_indexed,
        hosts_indexed = stats.hosts_indexed,
        chunks = stats.chunks,
        reclaim_runs = stats.reclaim_runs,
        admitted = stats.admitted,
        admission_retries = stats.admission_retries,
        elapsed_ms = stats.elapsed.as_millis() as u64,
        pressure = limits.pressure.as_str(),
        available_bytes = limits.available_bytes,
        "config apply materialized runtime server maps"
    );

    RuntimeServerMaps {
        all_servers,
        servers: host_servers,
        routes,
        id_to_lb,
        stats,
    }
}

/// Drop the currently installed site generation (maps, compiled plans, LBs)
/// before materializing a replacement snapshot. Callers must only do this
/// under High/Critical pressure — it briefly makes new host lookups miss.
pub fn drop_previous_server_generation(store: &ConfigStore, health_manager: &GlobalHealthManager) {
    health_manager.unregister_all();
    store.release_server_runtime_for_reload();
}

/// Apply a full site snapshot onto `store`, replacing previous servers while
/// keeping unrelated global fields. Used by tests and by incremental RPC
/// helpers that already parsed `Vec<ServerConfig>`.
pub async fn apply_server_snapshot(
    store: &ConfigStore,
    health_manager: &GlobalHealthManager,
    servers: Vec<ServerConfig>,
    limits: ConfigApplyLimits,
) -> RuntimeServerMaps {
    let released = limits.drop_previous_generation();
    if released {
        drop_previous_server_generation(store, health_manager);
    }
    let (node_level, parent_nodes, tiered_origin_bypass, allow_lan) =
        store.get_origin_runtime_context().await;
    let global_http = Some(store.get_global_http_config_sync());
    let mut maps = materialize_runtime_servers(MaterializeRuntimeServersArgs {
        servers,
        health_manager,
        node_level,
        parent_nodes,
        tiered_origin_bypass,
        allow_lan,
        global_http,
        limits,
    })
    .await;
    maps.stats.released_previous_generation = released;
    store
        .replace_all_servers(
            maps.all_servers.clone(),
            maps.servers.clone(),
            maps.routes.clone(),
            maps.id_to_lb.clone(),
        )
        .await;
    if released {
        crate::memory_reclaim::trim_released_heap();
    }
    maps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_server(id: i64, names: &[&str]) -> ServerConfig {
        let server_names: Vec<serde_json::Value> = names
            .iter()
            .map(|name| serde_json::json!({ "name": name }))
            .collect();
        serde_json::from_value(serde_json::json!({
            "id": id,
            "isOn": true,
            "serverNames": server_names,
            "http": {
                "isOn": true,
                "listen": [{"protocol": "http", "host": "0.0.0.0", "portRange": "80"}]
            },
            "reverseProxy": {
                "isOn": true,
                "primaryOrigins": [{
                    "id": id * 10,
                    "isOn": true,
                    "addr": "http://127.0.0.1:8080"
                }]
            }
        }))
        .expect("server fixture")
    }

    #[tokio::test]
    async fn host_indexes_share_one_server_arc() {
        let health = GlobalHealthManager::new(1);
        let maps = materialize_runtime_servers(MaterializeRuntimeServersArgs {
            servers: vec![sample_server(7, &["a.example.com", "www.a.example.com"])],
            health_manager: &health,
            node_level: 1,
            parent_nodes: Arc::new(HashMap::new()),
            tiered_origin_bypass: false,
            allow_lan: true,
            global_http: None,
            limits: ConfigApplyLimits::synthetic(8 * 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024),
        })
        .await;
        let a = maps.servers.get("a.example.com").expect("exact host");
        let www = maps.servers.get("www.a.example.com").expect("alias host");
        assert!(Arc::ptr_eq(a, www));
        assert!(Arc::ptr_eq(a, &maps.all_servers[0]));
        assert_eq!(maps.stats.servers_in, 1);
        assert_eq!(maps.stats.hosts_indexed, 2);
    }

    #[tokio::test]
    async fn critical_budget_applies_in_small_chunks_without_dropping_sites() {
        let health = GlobalHealthManager::new(1);
        let servers = (1..=40)
            .map(|id| sample_server(id, &[&format!("s{id}.example.com")]))
            .collect::<Vec<_>>();
        let limits = ConfigApplyLimits::synthetic(512 * 1024 * 1024, 32 * 1024 * 1024);
        assert_eq!(limits.pressure, MemoryPressureLevel::Critical);
        assert_eq!(limits.server_chunk_size(), 4);
        let maps = materialize_runtime_servers(MaterializeRuntimeServersArgs {
            servers,
            health_manager: &health,
            node_level: 1,
            parent_nodes: Arc::new(HashMap::new()),
            tiered_origin_bypass: false,
            allow_lan: true,
            global_http: None,
            limits,
        })
        .await;
        assert_eq!(maps.all_servers.len(), 40);
        assert_eq!(maps.servers.len(), 40);
        assert!(maps.stats.chunks >= 10);
        assert!(maps.stats.reclaim_runs >= 1);
    }

    #[tokio::test]
    async fn critical_reapply_drops_previous_store_generation() {
        let health = GlobalHealthManager::new(1);
        let store = ConfigStore::new();
        let limits = ConfigApplyLimits::synthetic(512 * 1024 * 1024, 32 * 1024 * 1024);
        let first = apply_server_snapshot(
            &store,
            &health,
            vec![sample_server(1, &["a.example.com"])],
            limits,
        )
        .await;
        assert!(first.stats.released_previous_generation);
        assert_eq!(store.get_all_servers_sync().len(), 1);
        let second = apply_server_snapshot(
            &store,
            &health,
            vec![sample_server(1, &["a.example.com"])],
            limits,
        )
        .await;
        assert!(second.stats.released_previous_generation);
        assert_eq!(store.get_all_servers_sync().len(), 1);
        assert!(store.get_server_sync("a.example.com").is_some());
    }

    #[test]
    fn decode_budget_stays_within_available_memory() {
        let limits = ConfigApplyLimits::synthetic(512 * 1024 * 1024, 96 * 1024 * 1024);
        assert!(limits.decode_budget_bytes() <= 96 * 1024 * 1024);
        assert!(limits.decode_budget_bytes() >= MIN_DECODE_BUDGET_BYTES);
    }

    #[test]
    fn high_and_critical_drop_the_previous_generation() {
        let high = ConfigApplyLimits::synthetic(2 * 1024 * 1024 * 1024, 150 * 1024 * 1024);
        let low = ConfigApplyLimits::synthetic(512 * 1024 * 1024, 32 * 1024 * 1024);
        let normal = ConfigApplyLimits::synthetic(8 * 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024);
        assert!(high.drop_previous_generation());
        assert!(low.drop_previous_generation());
        assert!(!normal.drop_previous_generation());
    }
}
