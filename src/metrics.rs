use dashmap::DashMap;
use lazy_static::lazy_static;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

pub mod aggregator;
pub mod analyzer;
pub mod storage;
pub mod top_ip;

/// Metrics for a specific server (site)
pub struct ServerMetrics {
    pub user_id: AtomicI64,
    pub user_plan_id: AtomicI64,
    pub plan_id: AtomicI64,
    pub total_requests: AtomicU64,
    pub active_connections: AtomicI64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub cached_bytes: AtomicU64,
    pub attack_bytes: AtomicU64,
    pub count_cached_requests: AtomicU64,
    pub count_attack_requests: AtomicU64,
    pub count_websocket_connections: AtomicU64,
    pub origin_bytes_sent: AtomicU64,
    pub origin_bytes_received: AtomicU64,
    pub distinct_ips: dashmap::DashSet<String>,
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerMetrics {
    pub fn new() -> Self {
        Self {
            user_id: AtomicI64::new(0),
            user_plan_id: AtomicI64::new(0),
            plan_id: AtomicI64::new(0),
            total_requests: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            cached_bytes: AtomicU64::new(0),
            attack_bytes: AtomicU64::new(0),
            count_cached_requests: AtomicU64::new(0),
            count_attack_requests: AtomicU64::new(0),
            count_websocket_connections: AtomicU64::new(0),
            origin_bytes_sent: AtomicU64::new(0),
            origin_bytes_received: AtomicU64::new(0),
            distinct_ips: dashmap::DashSet::new(),
        }
    }

    pub fn snapshot(&self) -> ServerStatusSnapshot {
        let count_ips = self.distinct_ips.len() as u64;
        ServerStatusSnapshot {
            server_id: 0, // placeholder
            user_id: self.user_id.load(Ordering::Relaxed),
            user_plan_id: self.user_plan_id.load(Ordering::Relaxed),
            plan_id: self.plan_id.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            cached_bytes: self.cached_bytes.load(Ordering::Relaxed),
            attack_bytes: self.attack_bytes.load(Ordering::Relaxed),
            count_cached_requests: self.count_cached_requests.load(Ordering::Relaxed),
            count_attack_requests: self.count_attack_requests.load(Ordering::Relaxed),
            count_websocket_connections: self.count_websocket_connections.load(Ordering::Relaxed),
            origin_bytes_sent: self.origin_bytes_sent.load(Ordering::Relaxed),
            origin_bytes_received: self.origin_bytes_received.load(Ordering::Relaxed),
            count_ips,
        }
    }

    pub fn clear_ips(&self) {
        self.distinct_ips.clear();
    }
}

#[derive(serde::Serialize)]
pub struct ServerStatusSnapshot {
    pub server_id: i64,
    pub user_id: i64,
    pub user_plan_id: i64,
    pub plan_id: i64,
    pub total_requests: u64,
    pub active_connections: i64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub cached_bytes: u64,
    pub attack_bytes: u64,
    pub count_cached_requests: u64,
    pub count_attack_requests: u64,
    pub count_websocket_connections: u64,
    pub origin_bytes_sent: u64,
    pub origin_bytes_received: u64,
    pub count_ips: u64,
}

impl ServerStatusSnapshot {
    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }
}

pub struct RpcMetrics {
    pub total_calls: AtomicU64,
    pub total_fails: AtomicU64,
    pub total_cost_ms: AtomicU64,
}

impl Default for RpcMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl RpcMetrics {
    pub fn new() -> Self {
        Self {
            total_calls: AtomicU64::new(0),
            total_fails: AtomicU64::new(0),
            total_cost_ms: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> (f64, f64) {
        let calls = self.total_calls.swap(0, Ordering::Relaxed);
        let fails = self.total_fails.swap(0, Ordering::Relaxed);
        let cost = self.total_cost_ms.swap(0, Ordering::Relaxed);

        let success_percent = if calls > 0 {
            ((calls - fails) as f64 / calls as f64) * 100.0
        } else {
            100.0
        };

        let avg_cost = if calls > 0 {
            (cost as f64 / calls as f64) / 1000.0 // Convert to seconds
        } else {
            0.0
        };

        (success_percent, avg_cost)
    }
}

pub struct NodeMetrics {
    pub servers: DashMap<i64, Arc<ServerMetrics>>,
    pub total_bytes_sent: AtomicU64,
    pub total_bytes_received: AtomicU64,
    pub rpc: RpcMetrics,
}

lazy_static! {
    pub static ref METRICS: NodeMetrics = NodeMetrics {
        servers: DashMap::new(),
        total_bytes_sent: AtomicU64::new(0),
        total_bytes_received: AtomicU64::new(0),
        rpc: RpcMetrics::new(),
    };
}

impl NodeMetrics {
    pub fn take_snapshots(&self) -> Vec<ServerStatusSnapshot> {
        self.servers
            .iter()
            .map(|entry| {
                let (id, metrics) = entry.pair();
                let mut snap = metrics.snapshot();
                snap.server_id = *id;
                snap
            })
            .collect()
    }

    pub fn get_node_totals(&self) -> (u64, u64, i64) {
        let mut total_conns = 0;
        for entry in self.servers.iter() {
            total_conns += entry.value().active_connections.load(Ordering::Relaxed);
        }
        (
            self.total_bytes_sent.load(Ordering::Relaxed),
            self.total_bytes_received.load(Ordering::Relaxed),
            total_conns,
        )
    }

    /// Calculate aggregate node pressure (0.0 to 1.0)
    /// This is used for smart load balancing in Tiered Origin.
    pub fn get_node_pressure(&self) -> f32 {
        let (_, _, active_conns) = self.get_node_totals();
        
        // 1. Connection Pressure (Cap at 50,000 for 100%)
        let conn_pressure = (active_conns as f32 / 50000.0).min(1.0);
        
        // 2. Resource Pressure (Memory/CPU)
        // We use a simplified approximation based on swap usage or static baseline
        // In a real system, we'd pull from sysinfo.
        let sys_pressure = 0.1; // Placeholder for baseline
        
        // Combined weighted pressure
        (conn_pressure * 0.7 + sys_pressure * 0.3).min(1.0)
    }
}

pub mod record {
    use super::*;
    use std::net::IpAddr;

    pub fn request_start(
        server_id: i64,
        remote_ip: String,
        user_id: i64,
        user_plan_id: i64,
        plan_id: i64,
    ) {
        let m = get_or_create(server_id);
        if user_id > 0 {
            m.user_id.store(user_id, Ordering::Relaxed);
        }
        if user_plan_id > 0 {
            m.user_plan_id.store(user_plan_id, Ordering::Relaxed);
        }
        if plan_id > 0 {
            m.plan_id.store(plan_id, Ordering::Relaxed);
        }
        m.total_requests.fetch_add(1, Ordering::Relaxed);
        m.active_connections.fetch_add(1, Ordering::Relaxed);
        m.distinct_ips.insert(remote_ip);
    }

    pub fn request_end(
        server_id: i64,
        bytes_sent: u64,
        bytes_received: u64,
        is_cached: bool,
        is_attack: bool,
        is_websocket: bool,
    ) {
        let m = get_or_create(server_id);
        m.active_connections.fetch_sub(1, Ordering::Relaxed);
        m.bytes_sent.fetch_add(bytes_sent, Ordering::Relaxed);
        m.bytes_received
            .fetch_add(bytes_received, Ordering::Relaxed);

        if is_cached {
            m.cached_bytes.fetch_add(bytes_sent, Ordering::Relaxed);
            m.count_cached_requests.fetch_add(1, Ordering::Relaxed);
        }

        if is_attack {
            m.attack_bytes.fetch_add(bytes_sent, Ordering::Relaxed);
            m.count_attack_requests.fetch_add(1, Ordering::Relaxed);
        }

        if is_websocket {
            m.count_websocket_connections
                .fetch_add(1, Ordering::Relaxed);
        }

        // Also update node-wide totals
        METRICS
            .total_bytes_sent
            .fetch_add(bytes_sent, Ordering::Relaxed);
        METRICS
            .total_bytes_received
            .fetch_add(bytes_received, Ordering::Relaxed);
    }

    pub fn record_transfer(server_id: i64, bytes_sent: u64, bytes_received: u64) {
        let m = get_or_create(server_id);
        m.bytes_sent.fetch_add(bytes_sent, Ordering::Relaxed);
        m.bytes_received
            .fetch_add(bytes_received, Ordering::Relaxed);

        METRICS
            .total_bytes_sent
            .fetch_add(bytes_sent, Ordering::Relaxed);
        METRICS
            .total_bytes_received
            .fetch_add(bytes_received, Ordering::Relaxed);
    }

    pub fn record_origin_traffic(server_id: i64, sent: u64, received: u64) {
        let m = get_or_create(server_id);
        m.origin_bytes_sent.fetch_add(sent, Ordering::Relaxed);
        m.origin_bytes_received
            .fetch_add(received, Ordering::Relaxed);
    }

    pub fn record_rpc_call(is_success: bool, cost_ms: u64) {
        METRICS.rpc.total_calls.fetch_add(1, Ordering::Relaxed);
        if !is_success {
            METRICS.rpc.total_fails.fetch_add(1, Ordering::Relaxed);
        }
        METRICS
            .rpc
            .total_cost_ms
            .fetch_add(cost_ms, Ordering::Relaxed);
    }

    pub fn record_http_dimensions(
        server_id: i64,
        client_ip: IpAddr,
        user_agent: &str,
        bytes_sent: i64,
        waf_group_id: i64,
        waf_action: Option<&str>,
    ) {
        if server_id <= 0 {
            return;
        }

        let analyzed = crate::metrics::analyzer::analyze_request(client_ip, user_agent);
        let (country, country_id, province, province_id, city, city_id, provider) =
            analyzed.geo.map_or_else(
                || {
                    (
                        String::new(),
                        0,
                        String::new(),
                        0,
                        String::new(),
                        0,
                        "Unknown".to_string(),
                    )
                },
                |geo| {
                    (
                        geo.country,
                        geo.country_id,
                        geo.region,
                        geo.region_id,
                        geo.city,
                        geo.city_id,
                        geo.provider,
                    )
                },
            );
        let key = crate::metrics::aggregator::AggregationKey {
            server_id,
            country,
            country_id,
            province,
            province_id,
            city,
            city_id,
            provider,
            browser: analyzed.browser,
            os: analyzed.os,
            waf_group_id,
            waf_action: waf_action.unwrap_or_default().to_string(),
        };
        let is_attack = waf_action.is_some();

        crate::metrics::aggregator::METRIC_STAT_AGGREGATOR
            .record(key.clone(), bytes_sent, is_attack);
        crate::metrics::aggregator::HTTP_REQUEST_STAT_AGGREGATOR
            .record(key, bytes_sent, is_attack);
        crate::metrics::top_ip::TOP_IP_TRACKER.record(server_id, &client_ip.to_string());
    }

    fn get_or_create(server_id: i64) -> Arc<ServerMetrics> {
        METRICS
            .servers
            .entry(server_id)
            .or_insert_with(|| Arc::new(ServerMetrics::new()))
            .clone()
    }
}

pub async fn start_persistence_flusher() {
    use std::collections::HashMap;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    // cache: server_id -> last_flushed_values
    let mut last_values: HashMap<i64, ServerStatusSnapshot> = HashMap::new();
    let mut last_node_sent = 0u64;
    let mut last_node_recv = 0u64;

    loop {
        interval.tick().await;
        let mut updates = Vec::new();
        let now = chrono::Utc::now().timestamp();
        let period = (now / 300) * 300;
        
        // 1. Flush individual servers
        for entry in METRICS.servers.iter() {
            let server_id = *entry.key();
            let current = entry.value().snapshot();
            let last = last_values.entry(server_id).or_insert_with(|| ServerStatusSnapshot {
                server_id,
                user_id: 0,
                user_plan_id: 0,
                plan_id: 0,
                total_requests: 0,
                active_connections: 0,
                bytes_sent: 0,
                bytes_received: 0,
                cached_bytes: 0,
                attack_bytes: 0,
                count_cached_requests: 0,
                count_attack_requests: 0,
                count_websocket_connections: 0,
                origin_bytes_sent: 0,
                origin_bytes_received: 0,
                count_ips: 0,
            });

            // Calculate deltas and add to batch
            macro_rules! add_delta {
                ($field:ident, $suffix:expr) => {
                    if current.$field > last.$field {
                        let delta = current.$field - last.$field;
                        updates.push((format!("S{}_T{}_{}", server_id, period, $suffix), delta));
                        last.$field = current.$field;
                    }
                };
            }

            add_delta!(bytes_sent, "bytes_sent");
            add_delta!(bytes_received, "bytes_received");
            add_delta!(total_requests, "requests");
            add_delta!(cached_bytes, "cached_bytes");
            add_delta!(attack_bytes, "attack_bytes");
            add_delta!(count_cached_requests, "cached_requests");
            add_delta!(count_attack_requests, "attack_requests");
            add_delta!(count_websocket_connections, "websocket_conns");
            add_delta!(origin_bytes_sent, "origin_bytes_sent");
            add_delta!(origin_bytes_received, "origin_bytes_received");
        }

        // 2. Flush Node totals
        let (node_sent, node_recv, _) = METRICS.get_node_totals();
        if node_sent > last_node_sent {
            updates.push((format!("NODE_T{}_bytes_sent", period), node_sent - last_node_sent));
            last_node_sent = node_sent;
        }
        if node_recv > last_node_recv {
            updates.push((format!("NODE_T{}_bytes_received", period), node_recv - last_node_recv));
            last_node_recv = node_recv;
        }

        // 3. Commit to RocksDB
        if !updates.is_empty() {
            storage::STORAGE.increment_batch(updates);
        }

        // 4. Periodically clean old stats (older than 24 hours)
        if now % 3600 < 30 { // Roughly every hour
            storage::STORAGE.cleanup_old_stats(now - 86400);
        }
    }
}
