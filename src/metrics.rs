use chrono::Timelike;
use dashmap::DashMap;
use std::sync::OnceLock as OnceCell;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

use std::sync::atomic::AtomicU32;

static CACHED_PRESSURE: AtomicU32 = AtomicU32::new(0);
static HTTP_DIMENSION_HANDLE: OnceCell<HttpDimensionHandle> = OnceCell::new();
static HTTP_DIMENSION_DROPPED: AtomicU64 = AtomicU64::new(0);
static EMPTY_ARC_STR: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from(""));
static UNKNOWN_ARC_STR: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("Unknown"));
static HTTP_DIMENSION_WARNING_INTERVAL_MS: u64 = 5_000;

pub fn start_pressure_updater() {
    tokio::spawn(async {
        let mut sys = sysinfo::System::new();
        let mut tick: u64 = 0;
        loop {
            let pressure = compute_node_pressure(&mut sys);
            CACHED_PRESSURE.store(pressure.to_bits(), Ordering::Relaxed);

            // Every 5 minutes, cap distinct_ips to prevent unbounded growth
            tick += 1;
            if tick % 150 == 0 {
                for entry in METRICS.servers.iter() {
                    if entry.value().distinct_ips.len() > 100_000 {
                        entry.value().distinct_ips.clear();
                    }
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
}

fn compute_node_pressure(sys: &mut sysinfo::System) -> f32 {
    let (_, _, total_conns) = METRICS.get_node_totals();
    let cpu_cores = num_cpus::get() as i64;
    let conn_pressure = (total_conns as f64 / (cpu_cores * 2000) as f64).min(1.0);

    sys.refresh_cpu_usage();
    let cpu_load = sys.global_cpu_usage() as f64 / 100.0;

    ((conn_pressure * 0.7 + cpu_load * 0.3).min(1.0)) as f32
}

pub mod aggregator;
pub mod analyzer;
pub mod daily;
pub mod storage;
pub mod top_ip;

#[derive(Clone)]
pub struct HttpDimensionEvent {
    pub server_id: i64,
    pub client_ip: std::net::IpAddr,
    pub domain: Arc<str>,
    pub user_agent: Arc<str>,
    pub bytes_sent: i64,
    pub cached_bytes: i64,
    pub waf_group_id: i64,
    pub waf_action: Option<Arc<str>>,
    pub analyzed: Option<crate::metrics::analyzer::RequestStats>,
    pub created_at: i64,
}

#[derive(Clone)]
struct HttpDimensionHandle {
    sender: mpsc::Sender<HttpDimensionEvent>,
    queue_capacity: usize,
    dropped_since_warning: Arc<AtomicU64>,
    last_warning_at_ms: Arc<AtomicI64>,
}

impl HttpDimensionHandle {
    fn new(sender: mpsc::Sender<HttpDimensionEvent>, queue_capacity: usize) -> Self {
        Self {
            sender,
            queue_capacity,
            dropped_since_warning: Arc::new(AtomicU64::new(0)),
            last_warning_at_ms: Arc::new(AtomicI64::new(0)),
        }
    }

    fn try_enqueue(&self, event: HttpDimensionEvent) {
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.record_drop("saturated");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.record_drop("closed");
            }
        }
    }

    fn record_drop(&self, reason: &str) {
        HTTP_DIMENSION_DROPPED.fetch_add(1, Ordering::Relaxed);
        self.dropped_since_warning.fetch_add(1, Ordering::Relaxed);
        let now = unix_epoch_millis_now();
        let last = self.last_warning_at_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= HTTP_DIMENSION_WARNING_INTERVAL_MS as i64
            && self
                .last_warning_at_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let dropped = self.dropped_since_warning.swap(0, Ordering::Relaxed);
            tracing::warn!(
                "METRICS: http dimension queue {} dropped={} total_dropped={} queue_capacity={} available_capacity={}",
                reason,
                dropped,
                HTTP_DIMENSION_DROPPED.load(Ordering::Relaxed),
                self.queue_capacity,
                self.sender.capacity()
            );
        }
    }
}

fn unix_epoch_millis_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

pub fn init_http_dimension_worker(queue_capacity: usize) {
    let capacity = queue_capacity.max(1);
    let (sender, mut receiver) = mpsc::channel::<HttpDimensionEvent>(capacity);
    let handle = HttpDimensionHandle::new(sender, capacity);
    let _ = HTTP_DIMENSION_HANDLE.set(handle);
    tokio::spawn(async move {
        let mut buffer = Vec::with_capacity(1024);
        loop {
            let Some(event) = receiver.recv().await else {
                return;
            };
            record::record_http_dimension_event(event);
            while buffer.len() < 1024 {
                match receiver.try_recv() {
                    Ok(event) => buffer.push(event),
                    Err(_) => break,
                }
            }
            for event in buffer.drain(..) {
                record::record_http_dimension_event(event);
            }
        }
    });
}

/// Metrics for a specific server (site)
pub struct ServerMetrics {
    pub user_id: AtomicI64,
    pub user_plan_id: AtomicI64,
    pub plan_id: AtomicI64,
    pub total_requests: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub cached_bytes: AtomicU64,
    pub count_cached_requests: AtomicU64,
    pub count_attack_requests: AtomicU64,
    pub attack_bytes: AtomicU64,
    pub origin_bytes_sent: AtomicU64,
    pub origin_bytes_received: AtomicU64,
    pub active_connections: AtomicI64,
    pub count_websocket_connections: AtomicU64,
    pub distinct_ips: dashmap::DashSet<std::net::IpAddr>,
}

impl ServerMetrics {
    pub fn new() -> Self {
        Self {
            user_id: AtomicI64::new(0),
            user_plan_id: AtomicI64::new(0),
            plan_id: AtomicI64::new(0),
            total_requests: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            cached_bytes: AtomicU64::new(0),
            count_cached_requests: AtomicU64::new(0),
            count_attack_requests: AtomicU64::new(0),
            attack_bytes: AtomicU64::new(0),
            origin_bytes_sent: AtomicU64::new(0),
            origin_bytes_received: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            count_websocket_connections: AtomicU64::new(0),
            distinct_ips: dashmap::DashSet::new(),
        }
    }

    pub fn snapshot(&self) -> ServerStatusSnapshot {
        ServerStatusSnapshot {
            server_id: 0, // set by caller
            user_id: self.user_id.load(Ordering::Relaxed),
            user_plan_id: self.user_plan_id.load(Ordering::Relaxed),
            plan_id: self.plan_id.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            cached_bytes: self.cached_bytes.load(Ordering::Relaxed),
            count_cached_requests: self.count_cached_requests.load(Ordering::Relaxed),
            count_attack_requests: self.count_attack_requests.load(Ordering::Relaxed),
            attack_bytes: self.attack_bytes.load(Ordering::Relaxed),
            origin_bytes_sent: self.origin_bytes_sent.load(Ordering::Relaxed),
            origin_bytes_received: self.origin_bytes_received.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed).max(0),
            count_websocket_connections: self.count_websocket_connections.load(Ordering::Relaxed),
            count_ips: self.distinct_ips.len() as u64,
        }
    }
}

fn decrement_active_connections(counter: &AtomicI64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        if current > 0 {
            Some(current - 1)
        } else if current < 0 {
            Some(0)
        } else {
            None
        }
    });
}

#[derive(Clone)]
pub struct ServerStatusSnapshot {
    pub server_id: i64,
    pub user_id: i64,
    pub user_plan_id: i64,
    pub plan_id: i64,
    pub total_requests: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub cached_bytes: u64,
    pub count_cached_requests: u64,
    pub count_attack_requests: u64,
    pub attack_bytes: u64,
    pub origin_bytes_sent: u64,
    pub origin_bytes_received: u64,
    pub active_connections: i64,
    pub count_websocket_connections: u64,
    pub count_ips: u64,
}

impl ServerStatusSnapshot {
    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }
}

pub struct NodeMetrics {
    pub total_bytes_sent: AtomicU64,
    pub total_bytes_received: AtomicU64,
    pub servers: DashMap<i64, Arc<ServerMetrics>>,
    pub rpc: RpcMetrics,
    pub waf: WafRuntimeMetrics,
}

pub struct WafRuntimeMetrics {
    pub compiled_evaluations: AtomicU64,
    pub compiled_matches: AtomicU64,
    pub legacy_evaluations: AtomicU64,
    pub legacy_matches: AtomicU64,
    pub legacy_fallbacks: AtomicU64,
    pub request_body_buffers: AtomicU64,
    pub request_body_buffered_bytes: AtomicU64,
    pub rule_evaluations: AtomicU64,
    pub evaluation_latency_ns: AtomicU64,
}

#[derive(Clone, Debug, Default)]
pub struct WafRuntimeSnapshot {
    pub compiled_evaluations: u64,
    pub compiled_matches: u64,
    pub legacy_evaluations: u64,
    pub legacy_matches: u64,
    pub legacy_fallbacks: u64,
    pub request_body_buffers: u64,
    pub request_body_buffered_bytes: u64,
    pub rule_evaluations: u64,
    pub evaluation_latency_ns: u64,
}

impl WafRuntimeMetrics {
    pub fn new() -> Self {
        Self {
            compiled_evaluations: AtomicU64::new(0),
            compiled_matches: AtomicU64::new(0),
            legacy_evaluations: AtomicU64::new(0),
            legacy_matches: AtomicU64::new(0),
            legacy_fallbacks: AtomicU64::new(0),
            request_body_buffers: AtomicU64::new(0),
            request_body_buffered_bytes: AtomicU64::new(0),
            rule_evaluations: AtomicU64::new(0),
            evaluation_latency_ns: AtomicU64::new(0),
        }
    }

    pub fn record_compiled_evaluation(&self, matched: bool, elapsed: Duration) {
        self.compiled_evaluations.fetch_add(1, Ordering::Relaxed);
        if matched {
            self.compiled_matches.fetch_add(1, Ordering::Relaxed);
        }
        self.evaluation_latency_ns.fetch_add(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    pub fn record_legacy_evaluation(&self, matched: bool, elapsed: Duration) {
        self.legacy_evaluations.fetch_add(1, Ordering::Relaxed);
        if matched {
            self.legacy_matches.fetch_add(1, Ordering::Relaxed);
        }
        self.evaluation_latency_ns.fetch_add(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    pub fn record_legacy_fallback(&self) {
        self.legacy_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_request_body_buffer(&self, bytes: usize) {
        self.request_body_buffers.fetch_add(1, Ordering::Relaxed);
        self.request_body_buffered_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_rule_evaluation(&self) {
        self.rule_evaluations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> WafRuntimeSnapshot {
        WafRuntimeSnapshot {
            compiled_evaluations: self.compiled_evaluations.load(Ordering::Relaxed),
            compiled_matches: self.compiled_matches.load(Ordering::Relaxed),
            legacy_evaluations: self.legacy_evaluations.load(Ordering::Relaxed),
            legacy_matches: self.legacy_matches.load(Ordering::Relaxed),
            legacy_fallbacks: self.legacy_fallbacks.load(Ordering::Relaxed),
            request_body_buffers: self.request_body_buffers.load(Ordering::Relaxed),
            request_body_buffered_bytes: self.request_body_buffered_bytes.load(Ordering::Relaxed),
            rule_evaluations: self.rule_evaluations.load(Ordering::Relaxed),
            evaluation_latency_ns: self.evaluation_latency_ns.load(Ordering::Relaxed),
        }
    }
}

impl Default for WafRuntimeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RpcMetrics {
    pub total_requests: AtomicU64,
    pub total_errors: AtomicU64,
    pub total_cost_ms: AtomicU64,
}

impl RpcMetrics {
    pub fn snapshot(&self) -> RpcStatusSnapshot {
        RpcStatusSnapshot {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_errors: self.total_errors.load(Ordering::Relaxed),
            total_cost_ms: self.total_cost_ms.load(Ordering::Relaxed),
        }
    }
}

pub struct RpcStatusSnapshot {
    pub total_requests: u64,
    pub total_errors: u64,
    pub total_cost_ms: u64,
}

impl NodeMetrics {
    pub fn take_snapshots(&self) -> Vec<(i64, ServerStatusSnapshot)> {
        self.servers
            .iter()
            .map(|entry| {
                let mut snap = entry.value().snapshot();
                snap.server_id = *entry.key();
                (*entry.key(), snap)
            })
            .collect()
    }

    pub fn get_node_totals(&self) -> (u64, u64, i64) {
        let mut total_conns = 0;
        for entry in self.servers.iter() {
            total_conns += entry
                .value()
                .active_connections
                .load(Ordering::Relaxed)
                .max(0);
        }
        (
            self.total_bytes_sent.load(Ordering::Relaxed),
            self.total_bytes_received.load(Ordering::Relaxed),
            total_conns,
        )
    }

    pub fn get_node_pressure(&self) -> f64 {
        f32::from_bits(CACHED_PRESSURE.load(Ordering::Relaxed)) as f64
    }
}

pub static METRICS: LazyLock<Arc<NodeMetrics>> = LazyLock::new(|| {
    Arc::new(NodeMetrics {
        total_bytes_sent: AtomicU64::new(0),
        total_bytes_received: AtomicU64::new(0),
        servers: DashMap::with_shard_amount(32),
        rpc: RpcMetrics {
            total_requests: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            total_cost_ms: AtomicU64::new(0),
        },
        waf: WafRuntimeMetrics::new(),
    })
});

use std::sync::RwLock;

struct TimeCache<T> {
    data: RwLock<(i64, T)>,
}

impl<T: Clone + Default> TimeCache<T> {
    fn new() -> Self {
        Self {
            data: RwLock::new((0, T::default())),
        }
    }

    fn get_or_update<F>(&self, current_tick: i64, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        {
            let read = self.data.read().unwrap();
            if read.0 == current_tick {
                return read.1.clone();
            }
        }

        let mut write = self.data.write().unwrap();
        if write.0 == current_tick {
            return write.1.clone();
        }

        let new_val = f();
        *write = (current_tick, new_val.clone());
        new_val
    }
}

static DAY_CACHE: LazyLock<TimeCache<String>> = LazyLock::new(TimeCache::new);
static PERIOD_CACHE: LazyLock<TimeCache<i64>> = LazyLock::new(TimeCache::new);

fn get_current_day() -> String {
    let now = crate::utils::time::system_timestamp();
    let now_day = now / 86400;

    DAY_CACHE.get_or_update(now_day, || {
        crate::utils::time::system_local()
            .format("%Y%m%d")
            .to_string()
    })
}

fn get_current_5min_ts() -> i64 {
    let now = crate::utils::time::system_timestamp();
    let now_5min = now / 300;

    PERIOD_CACHE.get_or_update(now_5min, || {
        let dt = crate::utils::time::system_local();
        let minute_floor = (dt.minute() / 5) * 5;
        dt.with_second(0)
            .and_then(|d| d.with_minute(minute_floor))
            .map(|d| d.timestamp())
            .unwrap_or(now - (now % 300))
    })
}

pub mod record {
    use super::*;
    use std::net::IpAddr;

    pub fn get_or_create(server_id: i64) -> Arc<ServerMetrics> {
        METRICS
            .servers
            .entry(server_id)
            .or_insert_with(|| Arc::new(ServerMetrics::new()))
            .clone()
    }

    pub fn request_start(
        server_id: i64,
        remote_ip: &str,
        user_id: i64,
        user_plan_id: i64,
        plan_id: i64,
        cached_m: Option<&Arc<ServerMetrics>>,
        ip_recorded: bool,
    ) -> bool {
        let m = if let Some(m) = cached_m {
            (*m).clone()
        } else {
            get_or_create(server_id)
        };
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

        if !ip_recorded {
            if let Ok(remote_ip) = remote_ip.parse::<IpAddr>() {
                let day = get_current_day();
                crate::metrics::daily::UNIQUE_IP_TRACKER.record(server_id, &day, remote_ip);
                m.distinct_ips.insert(remote_ip);
                return true;
            }
            return false;
        }
        false
    }

    pub fn request_end(
        server_id: i64,
        bytes_sent: u64,
        bytes_received: u64,
        is_cached: bool,
        is_attack: bool,
        is_websocket: bool,
        cached_m: Option<&Arc<ServerMetrics>>,
    ) {
        let m = if let Some(m) = cached_m {
            (*m).clone()
        } else {
            get_or_create(server_id)
        };
        decrement_active_connections(&m.active_connections);
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

        METRICS
            .total_bytes_sent
            .fetch_add(bytes_sent, Ordering::Relaxed);
        METRICS
            .total_bytes_received
            .fetch_add(bytes_received, Ordering::Relaxed);
    }

    pub fn record_transfer(
        server_id: i64,
        bytes_sent: u64,
        bytes_received: u64,
        cached_m: Option<&Arc<ServerMetrics>>,
    ) {
        let m = if let Some(m) = cached_m {
            (*m).clone()
        } else {
            get_or_create(server_id)
        };
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

    pub fn record_origin_traffic(
        server_id: i64,
        sent: u64,
        received: u64,
        cached_m: Option<&Arc<ServerMetrics>>,
    ) {
        let m = if let Some(m) = cached_m {
            (*m).clone()
        } else {
            get_or_create(server_id)
        };
        m.origin_bytes_sent.fetch_add(sent, Ordering::Relaxed);
        m.origin_bytes_received
            .fetch_add(received, Ordering::Relaxed);
    }

    pub fn record_rpc_call(cost_ms: u64, is_error: bool) {
        METRICS.rpc.total_requests.fetch_add(1, Ordering::Relaxed);
        if is_error {
            METRICS.rpc.total_errors.fetch_add(1, Ordering::Relaxed);
        }
        METRICS
            .rpc
            .total_cost_ms
            .fetch_add(cost_ms, Ordering::Relaxed);
    }

    pub fn record_http_dimensions(
        server_id: i64,
        client_ip: IpAddr,
        domain: &str,
        user_agent: &str,
        bytes_sent: i64,
        cached_bytes: i64,
        waf_group_id: i64,
        waf_action: Option<&str>,
        cached_analyzed: Option<&crate::metrics::analyzer::RequestStats>,
    ) {
        if server_id <= 0 {
            return;
        }

        let event = HttpDimensionEvent {
            server_id,
            client_ip,
            domain: if domain.is_empty() {
                Arc::clone(&EMPTY_ARC_STR)
            } else {
                Arc::from(domain)
            },
            user_agent: if user_agent.is_empty() {
                Arc::clone(&EMPTY_ARC_STR)
            } else {
                Arc::from(user_agent)
            },
            bytes_sent,
            cached_bytes,
            waf_group_id,
            waf_action: waf_action.map(|action| {
                if action.is_empty() {
                    Arc::clone(&EMPTY_ARC_STR)
                } else {
                    Arc::from(action)
                }
            }),
            analyzed: cached_analyzed.cloned(),
            created_at: get_current_5min_ts(),
        };

        if let Some(handle) = HTTP_DIMENSION_HANDLE.get() {
            handle.try_enqueue(event);
        } else {
            HTTP_DIMENSION_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_http_dimension_event(event: HttpDimensionEvent) {
        if event.server_id <= 0 {
            return;
        }

        let analyzed_owned;
        let analyzed = if let Some(ref analyzed) = event.analyzed {
            analyzed
        } else {
            analyzed_owned = crate::metrics::analyzer::analyze_request(
                event.client_ip,
                event.user_agent.as_ref(),
            );
            &analyzed_owned
        };

        let (country, country_id, province, province_id, city, city_id, provider) =
            analyzed.geo.as_ref().map_or_else(
                || {
                    (
                        Arc::clone(&EMPTY_ARC_STR),
                        0,
                        Arc::clone(&EMPTY_ARC_STR),
                        0,
                        Arc::clone(&EMPTY_ARC_STR),
                        0,
                        Arc::clone(&UNKNOWN_ARC_STR),
                    )
                },
                |geo| {
                    (
                        geo.country.clone(),
                        geo.country_id,
                        geo.region.clone(),
                        geo.region_id,
                        geo.city.clone(),
                        geo.city_id,
                        geo.provider.clone(),
                    )
                },
            );
        let provider_id = crate::metrics::storage::lookup_region_provider_id(event.client_ip);
        let key = crate::metrics::aggregator::AggregationKey {
            server_id: event.server_id,
            country,
            country_id,
            province,
            province_id,
            city,
            city_id,
            provider,
            browser: analyzed.browser.clone(),
            os: analyzed.os.clone(),
            waf_group_id: event.waf_group_id,
            waf_action: event
                .waf_action
                .clone()
                .unwrap_or_else(|| Arc::clone(&EMPTY_ARC_STR)),
            provider_id,
        };
        let is_attack = event.waf_action.is_some();

        crate::metrics::aggregator::METRIC_STAT_AGGREGATOR.record(
            key.clone(),
            event.bytes_sent,
            is_attack,
        );
        crate::metrics::aggregator::HTTP_REQUEST_STAT_AGGREGATOR.record(
            key,
            event.bytes_sent,
            is_attack,
        );
        crate::metrics::top_ip::TOP_IP_TRACKER.record_addr(event.server_id, event.client_ip);

        crate::metrics::daily::DAILY_DOMAIN_TRACKER.record(
            event.server_id,
            event.created_at,
            event.domain.as_ref(),
            event.bytes_sent,
            event.cached_bytes,
            1,
            if event.cached_bytes > 0 { 1 } else { 0 },
            if is_attack { 1 } else { 0 },
            if is_attack { event.bytes_sent } else { 0 },
        );
    }
}

pub async fn start_persistence_flusher() {
    use std::collections::HashMap;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut last_values: HashMap<i64, ServerStatusSnapshot> = HashMap::new();
    let mut last_node_sent = 0u64;
    let mut last_node_recv = 0u64;

    loop {
        interval.tick().await;
        let mut updates = Vec::new();
        let now = crate::utils::time::system_timestamp();
        let period = (now / 300) * 300;

        for entry in METRICS.servers.iter() {
            let server_id = *entry.key();
            let current = entry.value().snapshot();
            let last = last_values
                .entry(server_id)
                .or_insert_with(|| ServerStatusSnapshot {
                    server_id,
                    user_id: 0,
                    user_plan_id: 0,
                    plan_id: 0,
                    total_requests: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    cached_bytes: 0,
                    count_cached_requests: 0,
                    count_attack_requests: 0,
                    attack_bytes: 0,
                    origin_bytes_sent: 0,
                    origin_bytes_received: 0,
                    active_connections: 0,
                    count_websocket_connections: 0,
                    count_ips: 0,
                });

            updates.push(crate::rpc::metrics::ServerMetricUpdate {
                server_id,
                user_id: current.user_id,
                user_plan_id: current.user_plan_id,
                plan_id: current.plan_id,
                total_requests: current.total_requests - last.total_requests,
                bytes_sent: current.bytes_sent - last.bytes_sent,
                bytes_received: current.bytes_received - last.bytes_received,
                cached_bytes: current.cached_bytes - last.cached_bytes,
                count_cached_requests: current.count_cached_requests - last.count_cached_requests,
                count_attack_requests: current.count_attack_requests - last.count_attack_requests,
                attack_bytes: current.attack_bytes - last.attack_bytes,
                active_connections: current.active_connections,
                count_websocket_connections: current.count_websocket_connections
                    - last.count_websocket_connections,
                count_ips: current.count_ips,
            });

            *last = current;
            last.server_id = server_id;
        }

        let node_sent = METRICS.total_bytes_sent.load(Ordering::Relaxed);
        let node_recv = METRICS.total_bytes_received.load(Ordering::Relaxed);
        let node_sent_delta = node_sent - last_node_sent;
        let node_recv_delta = node_recv - last_node_recv;
        last_node_sent = node_sent;
        last_node_recv = node_recv;

        if !updates.is_empty() {
            storage::STORAGE.record_server_batch(period, updates, node_sent_delta, node_recv_delta);
        }

        if now % 3600 < 30 {
            storage::STORAGE.cleanup_old_stats(now - 86400);
        }
    }
}
