use chrono::Timelike;
use dashmap::DashMap;
use std::collections::BTreeMap;
use std::sync::OnceLock as OnceCell;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
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

pub const METRIC_CATEGORY_HTTP: &str = "http";
pub const METRIC_CATEGORY_TCP: &str = "tcp";
pub const METRIC_CATEGORY_UDP: &str = "udp";

pub fn normalize_metric_category(category: &str) -> String {
    let category = category.trim().to_ascii_lowercase();
    if category.is_empty() {
        METRIC_CATEGORY_HTTP.to_string()
    } else {
        category
    }
}

pub fn start_pressure_updater() {
    tokio::spawn(async {
        let mut sys = sysinfo::System::new();
        loop {
            let pressure = compute_node_pressure(&mut sys);
            CACHED_PRESSURE.store(pressure.to_bits(), Ordering::Relaxed);

            // Runtime distinct-IP cardinality is strictly bounded by its
            // governor-derived tracker; daily exact tracking remains separate.

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
mod mace_backend;
pub mod storage;
pub mod top_ip;

#[derive(Clone)]
pub struct HttpDimensionEvent {
    pub category: Arc<str>,
    pub server_id: i64,
    pub client_ip: std::net::IpAddr,
    pub domain: Arc<str>,
    pub user_agent: Arc<str>,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub cached_bytes: i64,
    pub waf_group_id: i64,
    pub waf_action: Option<Arc<str>>,
    pub analyzed: Option<crate::metrics::analyzer::RequestStats>,
    pub request_context: Arc<MetricRequestContext>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
pub struct MetricRequestContext {
    pub values: BTreeMap<String, String>,
}

impl MetricRequestContext {
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values.insert(key.into(), value.into());
    }

    pub fn resolve_key(&self, key: &str) -> String {
        resolve_template_with(key, |var_name| self.resolve_variable(var_name))
    }

    pub fn resolve_variable(&self, var_name: &str) -> String {
        resolve_metric_variable_from_map(&self.values, var_name)
    }

    pub fn network(
        domain: &str,
        client_ip: std::net::IpAddr,
        user_agent: &str,
        bytes_sent: i64,
        bytes_received: i64,
        status: u16,
    ) -> Self {
        let mut values = BTreeMap::new();
        let domain = domain.trim();
        let remote_addr = client_ip.to_string();
        values.insert("host".to_string(), domain.to_string());
        values.insert("serverName".to_string(), domain.to_string());
        values.insert("remoteAddr".to_string(), remote_addr.clone());
        values.insert("remoteAddrValue".to_string(), remote_addr.clone());
        values.insert("rawRemoteAddr".to_string(), remote_addr);
        values.insert("userAgent".to_string(), user_agent.to_string());
        values.insert("status".to_string(), status.to_string());
        values.insert("statusMessage".to_string(), status_message(status));
        values.insert("bytesSent".to_string(), bytes_sent.to_string());
        values.insert("bodyBytesSent".to_string(), bytes_sent.to_string());
        values.insert("requestLength".to_string(), bytes_received.to_string());
        Self { values }
    }
}

pub fn resolve_metric_variable_from_map(
    values: &BTreeMap<String, String>,
    var_name: &str,
) -> String {
    match var_name {
        "requestMethod" | "method" | "request.method" => {
            return metric_method_value(values);
        }
        _ => {}
    }

    if let Some(value) = values.get(var_name) {
        return value.clone();
    }

    match var_name {
        "path" => return values.get("requestPath").cloned().unwrap_or_default(),
        "uri" => {
            return values
                .get("requestURI")
                .or_else(|| values.get("requestUri"))
                .cloned()
                .unwrap_or_default();
        }
        _ => {}
    }

    let Some((prefix, suffix)) = var_name.split_once('.') else {
        return format!("${{{}}}", var_name);
    };

    match prefix {
        "header" | "http" => lookup_case_insensitive(values, &format!("header.{suffix}")),
        "response" => {
            if suffix == "contentType" {
                values
                    .get("response.contentType")
                    .cloned()
                    .or_else(|| {
                        Some(lookup_case_insensitive(
                            values,
                            "response.header.Content-Type",
                        ))
                        .filter(|value| !value.is_empty())
                    })
                    .unwrap_or_default()
            } else if let Some(header) = suffix.strip_prefix("header.") {
                lookup_case_insensitive(values, &format!("response.header.{header}"))
            } else {
                String::new()
            }
        }
        "request" => match suffix {
            "method" => metric_method_value(values),
            "path" => values.get("requestPath").cloned().unwrap_or_default(),
            "uri" | "URI" => values
                .get("requestURI")
                .or_else(|| values.get("requestUri"))
                .cloned()
                .unwrap_or_default(),
            _ => String::new(),
        },
        "cookie" | "arg" | "origin" | "node" | "geo" | "isp" | "browser" | "product" | "host" => {
            values.get(var_name).cloned().unwrap_or_default()
        }
        _ => String::new(),
    }
}

fn metric_method_value(values: &BTreeMap<String, String>) -> String {
    values
        .get("requestMethod")
        .or_else(|| values.get("method"))
        .or_else(|| values.get("request.method"))
        .map(|method| normalize_metric_http_method(method))
        .unwrap_or_default()
}

pub fn normalize_metric_http_method(method: &str) -> String {
    method.trim().to_ascii_uppercase()
}

pub fn status_message(status: u16) -> String {
    http::StatusCode::from_u16(status)
        .ok()
        .and_then(|code| code.canonical_reason().map(str::to_string))
        .unwrap_or_default()
}

pub fn resolve_template_with<F>(source: &str, mut resolve_variable: F) -> String
where
    F: FnMut(&str) -> String,
{
    let Some(mut cursor) = source.find("${") else {
        return source.to_string();
    };

    let mut out = String::with_capacity(source.len());
    out.push_str(&source[..cursor]);

    while cursor < source.len() {
        let var_start = cursor + 2;
        let Some(relative_end) = source[var_start..].find('}') else {
            out.push_str(&source[cursor..]);
            return out;
        };
        let var_end = var_start + relative_end;
        out.push_str(&resolve_variable(&source[var_start..var_end]));

        let next_start = var_end + 1;
        if let Some(next_relative) = source[next_start..].find("${") {
            cursor = next_start + next_relative;
            out.push_str(&source[next_start..cursor]);
        } else {
            out.push_str(&source[next_start..]);
            return out;
        }
    }

    out
}

fn lookup_case_insensitive(values: &BTreeMap<String, String>, key: &str) -> String {
    values
        .get(key)
        .cloned()
        .or_else(|| {
            values
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
                .map(|(_, value)| value.clone())
        })
        .unwrap_or_default()
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
        crate::pipeline_metrics::increment(
            crate::pipeline_metrics::PipelineCounter::HttpDimensionDropped,
        );
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

pub struct RuntimeDistinctIpTracker {
    ips: dashmap::DashSet<std::net::IpAddr>,
    reserved: AtomicUsize,
    capacity: usize,
}

impl RuntimeDistinctIpTracker {
    fn new(max_servers: u64) -> Self {
        let budget = crate::memory_governor::MEMORY_GOVERNOR
            .snapshot(crate::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads())
            .cardinality_state_budget_bytes;
        let tracker_budget = budget / max_servers.max(1);
        Self {
            ips: dashmap::DashSet::new(),
            reserved: AtomicUsize::new(0),
            capacity: (tracker_budget / 64).max(1).min(usize::MAX as u64) as usize,
        }
    }

    fn insert(&self, ip: std::net::IpAddr) {
        if self.ips.contains(&ip) {
            return;
        }
        if self
            .reserved
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
                (reserved < self.capacity).then_some(reserved + 1)
            })
            .is_err()
        {
            return;
        }
        if !self.ips.insert(ip) {
            self.reserved.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn len(&self) -> usize {
        self.ips.len()
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.capacity
    }
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
    pub distinct_ips: RuntimeDistinctIpTracker,
}

impl ServerMetrics {
    pub fn new() -> Self {
        Self::with_server_count(1)
    }

    fn with_server_count(max_servers: u64) -> Self {
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
            distinct_ips: RuntimeDistinctIpTracker::new(max_servers),
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
    let now = crate::utils::time::now_timestamp();
    let now_day = now / 86400;

    DAY_CACHE.get_or_update(now_day, || {
        crate::utils::time::now_local().format("%Y%m%d").to_string()
    })
}

fn get_current_5min_ts() -> i64 {
    let now = crate::utils::time::now_timestamp();
    let now_5min = now / 300;

    PERIOD_CACHE.get_or_update(now_5min, || {
        let dt = crate::utils::time::now_local();
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
        let max_servers = METRICS.servers.len().saturating_add(1) as u64;
        METRICS
            .servers
            .entry(server_id)
            .or_insert_with(|| Arc::new(ServerMetrics::with_server_count(max_servers)))
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
        bytes_received: i64,
        cached_bytes: i64,
        waf_group_id: i64,
        waf_action: Option<&str>,
        cached_analyzed: Option<&crate::metrics::analyzer::RequestStats>,
        request_context: Option<MetricRequestContext>,
    ) {
        record_dimensions(
            crate::metrics::METRIC_CATEGORY_HTTP,
            server_id,
            client_ip,
            domain,
            user_agent,
            bytes_sent,
            bytes_received,
            cached_bytes,
            waf_group_id,
            waf_action,
            cached_analyzed,
            request_context,
        );
    }

    pub fn record_network_dimensions(
        category: &str,
        server_id: i64,
        client_ip: IpAddr,
        domain: &str,
        user_agent: &str,
        bytes_sent: i64,
        bytes_received: i64,
        status: u16,
    ) {
        record_dimensions(
            category,
            server_id,
            client_ip,
            domain,
            user_agent,
            bytes_sent,
            bytes_received,
            0,
            0,
            None,
            None,
            Some(MetricRequestContext::network(
                domain,
                client_ip,
                user_agent,
                bytes_sent,
                bytes_received,
                status,
            )),
        );
    }

    fn record_dimensions(
        category: &str,
        server_id: i64,
        client_ip: IpAddr,
        domain: &str,
        user_agent: &str,
        bytes_sent: i64,
        bytes_received: i64,
        cached_bytes: i64,
        waf_group_id: i64,
        waf_action: Option<&str>,
        cached_analyzed: Option<&crate::metrics::analyzer::RequestStats>,
        request_context: Option<MetricRequestContext>,
    ) {
        if server_id <= 0 {
            return;
        }

        let category = crate::metrics::normalize_metric_category(category);
        let event = HttpDimensionEvent {
            category: Arc::from(category),
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
            bytes_received,
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
            request_context: Arc::new(request_context.unwrap_or_default()),
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
            category: event.category.clone(),
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
            browser_version: analyzed.browser_version.clone(),
            os_version: analyzed.os_version.clone(),
            request_attrs: Arc::new(event.request_context.values.clone()),
        };
        let is_attack = event.waf_action.is_some();

        crate::metrics::aggregator::METRIC_STAT_AGGREGATOR.record(
            key.clone(),
            event.bytes_sent,
            event.bytes_received,
            is_attack,
        );
        crate::metrics::top_ip::TOP_IP_TRACKER.record_addr(event.server_id, event.client_ip);

        if event.category.as_ref() == crate::metrics::METRIC_CATEGORY_HTTP {
            crate::metrics::aggregator::HTTP_REQUEST_STAT_AGGREGATOR.record(
                key,
                event.bytes_sent,
                event.bytes_received,
                is_attack,
            );

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
        let now = crate::utils::time::now_timestamp();
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

        let cleanup_before = (now % 3600 < 30).then_some(now - 86400);
        if !updates.is_empty() || cleanup_before.is_some() {
            let write_result = tokio::task::spawn_blocking(move || {
                if !updates.is_empty() {
                    storage::STORAGE.record_server_batch(
                        period,
                        updates,
                        node_sent_delta,
                        node_recv_delta,
                    );
                }
                if let Some(older_than) = cleanup_before {
                    storage::STORAGE.cleanup_old_stats(older_than);
                }
            })
            .await;
            if let Err(err) = write_result {
                tracing::error!(error = %err, "metrics persistence worker failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MetricRequestContext;
    use std::net::IpAddr;

    #[test]
    fn metric_request_context_resolves_go_style_keys() {
        let mut ctx = MetricRequestContext::default();
        ctx.insert("status", "403");
        ctx.insert("host", "cdn.example.com");
        ctx.insert("requestMethod", "get");
        ctx.insert("requestPath", "/index.html");
        ctx.insert("requestURI", "/index.html?page=1");
        ctx.insert("header.User-Agent", "curl/8");
        ctx.insert("cookie.sid", "abc");
        ctx.insert("arg.page", "1");
        ctx.insert("response.header.Content-Type", "text/html");

        assert_eq!(ctx.resolve_key("${status}"), "403");
        assert_eq!(ctx.resolve_key("${host}"), "cdn.example.com");
        assert_eq!(ctx.resolve_key("${method}"), "GET");
        assert_eq!(ctx.resolve_key("${request.method}"), "GET");
        assert_eq!(ctx.resolve_key("${requestMethod}"), "GET");
        assert_eq!(ctx.resolve_key("${path}"), "/index.html");
        assert_eq!(ctx.resolve_key("${request.path}"), "/index.html");
        assert_eq!(ctx.resolve_key("${uri}"), "/index.html?page=1");
        assert_eq!(ctx.resolve_key("${request.uri}"), "/index.html?page=1");
        assert_eq!(ctx.resolve_key("${header.user-agent}"), "curl/8");
        assert_eq!(ctx.resolve_key("${http.User-Agent}"), "curl/8");
        assert_eq!(ctx.resolve_key("${cookie.sid}"), "abc");
        assert_eq!(ctx.resolve_key("${arg.page}"), "1");
        assert_eq!(ctx.resolve_key("${response.contentType}"), "text/html");
        assert_eq!(
            ctx.resolve_key("${response.header.content-type}"),
            "text/html"
        );
        assert_eq!(
            ctx.resolve_key("${host}-${status}-${header.user-agent}"),
            "cdn.example.com-403-curl/8"
        );
    }

    #[test]
    fn metric_request_context_preserves_unknown_simple_vars() {
        let ctx = MetricRequestContext::default();

        assert_eq!(ctx.resolve_key("${unknownVar}"), "${unknownVar}");
        assert_eq!(ctx.resolve_key("${unknown.prefix}"), "");
        assert_eq!(ctx.resolve_key("literal"), "literal");
    }

    #[test]
    fn network_metric_context_resolves_status_and_common_keys() {
        let ctx = MetricRequestContext::network(
            "edge.example.com",
            "203.0.113.9".parse().expect("valid ip"),
            "-",
            1234,
            56,
            502,
        );

        assert_eq!(ctx.resolve_key("${status}"), "502");
        assert_eq!(ctx.resolve_key("${statusMessage}"), "Bad Gateway");
        assert_eq!(ctx.resolve_key("${host}"), "edge.example.com");
        assert_eq!(ctx.resolve_key("${serverName}"), "edge.example.com");
        assert_eq!(ctx.resolve_key("${remoteAddr}"), "203.0.113.9");
        assert_eq!(ctx.resolve_key("${bytesSent}"), "1234");
        assert_eq!(ctx.resolve_key("${requestLength}"), "56");
    }

    #[test]
    fn runtime_distinct_ip_tracker_fail_closed_at_capacity() {
        let tracker = super::RuntimeDistinctIpTracker::new(1);
        let capacity = tracker.capacity();
        assert!(
            capacity > 0,
            "distinct IP tracker must derive a positive capacity"
        );

        for i in 0..capacity.saturating_add(128) {
            let ip = IpAddr::from([10, 0, (i / 256) as u8, (i % 256) as u8]);
            tracker.insert(ip);
        }
        assert!(
            tracker.len() <= capacity,
            "distinct IP tracker must not grow beyond capacity ({capacity}), got {}",
            tracker.len()
        );
    }
}
