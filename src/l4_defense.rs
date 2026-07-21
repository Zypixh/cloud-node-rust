use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use ipnet::IpNet;
use tracing::{debug, warn};

use crate::config::ConfigStore;
use crate::firewall::state::WafStateManager;
use crate::memory_governor::{AdmissionClass, MEMORY_GOVERNOR, MemoryPressureLevel};
use crate::rpc::ip_report::{IpReportKind, IpReportMessage};

const L4_BLOCK_WARN_INTERVAL_MS: i64 = 5_000;
const L4_AGGREGATE_WINDOW: Duration = Duration::from_secs(10);
const L4_SURGE_DISTINCT_IP_ELEVATED: usize = 1_000;
const L4_SURGE_DISTINCT_IP_HIGH: usize = 5_000;
const L4_SURGE_DISTINCT_IP_CRITICAL: usize = 10_000;
const L4_EXACT_COUNTER_CAPACITY: usize = 262_144;
const L4_EXACT_COUNTER_SWEEP_INTERVAL_MS: i64 = 10_000;
const L4_AGGREGATE_ESTIMATED_BYTES: u64 = 192;
const L4_AGGREGATE_SWEEP_INTERVAL_MS: i64 = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L4DefenseKind {
    TcpActiveLimit,
    TcpAdmissionReject,
    TcpConnectionChurn,
    TcpAcceptedChurn,
    TcpPressureIdleClose,
    TcpSlowFirstByte,
    TcpProxyEarlyCloseOrTinyPayload,
    TlsHandshakeFail,
    TlsPartialClientHello,
    TlsInvalidProbe,
    TlsPlaintextConnectOnTls,
    TlsSlowClientHello,
    TlsHandshakeThenNoHttp,
    HttpSlowHeader,
    HttpEarlyCloseOrTinyRequest,
    SniProbeFail,
    H2StreamAdmissionReject,
    H2RapidReset,
    H2DownstreamCancel,
    H2RequestChurn,
    H2ConnectionAbuse,
    SynBacklogPressure,
    UdpSessionFlood,
    UdpAdmissionReject,
    UdpQueueFull,
    QuicNewRouteFlood,
    QuicIncompleteClientHello,
    QuicPendingReject,
    QuicReassemblyReject,
    QuicNoRoute,
    H3AdmissionReject,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum L4PressureLevel {
    Normal,
    Elevated,
    High,
    Critical,
}

impl Default for L4PressureLevel {
    fn default() -> Self {
        Self::Normal
    }
}

impl L4PressureLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L4DefenseVerdict {
    Disabled,
    Allowed,
    AggregateDropped,
    Blocked,
    AlreadyBlocked,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct L4DefenseMetricsSnapshot {
    pub events_total: u64,
    pub disabled_total: u64,
    pub allowed_total: u64,
    pub blocked_total: u64,
    pub already_blocked_total: u64,
    pub active_limit_total: u64,
    pub admission_reject_total: u64,
    pub slow_close_total: u64,
    pub completed_handshake_total: u64,
    pub h2_defense_total: u64,
    pub tls_probe_total: u64,
    pub syn_pressure_total: u64,
    pub quic_pressure_total: u64,
    pub prefix_event_total: u64,
    pub prefix_blocked_total: u64,
    pub aggregate_drop_total: u64,
    pub exact_counter_saturated_total: u64,
    pub distinct_ips_recent: usize,
    pub prefix_pressure_level: L4PressureLevel,
    pub top_event_kind: &'static str,
    pub top_prefix: String,
    pub top_prefix_events: u64,
}

struct L4DefenseMetrics {
    events_total: AtomicU64,
    disabled_total: AtomicU64,
    allowed_total: AtomicU64,
    blocked_total: AtomicU64,
    already_blocked_total: AtomicU64,
    active_limit_total: AtomicU64,
    admission_reject_total: AtomicU64,
    slow_close_total: AtomicU64,
    completed_handshake_total: AtomicU64,
    h2_defense_total: AtomicU64,
    tls_probe_total: AtomicU64,
    syn_pressure_total: AtomicU64,
    quic_pressure_total: AtomicU64,
    prefix_event_total: AtomicU64,
    prefix_blocked_total: AtomicU64,
    aggregate_drop_total: AtomicU64,
    exact_counter_saturated_total: AtomicU64,
    kind_counts: DashMap<&'static str, AtomicU64>,
}

#[derive(Clone, Debug)]
pub struct L4EventContext {
    pub detail: String,
    pub pressure_level: L4PressureLevel,
}

impl L4EventContext {
    pub fn new(detail: impl Into<String>, pressure_level: L4PressureLevel) -> Self {
        Self {
            detail: detail.into(),
            pressure_level,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum L4AggregateKey {
    V4([u8; 3]),
    V6([u16; 4]),
}

struct AggregateWindow {
    started_at: Instant,
    events: u64,
    high_confidence_events: u64,
    ips: HashSet<IpAddr>,
}

struct DistinctIpWindow {
    started_at: Instant,
    ips: HashSet<IpAddr>,
}

struct PrefixCountWindow {
    last_seen: Instant,
    count: AtomicU64,
}

struct L4AggregateState {
    prefixes: DashMap<(i64, L4AggregateKey), Mutex<AggregateWindow>>,
    distinct_ips: DashMap<i64, Mutex<DistinctIpWindow>>,
    prefix_counts: DashMap<(i64, L4AggregateKey), PrefixCountWindow>,
    last_sweep_at_ms: AtomicI64,
}

struct ExactCounterWindow {
    started_at: Instant,
    count: u64,
    period: Duration,
}

struct L4ExactCounterState {
    counters: DashMap<(i64, IpAddr, &'static str), Mutex<ExactCounterWindow>>,
    last_sweep_at_ms: AtomicI64,
    capacity_override: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum L4ExactCounterIncrement {
    Count(u64),
    CapacitySaturatedFailClosed,
    CapacitySaturatedAllowed,
}

struct ActiveIpTracker {
    active_by_ip: DashMap<IpAddr, Arc<AtomicUsize>>,
}

pub struct ActiveIpPermit {
    ip: IpAddr,
    counter: Arc<AtomicUsize>,
}

impl ActiveIpTracker {
    fn new() -> Self {
        Self {
            active_by_ip: DashMap::new(),
        }
    }

    fn try_acquire(&self, ip: IpAddr, limit: usize) -> Option<ActiveIpPermit> {
        let limit = limit.max(1);
        let counter = self
            .active_by_ip
            .entry(ip)
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();
        loop {
            let current = counter.load(Ordering::Acquire);
            if current >= limit {
                return None;
            }
            if counter
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(ActiveIpPermit { ip, counter });
            }
        }
    }

    fn remove_if_idle(&self, ip: IpAddr, counter: &Arc<AtomicUsize>) {
        self.active_by_ip.remove_if(&ip, |_, existing| {
            Arc::ptr_eq(existing, counter) && existing.load(Ordering::Acquire) == 0
        });
    }
}

impl Drop for ActiveIpPermit {
    fn drop(&mut self) {
        if self.counter.fetch_sub(1, Ordering::AcqRel) == 1 {
            TCP_ACTIVE_IP_TRACKER.remove_if_idle(self.ip, &self.counter);
        }
    }
}

static TCP_ACTIVE_IP_TRACKER: LazyLock<ActiveIpTracker> = LazyLock::new(ActiveIpTracker::new);
static L4_METRICS: LazyLock<L4DefenseMetrics> = LazyLock::new(L4DefenseMetrics::new);
static L4_AGGREGATES: LazyLock<L4AggregateState> = LazyLock::new(L4AggregateState::new);
static L4_EXACT_COUNTERS: LazyLock<L4ExactCounterState> =
    LazyLock::new(L4ExactCounterState::new);
static LAST_BLOCK_WARN_AT_MS: AtomicI64 = AtomicI64::new(0);
static LAST_COUNTER_SATURATION_WARN_AT_MS: AtomicI64 = AtomicI64::new(0);

fn canonical_l4_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(ipv6) = ip
        && let Some(ipv4) = ipv6.to_ipv4_mapped()
    {
        return IpAddr::V4(ipv4);
    }
    ip
}

pub fn try_acquire_tcp_active_ip(ip: IpAddr, limit: usize) -> Option<ActiveIpPermit> {
    TCP_ACTIVE_IP_TRACKER.try_acquire(canonical_l4_ip(ip), limit)
}

impl L4DefenseMetrics {
    fn new() -> Self {
        Self {
            events_total: AtomicU64::new(0),
            disabled_total: AtomicU64::new(0),
            allowed_total: AtomicU64::new(0),
            blocked_total: AtomicU64::new(0),
            already_blocked_total: AtomicU64::new(0),
            active_limit_total: AtomicU64::new(0),
            admission_reject_total: AtomicU64::new(0),
            slow_close_total: AtomicU64::new(0),
            completed_handshake_total: AtomicU64::new(0),
            h2_defense_total: AtomicU64::new(0),
            tls_probe_total: AtomicU64::new(0),
            syn_pressure_total: AtomicU64::new(0),
            quic_pressure_total: AtomicU64::new(0),
            prefix_event_total: AtomicU64::new(0),
            prefix_blocked_total: AtomicU64::new(0),
            aggregate_drop_total: AtomicU64::new(0),
            exact_counter_saturated_total: AtomicU64::new(0),
            kind_counts: DashMap::new(),
        }
    }

    fn record(&self, kind: L4DefenseKind, verdict: L4DefenseVerdict) {
        self.events_total.fetch_add(1, Ordering::Relaxed);
        let counter = self
            .kind_counts
            .entry(kind.as_str())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
        match verdict {
            L4DefenseVerdict::Disabled => {
                self.disabled_total.fetch_add(1, Ordering::Relaxed);
            }
            L4DefenseVerdict::Allowed => {
                self.allowed_total.fetch_add(1, Ordering::Relaxed);
            }
            L4DefenseVerdict::AggregateDropped => {
                self.aggregate_drop_total.fetch_add(1, Ordering::Relaxed);
            }
            L4DefenseVerdict::Blocked => {
                self.blocked_total.fetch_add(1, Ordering::Relaxed);
            }
            L4DefenseVerdict::AlreadyBlocked => {
                self.already_blocked_total.fetch_add(1, Ordering::Relaxed);
            }
        }
        if kind.is_active_limit() {
            self.active_limit_total.fetch_add(1, Ordering::Relaxed);
        }
        if kind.is_admission_reject() {
            self.admission_reject_total.fetch_add(1, Ordering::Relaxed);
        }
        if kind.is_slow_close() {
            self.slow_close_total.fetch_add(1, Ordering::Relaxed);
        }
        if kind.is_completed_handshake() {
            self.completed_handshake_total
                .fetch_add(1, Ordering::Relaxed);
        }
        if kind.is_h2_defense() {
            self.h2_defense_total.fetch_add(1, Ordering::Relaxed);
        }
        if kind.is_tls_probe() {
            self.tls_probe_total.fetch_add(1, Ordering::Relaxed);
        }
        if kind.is_syn_pressure() {
            self.syn_pressure_total.fetch_add(1, Ordering::Relaxed);
        }
        if kind.is_quic_pressure() {
            self.quic_pressure_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> L4DefenseMetricsSnapshot {
        let (top_event_kind, _) = self
            .kind_counts
            .iter()
            .map(|entry| (*entry.key(), entry.value().load(Ordering::Relaxed)))
            .max_by_key(|(_, count)| *count)
            .unwrap_or(("", 0));
        let aggregate = L4_AGGREGATES.snapshot();
        L4DefenseMetricsSnapshot {
            events_total: self.events_total.load(Ordering::Relaxed),
            disabled_total: self.disabled_total.load(Ordering::Relaxed),
            allowed_total: self.allowed_total.load(Ordering::Relaxed),
            blocked_total: self.blocked_total.load(Ordering::Relaxed),
            already_blocked_total: self.already_blocked_total.load(Ordering::Relaxed),
            active_limit_total: self.active_limit_total.load(Ordering::Relaxed),
            admission_reject_total: self.admission_reject_total.load(Ordering::Relaxed),
            slow_close_total: self.slow_close_total.load(Ordering::Relaxed),
            completed_handshake_total: self.completed_handshake_total.load(Ordering::Relaxed),
            h2_defense_total: self.h2_defense_total.load(Ordering::Relaxed),
            tls_probe_total: self.tls_probe_total.load(Ordering::Relaxed),
            syn_pressure_total: self.syn_pressure_total.load(Ordering::Relaxed),
            quic_pressure_total: self.quic_pressure_total.load(Ordering::Relaxed),
            prefix_event_total: self.prefix_event_total.load(Ordering::Relaxed),
            prefix_blocked_total: self.prefix_blocked_total.load(Ordering::Relaxed),
            aggregate_drop_total: self.aggregate_drop_total.load(Ordering::Relaxed),
            exact_counter_saturated_total: self
                .exact_counter_saturated_total
                .load(Ordering::Relaxed),
            distinct_ips_recent: aggregate.distinct_ips_recent,
            prefix_pressure_level: aggregate.pressure_level,
            top_event_kind,
            top_prefix: aggregate.top_prefix,
            top_prefix_events: aggregate.top_prefix_events,
        }
    }

    fn record_prefix_event(&self) {
        self.prefix_event_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_prefix_blocked(&self) {
        self.prefix_blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_exact_counter_saturated(&self) {
        self.exact_counter_saturated_total
            .fetch_add(1, Ordering::Relaxed);
    }
}

pub fn metrics_snapshot() -> L4DefenseMetricsSnapshot {
    L4_METRICS.snapshot()
}

struct AggregateSnapshot {
    distinct_ips_recent: usize,
    pressure_level: L4PressureLevel,
    top_prefix: String,
    top_prefix_events: u64,
}

impl L4AggregateState {
    fn new() -> Self {
        Self {
            prefixes: DashMap::new(),
            distinct_ips: DashMap::new(),
            prefix_counts: DashMap::new(),
            last_sweep_at_ms: AtomicI64::new(0),
        }
    }

    fn capacity(&self) -> usize {
        let budget = MEMORY_GOVERNOR
            .snapshot(MEMORY_GOVERNOR.pingora_worker_threads())
            .l4_aggregate_state_budget_bytes;
        (budget / L4_AGGREGATE_ESTIMATED_BYTES)
            .max(L4_SURGE_DISTINCT_IP_CRITICAL as u64)
            .min(usize::MAX as u64) as usize
    }

    fn per_window_capacity(&self, prefix_count: usize) -> usize {
        let budget = MEMORY_GOVERNOR
            .snapshot(MEMORY_GOVERNOR.pingora_worker_threads())
            .l4_aggregate_state_budget_bytes;
        (budget
            / L4_AGGREGATE_ESTIMATED_BYTES
            .saturating_mul(prefix_count.max(1) as u64))
        .max(1)
        .min(usize::MAX as u64) as usize
    }

    fn record(&self, cluster_id: i64, ip: IpAddr, kind: L4DefenseKind) -> AggregateRecord {
        let now = Instant::now();
        self.sweep_if_needed(now);
        let prefix_capacity = self
            .capacity()
            .max(L4_SURGE_DISTINCT_IP_CRITICAL)
            .max(1);
        let key = L4AggregateKey::from_ip(ip);
        let mut prefix_counter = if self.prefix_counts.contains_key(&(cluster_id, key))
            || self.prefix_counts.len() < prefix_capacity
        {
            Some(self.prefix_counts.entry((cluster_id, key)).or_insert_with(|| {
                PrefixCountWindow {
                    last_seen: now,
                    count: AtomicU64::new(0),
                }
            }))
        } else {
            None
        };
        let top_prefix_events = prefix_counter
            .as_mut()
            .map(|counter| {
                if now.duration_since(counter.last_seen) >= L4_AGGREGATE_WINDOW {
                    counter.count.store(0, Ordering::Relaxed);
                }
                counter.last_seen = now;
                counter.count.fetch_add(1, Ordering::Relaxed) + 1
            })
            .unwrap_or_default();
        let capacity = self.per_window_capacity(self.prefixes.len().saturating_add(1));
        let distinct_mutex = self
            .distinct_ips
            .entry(cluster_id)
            .or_insert_with(|| Mutex::new(DistinctIpWindow::new(now)));
        let mut distinct_guard = distinct_mutex
            .lock()
            .expect("l4 distinct-ip window mutex poisoned");
        if distinct_guard.ips.len() < capacity || distinct_guard.ips.contains(&ip) {
            distinct_guard.ips.insert(ip);
        }
        let distinct_ips = distinct_guard.ips.len();
        drop(distinct_guard);

        let window_mutex = self
            .prefixes
            .entry((cluster_id, key))
            .or_insert_with(|| Mutex::new(AggregateWindow::new(now)));
        let mut window = window_mutex
            .lock()
            .expect("l4 aggregate prefix window mutex poisoned");
        window.reset_if_stale(now);
        window.events = window.events.saturating_add(1);
        if window.ips.len() < capacity || window.ips.contains(&ip) {
            window.ips.insert(ip);
        }
        if kind.is_high_confidence() {
            window.high_confidence_events = window.high_confidence_events.saturating_add(1);
        }
        AggregateRecord {
            prefix: key,
            prefix_events: window.events,
            prefix_high_confidence_events: window.high_confidence_events,
            prefix_distinct_ips: window.ips.len(),
            distinct_ips_recent: distinct_ips,
            top_prefix_events,
        }
    }

    fn snapshot(&self) -> AggregateSnapshot {
        let now = Instant::now();
        self.sweep_if_needed(now);
        let distinct_ips_recent = self
            .distinct_ips
            .iter()
            .filter_map(|entry| {
                entry.value().lock().ok().and_then(|mut window| {
                    window.reset_if_stale(now);
                    Some(window.ips.len())
                })
            })
            .max()
            .unwrap_or_default();
        let pressure_level = surge_pressure_level(distinct_ips_recent);
        let (top_prefix, top_prefix_events) = self
            .prefix_counts
            .iter()
            .map(|entry| (entry.key().1.label(), entry.value().count.load(Ordering::Relaxed)))
            .max_by_key(|(_, count)| *count)
            .unwrap_or_default();
        AggregateSnapshot {
            distinct_ips_recent,
            pressure_level,
            top_prefix,
            top_prefix_events,
        }
    }

    fn sweep_if_needed(&self, now: Instant) {
        let now_ms = crate::utils::time::now_timestamp_millis();
        let last_ms = self.last_sweep_at_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last_ms) < L4_AGGREGATE_SWEEP_INTERVAL_MS {
            return;
        }
        if self
            .last_sweep_at_ms
            .compare_exchange(last_ms, now_ms, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.prefixes.retain(|_, window| {
            window
                .lock()
                .map(|window| now.duration_since(window.started_at) < L4_AGGREGATE_WINDOW)
                .unwrap_or(false)
        });
        self.distinct_ips.retain(|_, window| {
            window
                .lock()
                .map(|window| now.duration_since(window.started_at) < L4_AGGREGATE_WINDOW)
                .unwrap_or(false)
        });
        self.prefix_counts.retain(|_, window| {
            now.duration_since(window.last_seen) < L4_AGGREGATE_WINDOW
        });
    }
}

impl L4ExactCounterState {
    fn new() -> Self {
        Self {
            counters: DashMap::new(),
            last_sweep_at_ms: AtomicI64::new(0),
            capacity_override: None,
        }
    }

    #[cfg(test)]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            counters: DashMap::new(),
            last_sweep_at_ms: AtomicI64::new(0),
            capacity_override: Some(capacity.max(1)),
        }
    }

    fn capacity(&self) -> usize {
        self.capacity_override.unwrap_or_else(|| {
            let budget = MEMORY_GOVERNOR
                .snapshot(MEMORY_GOVERNOR.pingora_worker_threads())
                .cardinality_state_budget_bytes;
            (budget / 256).max(1).min(usize::MAX as u64) as usize
        })
    }

    fn increase_by(
        &self,
        cluster_id: i64,
        ip: IpAddr,
        kind: L4DefenseKind,
        period_secs: i64,
        amount: u64,
    ) -> L4ExactCounterIncrement {
        let now = Instant::now();
        let period = Duration::from_secs(period_secs.max(1) as u64);
        let amount = amount.max(1);
        self.sweep_if_needed(now);

        let key = (cluster_id, ip, kind.as_str());
        if !self.counters.contains_key(&key) && self.counters.len() >= self.capacity() {
            self.sweep_force(now);
            if self.counters.len() >= self.capacity() {
                return if kind.is_high_confidence() {
                    L4ExactCounterIncrement::CapacitySaturatedFailClosed
                } else {
                    L4ExactCounterIncrement::CapacitySaturatedAllowed
                };
            }
        }

        let entry = self.counters.entry(key).or_insert_with(|| {
            Mutex::new(ExactCounterWindow {
                started_at: now,
                count: 0,
                period,
            })
        });
        let mut window = entry
            .lock()
            .expect("l4 exact counter window mutex poisoned");
        if window.is_stale(now) || window.period != period {
            window.started_at = now;
            window.count = 0;
            window.period = period;
        }
        window.count = window.count.saturating_add(amount);
        L4ExactCounterIncrement::Count(window.count)
    }

    fn sweep_if_needed(&self, now: Instant) {
        let now_ms = crate::utils::time::now_timestamp_millis();
        let last_ms = self.last_sweep_at_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last_ms) < L4_EXACT_COUNTER_SWEEP_INTERVAL_MS {
            return;
        }
        if self
            .last_sweep_at_ms
            .compare_exchange(last_ms, now_ms, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.sweep_force(now);
        }
    }

    fn sweep_force(&self, now: Instant) {
        self.counters
            .retain(|_, window| window.lock().map(|w| !w.is_stale(now)).unwrap_or(false));
    }
}

impl ExactCounterWindow {
    fn is_stale(&self, now: Instant) -> bool {
        now.duration_since(self.started_at) >= self.period
    }
}

impl AggregateWindow {
    fn new(now: Instant) -> Self {
        Self {
            started_at: now,
            events: 0,
            high_confidence_events: 0,
            ips: HashSet::new(),
        }
    }

    fn reset_if_stale(&mut self, now: Instant) {
        if now.duration_since(self.started_at) >= L4_AGGREGATE_WINDOW {
            self.started_at = now;
            self.events = 0;
            self.high_confidence_events = 0;
            self.ips.clear();
        }
    }
}

impl DistinctIpWindow {
    fn new(now: Instant) -> Self {
        Self {
            started_at: now,
            ips: HashSet::new(),
        }
    }

    fn reset_if_stale(&mut self, now: Instant) {
        if now.duration_since(self.started_at) >= L4_AGGREGATE_WINDOW {
            self.started_at = now;
            self.ips.clear();
        }
    }
}

#[derive(Clone, Debug)]
struct AggregateRecord {
    prefix: L4AggregateKey,
    prefix_events: u64,
    prefix_high_confidence_events: u64,
    prefix_distinct_ips: usize,
    distinct_ips_recent: usize,
    top_prefix_events: u64,
}

impl L4AggregateKey {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                Self::V4([octets[0], octets[1], octets[2]])
            }
            IpAddr::V6(ip) => {
                let segments = ip.segments();
                Self::V6([segments[0], segments[1], segments[2], segments[3]])
            }
        }
    }

    fn label(self) -> String {
        match self {
            Self::V4([a, b, c]) => format!("{a}.{b}.{c}.0/24"),
            Self::V6([a, b, c, d]) => format!("{a:x}:{b:x}:{c:x}:{d:x}::/64"),
        }
    }

    fn ip_net(self) -> Option<IpNet> {
        match self {
            Self::V4([a, b, c]) => ipnet::Ipv4Net::new(Ipv4Addr::new(a, b, c, 0), 24)
                .ok()
                .map(IpNet::V4),
            Self::V6([a, b, c, d]) => {
                let addr = Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0);
                ipnet::Ipv6Net::new(addr, 64).ok().map(IpNet::V6)
            }
        }
    }
}

impl L4DefenseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TcpActiveLimit => "tcp_active_limit",
            Self::TcpAdmissionReject => "tcp_admission_reject",
            Self::TcpConnectionChurn => "tcp_connection_churn",
            Self::TcpAcceptedChurn => "tcp_accepted_churn",
            Self::TcpPressureIdleClose => "tcp_pressure_idle_close",
            Self::TcpSlowFirstByte => "tcp_slow_first_byte",
            Self::TcpProxyEarlyCloseOrTinyPayload => "tcp_proxy_early_close_or_tiny_payload",
            Self::TlsHandshakeFail => "tls_handshake_fail",
            Self::TlsPartialClientHello => "tls_partial_client_hello",
            Self::TlsInvalidProbe => "tls_invalid_probe",
            Self::TlsPlaintextConnectOnTls => "tls_plaintext_connect_on_tls",
            Self::TlsSlowClientHello => "tls_slow_client_hello",
            Self::TlsHandshakeThenNoHttp => "tls_handshake_then_no_http",
            Self::HttpSlowHeader => "http_slow_header",
            Self::HttpEarlyCloseOrTinyRequest => "http_early_close_or_tiny_request",
            Self::SniProbeFail => "sni_probe_fail",
            Self::H2StreamAdmissionReject => "h2_stream_admission_reject",
            Self::H2RapidReset => "h2_rapid_reset",
            Self::H2DownstreamCancel => "h2_downstream_cancel",
            Self::H2RequestChurn => "h2_request_churn",
            Self::H2ConnectionAbuse => "h2_connection_abuse",
            Self::SynBacklogPressure => "syn_backlog_pressure",
            Self::UdpSessionFlood => "udp_session_flood",
            Self::UdpAdmissionReject => "udp_admission_reject",
            Self::UdpQueueFull => "udp_queue_full",
            Self::QuicNewRouteFlood => "quic_new_route_flood",
            Self::QuicIncompleteClientHello => "quic_incomplete_client_hello",
            Self::QuicPendingReject => "quic_pending_reject",
            Self::QuicReassemblyReject => "quic_reassembly_reject",
            Self::QuicNoRoute => "quic_no_route",
            Self::H3AdmissionReject => "h3_admission_reject",
        }
    }

    fn threshold_multiplier(self) -> u32 {
        match self {
            Self::TcpActiveLimit
            | Self::TcpAdmissionReject
            | Self::TcpConnectionChurn
            | Self::TcpProxyEarlyCloseOrTinyPayload
            | Self::TcpSlowFirstByte
            | Self::TlsHandshakeThenNoHttp
            | Self::HttpEarlyCloseOrTinyRequest
            | Self::H2StreamAdmissionReject
            | Self::H2RapidReset
            | Self::H2RequestChurn
            | Self::H2ConnectionAbuse
            | Self::SynBacklogPressure
            | Self::UdpSessionFlood
            | Self::UdpAdmissionReject
            | Self::QuicPendingReject
            | Self::QuicReassemblyReject
            | Self::H3AdmissionReject => 1,
            Self::TcpPressureIdleClose
            | Self::TlsHandshakeFail
            | Self::TlsPartialClientHello
            | Self::TlsInvalidProbe
            | Self::TlsPlaintextConnectOnTls
            | Self::TlsSlowClientHello
            | Self::HttpSlowHeader
            | Self::SniProbeFail
            | Self::H2DownstreamCancel
            | Self::UdpQueueFull
            | Self::QuicIncompleteClientHello => 2,
            Self::TcpAcceptedChurn | Self::QuicNewRouteFlood | Self::QuicNoRoute => 4,
        }
    }

    fn is_active_limit(self) -> bool {
        matches!(self, Self::TcpActiveLimit)
    }

    fn is_admission_reject(self) -> bool {
        matches!(
            self,
            Self::TcpAdmissionReject
                | Self::TcpConnectionChurn
                | Self::TcpAcceptedChurn
                | Self::TcpProxyEarlyCloseOrTinyPayload
                | Self::TlsHandshakeThenNoHttp
                | Self::HttpEarlyCloseOrTinyRequest
                | Self::UdpAdmissionReject
                | Self::H3AdmissionReject
                | Self::H2StreamAdmissionReject
                | Self::QuicPendingReject
        )
    }

    fn is_slow_close(self) -> bool {
        matches!(
            self,
            Self::TcpPressureIdleClose
                | Self::TcpSlowFirstByte
                | Self::TcpProxyEarlyCloseOrTinyPayload
                | Self::TlsPartialClientHello
                | Self::TlsSlowClientHello
                | Self::TlsHandshakeThenNoHttp
                | Self::HttpSlowHeader
                | Self::HttpEarlyCloseOrTinyRequest
                | Self::H2DownstreamCancel
        )
    }

    fn is_h2_defense(self) -> bool {
        matches!(
            self,
            Self::H2StreamAdmissionReject
                | Self::H2RapidReset
                | Self::H2DownstreamCancel
                | Self::H2RequestChurn
                | Self::H2ConnectionAbuse
        )
    }

    fn is_tls_probe(self) -> bool {
        matches!(
            self,
            Self::TlsPartialClientHello
                | Self::TlsInvalidProbe
                | Self::TlsPlaintextConnectOnTls
                | Self::TlsSlowClientHello
                | Self::TlsHandshakeThenNoHttp
                | Self::SniProbeFail
        )
    }

    fn is_completed_handshake(self) -> bool {
        matches!(
            self,
            Self::TcpAcceptedChurn
                | Self::TcpProxyEarlyCloseOrTinyPayload
                | Self::TlsHandshakeThenNoHttp
                | Self::HttpEarlyCloseOrTinyRequest
        )
    }

    fn is_syn_pressure(self) -> bool {
        matches!(self, Self::SynBacklogPressure)
    }

    fn is_quic_pressure(self) -> bool {
        matches!(
            self,
            Self::QuicNewRouteFlood
                | Self::QuicIncompleteClientHello
                | Self::QuicPendingReject
                | Self::QuicReassemblyReject
                | Self::QuicNoRoute
                | Self::H3AdmissionReject
        )
    }

    fn is_high_confidence(self) -> bool {
        self.threshold_multiplier() == 1
    }
}

pub fn pressure_level_from_utilization_pct(
    memory_pressure: MemoryPressureLevel,
    connection_pct: u64,
    quic_pct: Option<u64>,
) -> L4PressureLevel {
    let memory_level = match memory_pressure {
        MemoryPressureLevel::Normal => L4PressureLevel::Normal,
        MemoryPressureLevel::Elevated => L4PressureLevel::Elevated,
        MemoryPressureLevel::High => L4PressureLevel::High,
        MemoryPressureLevel::Critical => L4PressureLevel::Critical,
    };
    let utilization_pct = connection_pct.max(quic_pct.unwrap_or(0));
    let utilization_level = if utilization_pct >= 95 {
        L4PressureLevel::Critical
    } else if utilization_pct >= 85 {
        L4PressureLevel::High
    } else if utilization_pct >= 70 {
        L4PressureLevel::Elevated
    } else {
        L4PressureLevel::Normal
    };
    memory_level.max(utilization_level)
}

pub fn pressure_level_from_utilization_pct_ext(
    memory_pressure: MemoryPressureLevel,
    connection_pct: u64,
    quic_pct: Option<u64>,
    fd_pct: Option<u64>,
    aggregate_level: L4PressureLevel,
) -> L4PressureLevel {
    pressure_level_from_utilization_pct(memory_pressure, connection_pct, quic_pct)
        .max(level_from_pct(fd_pct.unwrap_or(0)))
        .max(aggregate_level)
        .max(crate::kernel_syn_defense::current_pressure_level())
}

pub fn current_pressure_level() -> L4PressureLevel {
    let snapshot = MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads());
    let connection_pct = snapshot
        .connection_admission_used_bytes
        .saturating_mul(100)
        .saturating_div(snapshot.connection_budget_bytes.max(1));
    aggregate_pressure_level(
        snapshot.memory_pressure_level,
        connection_pct,
        None,
        Some(snapshot.fd_used_pct),
    )
}

pub fn aggregate_pressure_level(
    memory_pressure: MemoryPressureLevel,
    connection_pct: u64,
    quic_pct: Option<u64>,
    fd_pct: Option<u64>,
) -> L4PressureLevel {
    pressure_level_from_utilization_pct_ext(
        memory_pressure,
        connection_pct,
        quic_pct,
        fd_pct,
        L4_AGGREGATES.snapshot().pressure_level,
    )
}

pub fn current_pressure_level_with_quic_usage(
    routes: usize,
    route_limit: usize,
    pending_routes: usize,
    pending_route_limit: usize,
    reassembly_bytes: usize,
    reassembly_budget_bytes: usize,
) -> L4PressureLevel {
    let route_pct = usage_pct(routes, route_limit);
    let pending_pct = usage_pct(pending_routes, pending_route_limit);
    let reassembly_pct = usage_pct(reassembly_bytes, reassembly_budget_bytes);
    let quic_pct = route_pct.max(pending_pct).max(reassembly_pct);
    let snapshot = MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads());
    let connection_pct = snapshot
        .connection_admission_used_bytes
        .saturating_mul(100)
        .saturating_div(snapshot.connection_budget_bytes.max(1));
    aggregate_pressure_level(
        snapshot.memory_pressure_level,
        connection_pct,
        Some(quic_pct),
        Some(snapshot.fd_used_pct),
    )
}

fn usage_pct(used: usize, limit: usize) -> u64 {
    (used as u64)
        .saturating_mul(100)
        .saturating_div((limit.max(1)) as u64)
}

fn level_from_pct(pct: u64) -> L4PressureLevel {
    if pct >= 95 {
        L4PressureLevel::Critical
    } else if pct >= 85 {
        L4PressureLevel::High
    } else if pct >= 70 {
        L4PressureLevel::Elevated
    } else {
        L4PressureLevel::Normal
    }
}

fn surge_pressure_level(distinct_ips: usize) -> L4PressureLevel {
    if distinct_ips >= L4_SURGE_DISTINCT_IP_CRITICAL {
        L4PressureLevel::Critical
    } else if distinct_ips >= L4_SURGE_DISTINCT_IP_HIGH {
        L4PressureLevel::High
    } else if distinct_ips >= L4_SURGE_DISTINCT_IP_ELEVATED {
        L4PressureLevel::Elevated
    } else {
        L4PressureLevel::Normal
    }
}

pub fn tcp_active_limit_per_ip_for_level(total_limit: usize, level: L4PressureLevel) -> usize {
    let total_limit = total_limit.max(1);
    match level {
        L4PressureLevel::Normal => (total_limit / 16).clamp(8_192, 65_536),
        L4PressureLevel::Elevated => (total_limit / 128).clamp(1_024, 8_192),
        L4PressureLevel::High => (total_limit / 1_024).clamp(128, 2_048),
        L4PressureLevel::Critical => (total_limit / 4_096).clamp(16, 512),
    }
}

pub fn current_tcp_active_limit_per_ip() -> usize {
    let total_limit = MEMORY_GOVERNOR
        .limit_for(AdmissionClass::TcpConnection)
        .max(1);
    tcp_active_limit_per_ip_for_level(total_limit, current_pressure_level())
}

pub fn first_byte_timeout(level: L4PressureLevel) -> Duration {
    match level {
        L4PressureLevel::Normal => Duration::from_secs(2),
        L4PressureLevel::Elevated => Duration::from_secs(1),
        L4PressureLevel::High => Duration::from_millis(500),
        L4PressureLevel::Critical => Duration::from_millis(250),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientHelloTimeouts {
    pub total: Duration,
    pub idle: Duration,
}

pub fn client_hello_timeouts(level: L4PressureLevel) -> ClientHelloTimeouts {
    match level {
        L4PressureLevel::Normal => ClientHelloTimeouts {
            total: Duration::from_secs(2),
            idle: Duration::from_millis(500),
        },
        L4PressureLevel::Elevated => ClientHelloTimeouts {
            total: Duration::from_secs(1),
            idle: Duration::from_millis(300),
        },
        L4PressureLevel::High => ClientHelloTimeouts {
            total: Duration::from_millis(750),
            idle: Duration::from_millis(200),
        },
        L4PressureLevel::Critical => ClientHelloTimeouts {
            total: Duration::from_millis(500),
            idle: Duration::from_millis(100),
        },
    }
}

pub fn clamp_tls_handshake_timeout(base: Duration, level: L4PressureLevel) -> Duration {
    base.min(client_hello_timeouts(level).total)
}

pub fn clamp_http_read_timeout(base: Duration, level: L4PressureLevel) -> Duration {
    match level {
        L4PressureLevel::Normal => base,
        L4PressureLevel::Elevated => base.min(Duration::from_secs(5)),
        L4PressureLevel::High => base.min(Duration::from_secs(2)),
        L4PressureLevel::Critical => base.min(Duration::from_secs(1)),
    }
}

pub fn quic_new_route_limit(level: L4PressureLevel) -> usize {
    match level {
        L4PressureLevel::Normal => 128,
        L4PressureLevel::Elevated => 32,
        L4PressureLevel::High => 8,
        L4PressureLevel::Critical => 2,
    }
}

pub fn quic_pending_route_timeout(level: L4PressureLevel) -> Duration {
    match level {
        L4PressureLevel::Normal => Duration::from_secs(3),
        L4PressureLevel::Elevated => Duration::from_secs(2),
        L4PressureLevel::High => Duration::from_secs(1),
        L4PressureLevel::Critical => Duration::from_millis(500),
    }
}

pub fn quic_pending_datagrams_limit(level: L4PressureLevel) -> usize {
    match level {
        L4PressureLevel::Normal | L4PressureLevel::Elevated => 4,
        L4PressureLevel::High => 2,
        L4PressureLevel::Critical => 1,
    }
}

pub fn quic_pending_ranges_limit(level: L4PressureLevel) -> usize {
    match level {
        L4PressureLevel::Normal | L4PressureLevel::Elevated => 16,
        L4PressureLevel::High => 8,
        L4PressureLevel::Critical => 4,
    }
}

pub fn effective_l4_threshold(
    base_threshold: u32,
    kind: L4DefenseKind,
    level: L4PressureLevel,
) -> u32 {
    let threshold = base_threshold
        .max(1)
        .saturating_mul(kind.threshold_multiplier());
    match level {
        L4PressureLevel::Normal | L4PressureLevel::Elevated => threshold.max(1),
        L4PressureLevel::High => (threshold / 2).max(2),
        L4PressureLevel::Critical => (threshold / 4).max(2),
    }
}

pub fn is_l4_blocked(
    config_store: &ConfigStore,
    waf_state: &Arc<WafStateManager>,
    ip: IpAddr,
) -> bool {
    if waf_state.is_whitelisted(ip, 0) {
        return false;
    }
    if waf_state.is_blocked(ip, 0) {
        return true;
    }
    let cluster_scope =
        crate::special_defense::cluster_block_scope_id(config_store.get_node_cluster_id_sync());
    cluster_scope != 0
        && !waf_state.is_whitelisted(ip, cluster_scope)
        && waf_state.is_blocked(ip, cluster_scope)
}

pub fn record_l4_event(
    config_store: &ConfigStore,
    waf_state: &Arc<WafStateManager>,
    node_id: i64,
    ip: IpAddr,
    kind: L4DefenseKind,
    detail: impl Into<String>,
) -> L4DefenseVerdict {
    record_l4_event_with_pressure(
        config_store,
        waf_state,
        node_id,
        ip,
        kind,
        detail,
        current_pressure_level(),
    )
}

/// Record TCP connection churn during elevated pressure (Moderate or High).
///
/// Returns None if pressure is Normal — pure open-close churn detection in
/// Normal pressure relies on record_tcp_accepted_churn and
/// record_completed_handshake_event, which bypass the pressure gate.
pub fn record_tcp_connection_churn_under_pressure<F>(
    config_store: &ConfigStore,
    waf_state: &Arc<WafStateManager>,
    node_id: i64,
    ip: IpAddr,
    detail: F,
) -> Option<L4DefenseVerdict>
where
    F: FnOnce() -> String,
{
    let pressure_level = current_pressure_level();
    if pressure_level == L4PressureLevel::Normal {
        return None;
    }
    Some(record_l4_event_with_pressure(
        config_store,
        waf_state,
        node_id,
        ip,
        L4DefenseKind::TcpConnectionChurn,
        detail(),
        pressure_level,
    ))
}

/// Record TCP accepted-then-closed churn (socket accept followed by rapid close
/// with minimal or no data transfer).
///
/// This path does NOT require elevated pressure — it detects pure open-close
/// churn in Normal pressure. Returns None only if empty_connection_flood policy
/// is not configured for the cluster.
pub fn record_tcp_accepted_churn<F>(
    config_store: &ConfigStore,
    waf_state: &Arc<WafStateManager>,
    node_id: i64,
    ip: IpAddr,
    detail: F,
) -> Option<L4DefenseVerdict>
where
    F: FnOnce() -> String,
{
    let cluster_id = config_store.get_node_cluster_id_sync();
    config_store.get_empty_connection_flood_config_for_cluster_sync(cluster_id)?;
    Some(record_l4_event_with_pressure(
        config_store,
        waf_state,
        node_id,
        ip,
        L4DefenseKind::TcpAcceptedChurn,
        detail(),
        current_pressure_level(),
    ))
}

/// Record completed-handshake events (early close with minimal data, connection
/// lifetime churn).
///
/// This path does NOT require elevated pressure — it detects open-close churn
/// patterns in Normal pressure. Returns None only if empty_connection_flood
/// policy is not configured for the cluster.
pub fn record_completed_handshake_event<F>(
    config_store: &ConfigStore,
    waf_state: &Arc<WafStateManager>,
    node_id: i64,
    ip: IpAddr,
    kind: L4DefenseKind,
    amount: u64,
    detail: F,
) -> Option<L4DefenseVerdict>
where
    F: FnOnce() -> String,
{
    debug_assert!(kind.is_completed_handshake());
    let cluster_id = config_store.get_node_cluster_id_sync();
    config_store.get_empty_connection_flood_config_for_cluster_sync(cluster_id)?;
    Some(record_l4_event_weighted_with_pressure(
        config_store,
        waf_state,
        node_id,
        ip,
        kind,
        amount,
        detail(),
        current_pressure_level(),
    ))
}

pub fn record_l4_event_with_pressure(
    config_store: &ConfigStore,
    waf_state: &Arc<WafStateManager>,
    node_id: i64,
    ip: IpAddr,
    kind: L4DefenseKind,
    detail: impl Into<String>,
    pressure_level: L4PressureLevel,
) -> L4DefenseVerdict {
    record_l4_event_weighted_with_pressure(
        config_store,
        waf_state,
        node_id,
        ip,
        kind,
        1,
        detail,
        pressure_level,
    )
}

pub fn record_l4_event_weighted_with_pressure(
    config_store: &ConfigStore,
    waf_state: &Arc<WafStateManager>,
    node_id: i64,
    ip: IpAddr,
    kind: L4DefenseKind,
    amount: u64,
    detail: impl Into<String>,
    pressure_level: L4PressureLevel,
) -> L4DefenseVerdict {
    record_l4_event_scored(
        config_store,
        waf_state,
        node_id,
        ip,
        kind,
        amount,
        L4EventContext::new(detail, pressure_level),
    )
}

pub fn record_l4_event_scored(
    config_store: &ConfigStore,
    waf_state: &Arc<WafStateManager>,
    node_id: i64,
    ip: IpAddr,
    kind: L4DefenseKind,
    amount: u64,
    context: L4EventContext,
) -> L4DefenseVerdict {
    let ip = canonical_l4_ip(ip);
    let amount = amount.max(1);
    let cluster_id = config_store.get_node_cluster_id_sync();
    let Some(config) = config_store.get_empty_connection_flood_config_for_cluster_sync(cluster_id)
    else {
        if amount == 1 {
            tracing::debug!(
                "L4 defense {} event for {} skipped: empty_connection_flood policy not configured for cluster {}",
                kind.as_str(),
                ip,
                cluster_id
            );
        }
        L4_METRICS.record(kind, L4DefenseVerdict::Disabled);
        return L4DefenseVerdict::Disabled;
    };

    let cluster_scope = crate::special_defense::cluster_block_scope_id(cluster_id);
    if waf_state.is_whitelisted(ip, cluster_scope) {
        L4_METRICS.record(kind, L4DefenseVerdict::Allowed);
        return L4DefenseVerdict::Allowed;
    }
    if cluster_scope != 0 && waf_state.is_blocked(ip, cluster_scope) {
        L4_METRICS.record(kind, L4DefenseVerdict::AlreadyBlocked);
        drain_l4_connections_for_ip(ip, kind, "already_blocked_cluster");
        return L4DefenseVerdict::AlreadyBlocked;
    }
    if waf_state.is_blocked(ip, 0) {
        L4_METRICS.record(kind, L4DefenseVerdict::AlreadyBlocked);
        drain_l4_connections_for_ip(ip, kind, "already_blocked_global");
        return L4DefenseVerdict::AlreadyBlocked;
    }

    let aggregate = L4_AGGREGATES.record(cluster_id, ip, kind);
    L4_METRICS.record_prefix_event();
    let aggregate_drop = should_apply_aggregate_emergency_drop(&aggregate, kind, config.threshold);
    if aggregate_drop {
        if should_block_prefix(&aggregate, kind, config.threshold)
            && !prefix_has_whitelisted_ip(waf_state, aggregate.prefix, cluster_scope)
        {
            block_cluster_prefix(
                waf_state,
                aggregate.prefix,
                cluster_scope,
                config.block_secs,
                config.use_local_firewall,
            );
            L4_METRICS.record_prefix_blocked();
        }
    }

    let pressure_level = context
        .pressure_level
        .max(surge_pressure_level(aggregate.distinct_ips_recent));
    let threshold = effective_l4_threshold(config.threshold, kind, pressure_level);
    let exact_count =
        L4_EXACT_COUNTERS.increase_by(cluster_id, ip, kind, config.period_secs, amount);
    let waf_count = waf_state.increase_counter_by(
        format!("L4:{}:cluster:{}:{}", kind.as_str(), cluster_id, ip),
        config.period_secs,
        amount,
    );
    let count = match exact_count {
        L4ExactCounterIncrement::Count(count) => count.max(waf_count),
        L4ExactCounterIncrement::CapacitySaturatedFailClosed => {
            L4_METRICS.record_exact_counter_saturated();
            warn_l4_counter_saturation("fail_closed");
            u64::from(threshold).saturating_add(1)
        }
        L4ExactCounterIncrement::CapacitySaturatedAllowed => {
            L4_METRICS.record_exact_counter_saturated();
            warn_l4_counter_saturation("fail_open_low_confidence");
            waf_count
        }
    };
    if count <= u64::from(threshold) {
        let verdict = if aggregate_drop {
            L4DefenseVerdict::AggregateDropped
        } else {
            L4DefenseVerdict::Allowed
        };
        L4_METRICS.record(kind, verdict);
        return verdict;
    }

    waf_state.block_ip(
        ip,
        cluster_scope,
        config.block_secs,
        Some("cluster"),
        false,
        config.use_local_firewall,
    );
    drain_l4_connections_for_ip(ip, kind, "blocked");

    let detail = context.detail;
    crate::rpc::ip_report::report_item(IpReportMessage {
        ip_list_id: 0,
        value: ip.to_string(),
        ip_from: String::new(),
        ip_to: String::new(),
        expired_at: crate::utils::time::now_timestamp() + config.block_secs.max(1),
        reason: format!(
            "L4 defense {} cluster={} pressure={} threshold={} count={}{}",
            kind.as_str(),
            cluster_id,
            pressure_level.as_str(),
            threshold,
            count,
            if detail.is_empty() {
                String::new()
            } else {
                format!(" detail={}", detail)
            }
        ),
        r#type: String::new(),
        list_kind: IpReportKind::Black,
        event_level: "error".to_string(),
        node_id,
        server_id: 0,
        source_node_id: node_id,
        source_server_id: 0,
        source_http_firewall_policy_id: 0,
        source_http_firewall_rule_group_id: 0,
        source_http_firewall_rule_set_id: 0,
        source_url: String::new(),
        source_user_agent: String::new(),
        source_category: format!("l4_defense:cluster:{}:{}", cluster_id, kind.as_str()),
    });

    let now_ms = crate::utils::time::now_timestamp_millis();
    let last_warn_ms = LAST_BLOCK_WARN_AT_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last_warn_ms) >= L4_BLOCK_WARN_INTERVAL_MS
        && LAST_BLOCK_WARN_AT_MS
            .compare_exchange(last_warn_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        warn!(
            "L4 defense blocked {} in cluster {} for {}s kind={} pressure={} count={} threshold={} policy={} detail={}",
            ip,
            cluster_id,
            config.block_secs,
            kind.as_str(),
            pressure_level.as_str(),
            count,
            threshold,
            config.policy_name,
            detail
        );
    } else {
        debug!(
            "L4 defense block suppressed from process warn ip={} cluster={} kind={} pressure={} count={} threshold={} policy={} detail={}",
            ip,
            cluster_id,
            kind.as_str(),
            pressure_level.as_str(),
            count,
            threshold,
            config.policy_name,
            detail
        );
    }
    L4_METRICS.record(kind, L4DefenseVerdict::Blocked);
    L4DefenseVerdict::Blocked
}

fn drain_l4_connections_for_ip(ip: IpAddr, kind: L4DefenseKind, reason: &'static str) {
    let drained = crate::l4_connection_registry::drain_ip(ip);
    if drained > 0 {
        crate::logging::report_node_log(
            "warn".to_string(),
            "l4_recovery".to_string(),
            format!(
                "ip={} kind={} reason={} drained_connections={}",
                ip,
                kind.as_str(),
                reason,
                drained
            ),
            0,
        );
    }
}

fn warn_l4_counter_saturation(mode: &'static str) {
    let now_ms = crate::utils::time::now_timestamp_millis();
    let last_warn_ms = LAST_COUNTER_SATURATION_WARN_AT_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last_warn_ms) >= L4_BLOCK_WARN_INTERVAL_MS
        && LAST_COUNTER_SATURATION_WARN_AT_MS
            .compare_exchange(last_warn_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        warn!(
            "L4 exact counter capacity saturated; mode={} capacity={}",
            mode, L4_EXACT_COUNTER_CAPACITY
        );
    }
}

fn should_apply_aggregate_emergency_drop(
    aggregate: &AggregateRecord,
    kind: L4DefenseKind,
    base_threshold: u32,
) -> bool {
    let base = u64::from(base_threshold.max(1));
    let prefix_events_threshold = base
        .saturating_mul(kind.threshold_multiplier() as u64)
        .saturating_mul(8)
        .max(64);
    aggregate.prefix_events >= prefix_events_threshold
        || aggregate.distinct_ips_recent >= L4_SURGE_DISTINCT_IP_HIGH
        || aggregate.top_prefix_events >= prefix_events_threshold.saturating_mul(2)
}

fn should_block_prefix(
    aggregate: &AggregateRecord,
    kind: L4DefenseKind,
    base_threshold: u32,
) -> bool {
    if !kind.is_high_confidence() {
        return false;
    }
    let base = u64::from(base_threshold.max(1));
    let high_conf_threshold = base.saturating_mul(16).max(128);
    aggregate.prefix_high_confidence_events >= high_conf_threshold
        && aggregate.prefix_distinct_ips >= 16
}

fn prefix_has_whitelisted_ip(
    waf_state: &Arc<WafStateManager>,
    prefix: L4AggregateKey,
    cluster_scope: i64,
) -> bool {
    let Some(net) = prefix.ip_net() else {
        return false;
    };
    waf_state.has_whitelist_overlapping_network(net, cluster_scope)
}

fn block_cluster_prefix(
    waf_state: &Arc<WafStateManager>,
    prefix: L4AggregateKey,
    cluster_scope: i64,
    block_secs: i64,
    use_local_firewall: bool,
) {
    let Some(net) = prefix.ip_net() else {
        return;
    };
    waf_state.block_network(
        net,
        cluster_scope,
        block_secs,
        Some("cluster"),
        use_local_firewall,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::{EmptyConnectionFloodConfig, HTTPFirewallPolicy, ServerConfig};
    use std::collections::HashMap;

    #[test]
    fn confidence_multipliers_match_policy() {
        assert_eq!(L4DefenseKind::TcpAdmissionReject.threshold_multiplier(), 1);
        assert_eq!(L4DefenseKind::TcpConnectionChurn.threshold_multiplier(), 1);
        assert_eq!(L4DefenseKind::TcpAcceptedChurn.threshold_multiplier(), 4);
        assert_eq!(
            L4DefenseKind::TcpProxyEarlyCloseOrTinyPayload.threshold_multiplier(),
            1
        );
        assert_eq!(L4DefenseKind::TcpSlowFirstByte.threshold_multiplier(), 1);
        assert_eq!(
            L4DefenseKind::TlsHandshakeThenNoHttp.threshold_multiplier(),
            1
        );
        assert_eq!(
            L4DefenseKind::HttpEarlyCloseOrTinyRequest.threshold_multiplier(),
            1
        );
        assert_eq!(L4DefenseKind::TlsSlowClientHello.threshold_multiplier(), 2);
        assert_eq!(L4DefenseKind::HttpSlowHeader.threshold_multiplier(), 2);
        assert_eq!(L4DefenseKind::UdpQueueFull.threshold_multiplier(), 2);
        assert_eq!(L4DefenseKind::QuicNoRoute.threshold_multiplier(), 4);
    }

    #[test]
    fn pressure_level_follows_connection_quic_and_memory_pressure() {
        assert_eq!(
            pressure_level_from_utilization_pct(MemoryPressureLevel::Normal, 69, None),
            L4PressureLevel::Normal
        );
        assert_eq!(
            pressure_level_from_utilization_pct(MemoryPressureLevel::Normal, 70, None),
            L4PressureLevel::Elevated
        );
        assert_eq!(
            pressure_level_from_utilization_pct(MemoryPressureLevel::Normal, 85, None),
            L4PressureLevel::High
        );
        assert_eq!(
            pressure_level_from_utilization_pct(MemoryPressureLevel::Normal, 95, None),
            L4PressureLevel::Critical
        );
        assert_eq!(
            pressure_level_from_utilization_pct(MemoryPressureLevel::High, 1, Some(1)),
            L4PressureLevel::High
        );
        assert_eq!(
            pressure_level_from_utilization_pct(MemoryPressureLevel::Elevated, 1, Some(95)),
            L4PressureLevel::Critical
        );
    }

    #[test]
    fn tcp_active_limit_per_ip_tightens_by_pressure() {
        let total = 1_048_576;
        assert_eq!(
            tcp_active_limit_per_ip_for_level(total, L4PressureLevel::Normal),
            65_536
        );
        assert_eq!(
            tcp_active_limit_per_ip_for_level(total, L4PressureLevel::Elevated),
            8_192
        );
        assert_eq!(
            tcp_active_limit_per_ip_for_level(total, L4PressureLevel::High),
            1_024
        );
        assert_eq!(
            tcp_active_limit_per_ip_for_level(total, L4PressureLevel::Critical),
            256
        );
        assert_eq!(
            tcp_active_limit_per_ip_for_level(16_384, L4PressureLevel::Critical),
            16
        );
    }

    #[test]
    fn effective_threshold_tightens_under_high_and_critical_pressure() {
        assert_eq!(
            effective_l4_threshold(
                100,
                L4DefenseKind::TcpAdmissionReject,
                L4PressureLevel::Normal
            ),
            100
        );
        assert_eq!(
            effective_l4_threshold(100, L4DefenseKind::QuicNoRoute, L4PressureLevel::Elevated),
            400
        );
        assert_eq!(
            effective_l4_threshold(100, L4DefenseKind::QuicNoRoute, L4PressureLevel::High),
            200
        );
        assert_eq!(
            effective_l4_threshold(100, L4DefenseKind::QuicNoRoute, L4PressureLevel::Critical),
            100
        );
        assert_eq!(
            effective_l4_threshold(1, L4DefenseKind::TcpAdmissionReject, L4PressureLevel::High),
            2
        );
        assert_eq!(
            effective_l4_threshold(
                1,
                L4DefenseKind::TcpAdmissionReject,
                L4PressureLevel::Critical
            ),
            2
        );
    }

    #[test]
    fn adaptive_deadlines_match_policy() {
        assert_eq!(
            first_byte_timeout(L4PressureLevel::Normal),
            Duration::from_secs(2)
        );
        assert_eq!(
            first_byte_timeout(L4PressureLevel::Critical),
            Duration::from_millis(250)
        );
        assert_eq!(
            client_hello_timeouts(L4PressureLevel::High),
            ClientHelloTimeouts {
                total: Duration::from_millis(750),
                idle: Duration::from_millis(200),
            }
        );
        assert_eq!(
            clamp_http_read_timeout(Duration::from_secs(30), L4PressureLevel::Elevated),
            Duration::from_secs(5)
        );
        assert_eq!(
            clamp_tls_handshake_timeout(Duration::from_secs(10), L4PressureLevel::Critical),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn quic_adaptive_limits_match_policy() {
        assert_eq!(quic_new_route_limit(L4PressureLevel::Normal), 128);
        assert_eq!(quic_new_route_limit(L4PressureLevel::Elevated), 32);
        assert_eq!(quic_new_route_limit(L4PressureLevel::High), 8);
        assert_eq!(quic_new_route_limit(L4PressureLevel::Critical), 2);
        assert_eq!(
            quic_pending_route_timeout(L4PressureLevel::Critical),
            Duration::from_millis(500)
        );
        assert_eq!(quic_pending_datagrams_limit(L4PressureLevel::Critical), 1);
        assert_eq!(quic_pending_ranges_limit(L4PressureLevel::High), 8);
    }

    #[test]
    fn aggregate_pressure_level_includes_fd_and_prefix_surge() {
        assert_eq!(
            aggregate_pressure_level(MemoryPressureLevel::Normal, 1, None, Some(85)),
            L4PressureLevel::High
        );
        assert_eq!(surge_pressure_level(999), L4PressureLevel::Normal);
        assert_eq!(surge_pressure_level(1_000), L4PressureLevel::Elevated);
        assert_eq!(surge_pressure_level(5_000), L4PressureLevel::High);
        assert_eq!(surge_pressure_level(10_000), L4PressureLevel::Critical);
    }

    #[test]
    fn exact_l4_counter_capacity_fails_closed_for_high_confidence() {
        let counters = L4ExactCounterState::with_capacity(1);
        let first_ip: IpAddr = "198.51.100.10".parse().unwrap();
        let second_ip: IpAddr = "198.51.100.11".parse().unwrap();

        assert_eq!(
            counters.increase_by(1, first_ip, L4DefenseKind::TcpAdmissionReject, 60, 1),
            L4ExactCounterIncrement::Count(1)
        );
        assert_eq!(
            counters.increase_by(1, second_ip, L4DefenseKind::TcpAdmissionReject, 60, 1),
            L4ExactCounterIncrement::CapacitySaturatedFailClosed
        );
        assert_eq!(
            counters.increase_by(1, second_ip, L4DefenseKind::QuicNoRoute, 60, 1),
            L4ExactCounterIncrement::CapacitySaturatedAllowed
        );
    }

    #[test]
    fn active_ip_tracker_releases_permit_on_drop() {
        let ip: IpAddr = "203.0.113.250".parse().unwrap();
        let permit = try_acquire_tcp_active_ip(ip, 1).expect("first permit");
        assert!(try_acquire_tcp_active_ip(ip, 1).is_none());
        drop(permit);
        assert!(try_acquire_tcp_active_ip(ip, 1).is_some());
    }

    fn test_firewall_policy(
        is_on: bool,
        max_empty_connections: u32,
        period: i32,
        block_seconds: i32,
    ) -> HTTPFirewallPolicy {
        HTTPFirewallPolicy {
            id: 1,
            is_on: true,
            name: "l4-test-policy".to_string(),
            inbound: None,
            outbound: None,
            empty_connection_flood: Some(EmptyConnectionFloodConfig {
                is_on,
                max_empty_connections,
                period,
                block_seconds,
            }),
            tls_exhaustion_attack: None,
            cc_config: None,
            block_options: None,
            page_options: None,
            captcha_options: None,
            js_cookie_options: None,
            max_request_body_size: 0,
            deny_country_html: String::new(),
            deny_province_html: String::new(),
            use_local_firewall: false,
            syn_flood: None,
            mode: String::new(),
            candidate_rules: None,
            candidate_traffic_pct: 0,
            candidate_version: 0,
        }
    }

    async fn store_with_empty_connection_flood(
        is_on: bool,
        max_empty_connections: u32,
    ) -> ConfigStore {
        store_with_empty_connection_flood_for_cluster(is_on, max_empty_connections, 12).await
    }

    async fn store_with_empty_connection_flood_for_cluster(
        is_on: bool,
        max_empty_connections: u32,
        cluster_id: i64,
    ) -> ConfigStore {
        let store = ConfigStore::new();
        let server = Arc::new(ServerConfig {
            id: Some(1),
            cluster_id,
            http_firewall_policy_id: 1,
            ..Default::default()
        });
        store
            .update_config(
                1,
                1,
                0,
                cluster_id,
                vec![server],
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                0,
                1,
                true,
                true,
                HashMap::new(),
                false,
                false,
                "random".to_string(),
                HashMap::new(),
                None,
                false,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                Vec::new(),
                vec![test_firewall_policy(is_on, max_empty_connections, 1, 1)],
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;
        store
    }

    fn record_test_l4_event(
        store: &ConfigStore,
        waf_state: &Arc<WafStateManager>,
        ip: IpAddr,
        kind: L4DefenseKind,
        detail: impl Into<String>,
    ) -> L4DefenseVerdict {
        record_l4_event_with_pressure(
            store,
            waf_state,
            7,
            ip,
            kind,
            detail,
            L4PressureLevel::Normal,
        )
    }

    fn record_test_l4_event_weighted(
        store: &ConfigStore,
        waf_state: &Arc<WafStateManager>,
        ip: IpAddr,
        kind: L4DefenseKind,
        amount: u64,
        detail: impl Into<String>,
    ) -> L4DefenseVerdict {
        record_l4_event_weighted_with_pressure(
            store,
            waf_state,
            7,
            ip,
            kind,
            amount,
            detail,
            L4PressureLevel::Normal,
        )
    }

    #[tokio::test]
    async fn l4_defense_disabled_when_empty_connection_flood_is_off() {
        let store = store_with_empty_connection_flood(false, 1).await;
        let waf_state = Arc::new(WafStateManager::new());
        let ip: IpAddr = "203.0.113.10".parse().unwrap();

        assert_eq!(
            record_test_l4_event(
                &store,
                &waf_state,
                ip,
                L4DefenseKind::TcpAdmissionReject,
                "disabled-test"
            ),
            L4DefenseVerdict::Disabled
        );
        assert!(!waf_state.is_blocked(ip, crate::special_defense::cluster_block_scope_id(12)));
    }

    #[tokio::test]
    async fn completed_handshake_events_are_disabled_without_empty_connection_flood() {
        let store = store_with_empty_connection_flood(false, 1).await;
        let waf_state = Arc::new(WafStateManager::new());
        let ip: IpAddr = "203.0.113.66".parse().unwrap();

        assert_eq!(
            record_completed_handshake_event(
                &store,
                &waf_state,
                7,
                ip,
                L4DefenseKind::HttpEarlyCloseOrTinyRequest,
                2,
                || "disabled-completed".to_string(),
            ),
            None
        );
        assert!(!waf_state.is_blocked(ip, crate::special_defense::cluster_block_scope_id(12)));
    }

    #[tokio::test]
    async fn tcp_accepted_churn_counts_at_normal_pressure_with_conservative_threshold() {
        let store = store_with_empty_connection_flood_for_cluster(true, 8, 1205).await;
        let waf_state = Arc::new(WafStateManager::new());
        let cluster_scope = crate::special_defense::cluster_block_scope_id(1205);
        let ip: IpAddr = "203.0.113.67".parse().unwrap();

        let mut saw_allowed = false;
        for idx in 0..40 {
            let verdict =
                record_tcp_accepted_churn(&store, &waf_state, 7, ip, || format!("accepted-{idx}"));
            assert_ne!(verdict, None);
            if verdict == Some(L4DefenseVerdict::Allowed) {
                saw_allowed = true;
            }
            if matches!(
                verdict,
                Some(L4DefenseVerdict::Blocked | L4DefenseVerdict::AlreadyBlocked)
            ) {
                break;
            }
        }
        assert!(saw_allowed);
        assert!(waf_state.is_blocked(ip, cluster_scope));
    }

    #[tokio::test]
    async fn completed_handshake_weighted_event_blocks_quickly() {
        let store = store_with_empty_connection_flood_for_cluster(true, 3, 1206).await;
        let waf_state = Arc::new(WafStateManager::new());
        let cluster_scope = crate::special_defense::cluster_block_scope_id(1206);
        let ip: IpAddr = "203.0.113.68".parse().unwrap();

        assert_eq!(
            record_completed_handshake_event(
                &store,
                &waf_state,
                7,
                ip,
                L4DefenseKind::TlsHandshakeThenNoHttp,
                2,
                || "tls-no-http-1".to_string(),
            ),
            Some(L4DefenseVerdict::Allowed)
        );
        assert_eq!(
            record_completed_handshake_event(
                &store,
                &waf_state,
                7,
                ip,
                L4DefenseKind::TlsHandshakeThenNoHttp,
                2,
                || "tls-no-http-2".to_string(),
            ),
            Some(L4DefenseVerdict::Blocked)
        );
        assert!(waf_state.is_blocked(ip, cluster_scope));
    }

    #[tokio::test]
    async fn l4_defense_uses_empty_connection_threshold_multipliers() {
        let store = store_with_empty_connection_flood_for_cluster(true, 2, 1201).await;
        let waf_state = Arc::new(WafStateManager::new());
        let cluster_scope = crate::special_defense::cluster_block_scope_id(1201);

        let high_ip: IpAddr = "203.0.113.11".parse().unwrap();
        assert_eq!(
            record_test_l4_event(
                &store,
                &waf_state,
                high_ip,
                L4DefenseKind::TcpAdmissionReject,
                "high-1"
            ),
            L4DefenseVerdict::Allowed
        );
        assert_eq!(
            record_test_l4_event(
                &store,
                &waf_state,
                high_ip,
                L4DefenseKind::TcpAdmissionReject,
                "high-2"
            ),
            L4DefenseVerdict::Allowed
        );
        assert_eq!(
            record_test_l4_event(
                &store,
                &waf_state,
                high_ip,
                L4DefenseKind::TcpAdmissionReject,
                "high-3"
            ),
            L4DefenseVerdict::Blocked
        );
        assert!(waf_state.is_blocked(high_ip, cluster_scope));

        let medium_ip: IpAddr = "203.0.113.12".parse().unwrap();
        for idx in 0..4 {
            assert_eq!(
                record_test_l4_event(
                    &store,
                    &waf_state,
                    medium_ip,
                    L4DefenseKind::UdpQueueFull,
                    format!("medium-{idx}")
                ),
                L4DefenseVerdict::Allowed
            );
        }
        assert_eq!(
            record_test_l4_event(
                &store,
                &waf_state,
                medium_ip,
                L4DefenseKind::UdpQueueFull,
                "medium-5"
            ),
            L4DefenseVerdict::Blocked
        );

        let low_ip: IpAddr = "203.0.113.13".parse().unwrap();
        for idx in 0..8 {
            assert_eq!(
                record_test_l4_event(
                    &store,
                    &waf_state,
                    low_ip,
                    L4DefenseKind::QuicNoRoute,
                    format!("low-{idx}")
                ),
                L4DefenseVerdict::Allowed
            );
        }
        assert_eq!(
            record_test_l4_event(
                &store,
                &waf_state,
                low_ip,
                L4DefenseKind::QuicNoRoute,
                "low-9"
            ),
            L4DefenseVerdict::Blocked
        );
    }

    #[tokio::test]
    async fn l4_defense_weighted_events_count_toward_threshold() {
        let store = store_with_empty_connection_flood_for_cluster(true, 2, 1204).await;
        let waf_state = Arc::new(WafStateManager::new());
        let cluster_scope = crate::special_defense::cluster_block_scope_id(1204);
        let ip: IpAddr = "203.0.113.44".parse().unwrap();

        assert_eq!(
            record_test_l4_event_weighted(
                &store,
                &waf_state,
                ip,
                L4DefenseKind::H2RequestChurn,
                3,
                "weighted-h2-churn"
            ),
            L4DefenseVerdict::Blocked
        );
        assert!(waf_state.is_blocked(ip, cluster_scope));
    }

    #[tokio::test]
    async fn l4_defense_pressure_tightens_reporting_threshold() {
        let store = store_with_empty_connection_flood_for_cluster(true, 8, 1207).await;
        let waf_state = Arc::new(WafStateManager::new());
        let ip: IpAddr = "192.0.2.15".parse().unwrap();
        let cluster_scope = crate::special_defense::cluster_block_scope_id(1207);

        for idx in 0..2 {
            assert_eq!(
                record_l4_event_with_pressure(
                    &store,
                    &waf_state,
                    7,
                    ip,
                    L4DefenseKind::TcpAdmissionReject,
                    format!("critical-{idx}"),
                    L4PressureLevel::Normal,
                ),
                L4DefenseVerdict::Allowed
            );
        }
        assert_eq!(
            record_l4_event_with_pressure(
                &store,
                &waf_state,
                7,
                ip,
                L4DefenseKind::TcpAdmissionReject,
                "critical-3",
                L4PressureLevel::Critical,
            ),
            L4DefenseVerdict::Blocked
        );
        assert!(waf_state.is_blocked(ip, cluster_scope));
    }

    #[tokio::test]
    async fn tcp_connection_churn_is_high_confidence_under_pressure() {
        let store = store_with_empty_connection_flood_for_cluster(true, 8, 1208).await;
        let waf_state = Arc::new(WafStateManager::new());
        let ip: IpAddr = "192.0.2.45".parse().unwrap();
        let cluster_scope = crate::special_defense::cluster_block_scope_id(1208);

        for idx in 0..2 {
            assert_eq!(
                record_l4_event_with_pressure(
                    &store,
                    &waf_state,
                    7,
                    ip,
                    L4DefenseKind::TcpConnectionChurn,
                    format!("churn-{idx}"),
                    L4PressureLevel::Critical,
                ),
                L4DefenseVerdict::Allowed
            );
        }
        assert_eq!(
            record_l4_event_with_pressure(
                &store,
                &waf_state,
                7,
                ip,
                L4DefenseKind::TcpConnectionChurn,
                "churn-block",
                L4PressureLevel::Critical,
            ),
            L4DefenseVerdict::Blocked
        );
        assert!(waf_state.is_blocked(ip, cluster_scope));
    }

    #[tokio::test]
    async fn high_confidence_prefix_events_can_apply_local_cluster_prefix_block() {
        let store = store_with_empty_connection_flood_for_cluster(true, 10, 1209).await;
        let waf_state = Arc::new(WafStateManager::new());
        let cluster_scope = crate::special_defense::cluster_block_scope_id(1209);

        for host in 1..=20 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, host));
            for idx in 0..9 {
                let _ = record_l4_event_with_pressure(
                    &store,
                    &waf_state,
                    7,
                    ip,
                    L4DefenseKind::TcpAdmissionReject,
                    format!("prefix-{host}-{idx}"),
                    L4PressureLevel::Normal,
                );
            }
        }

        assert!(waf_state.is_blocked("198.51.100.250".parse().unwrap(), cluster_scope));
    }

    #[tokio::test]
    async fn low_confidence_prefix_events_do_not_apply_prefix_block() {
        let store = store_with_empty_connection_flood_for_cluster(true, 10, 1210).await;
        let waf_state = Arc::new(WafStateManager::new());
        let cluster_scope = crate::special_defense::cluster_block_scope_id(1210);

        for host in 1..=20 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, host));
            for idx in 0..9 {
                let _ = record_l4_event_with_pressure(
                    &store,
                    &waf_state,
                    7,
                    ip,
                    L4DefenseKind::QuicNoRoute,
                    format!("low-prefix-{host}-{idx}"),
                    L4PressureLevel::Critical,
                );
            }
        }

        assert!(!waf_state.is_blocked("203.0.113.250".parse().unwrap(), cluster_scope));
    }

    #[tokio::test]
    async fn l4_defense_does_not_count_already_blocked_ip_again() {
        let store = store_with_empty_connection_flood_for_cluster(true, 1, 1211).await;
        let waf_state = Arc::new(WafStateManager::new());
        let ip: IpAddr = "203.0.113.14".parse().unwrap();

        assert_eq!(
            record_test_l4_event(
                &store,
                &waf_state,
                ip,
                L4DefenseKind::TcpActiveLimit,
                "first"
            ),
            L4DefenseVerdict::Allowed
        );
        assert_eq!(
            record_test_l4_event(
                &store,
                &waf_state,
                ip,
                L4DefenseKind::TcpActiveLimit,
                "second"
            ),
            L4DefenseVerdict::Blocked
        );
        assert_eq!(
            record_test_l4_event(
                &store,
                &waf_state,
                ip,
                L4DefenseKind::TcpActiveLimit,
                "third"
            ),
            L4DefenseVerdict::AlreadyBlocked
        );
    }
}
