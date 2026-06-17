use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionClass {
    HttpConnection,
    TcpConnection,
    Http3Connection,
    Http2Stream,
    Http3Request,
    OriginConnect,
    BackgroundWork,
}

#[derive(Clone, Copy, Debug)]
pub struct GovernorSnapshot {
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub memory_available_bytes: u64,
    pub connection_budget_bytes: u64,
    pub keepalive_budget_bytes: u64,
    pub estimated_http_connections: u64,
    pub estimated_tcp_connections: u64,
    pub estimated_h3_connections: u64,
    pub estimated_h2_streams: u64,
    pub estimated_h3_requests: u64,
    pub estimated_origin_connects: u64,
    pub estimated_background_work: u64,
    pub http_connection_limit: usize,
    pub tcp_connection_limit: usize,
    pub h3_connection_limit: usize,
    pub h2_stream_limit_per_connection: usize,
    pub h3_request_limit_per_connection: usize,
    pub origin_connect_limit: usize,
    pub background_work_limit: usize,
    pub cache_budget_bytes: u64,
    pub bloom_budget_bytes: u64,
    pub negative_cache_limit: usize,
    pub listener_backlog: i32,
    pub pingora_keepalive_pool_size: usize,
}

struct MemorySnapshot {
    total_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
}

pub static MEMORY_GOVERNOR: LazyLock<MemoryGovernor> = LazyLock::new(MemoryGovernor::new);

const SNAPSHOT_TTL_MS: i64 = 2_000;
const MIN_MEMORY_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const RESERVE_HEADROOM_PCT: u64 = 30;
const CONNECTION_BUDGET_PCT: u64 = 45;
const KEEPALIVE_BUDGET_PCT: u64 = 12;
const CACHE_BUDGET_PCT: u64 = 25;
const BLOOM_BUDGET_PCT: u64 = 5;

const HTTP_CONN_ESTIMATED_BYTES: u64 = 32 * 1024;
const TCP_CONN_ESTIMATED_BYTES: u64 = 24 * 1024;
const H3_CONN_ESTIMATED_BYTES: u64 = 48 * 1024;
const H2_STREAM_ESTIMATED_BYTES: u64 = 16 * 1024;
const H3_REQUEST_ESTIMATED_BYTES: u64 = 24 * 1024;
const ORIGIN_CONNECT_ESTIMATED_BYTES: u64 = 32 * 1024;
const BACKGROUND_WORK_ESTIMATED_BYTES: u64 = 64 * 1024;
const KEEPALIVE_CONN_ESTIMATED_BYTES: u64 = 16 * 1024;
const NEGATIVE_CACHE_ESTIMATED_BYTES: u64 = 160;

const MIN_HTTP_CONNECTION_LIMIT: usize = 16_384;
const MIN_TCP_CONNECTION_LIMIT: usize = 16_384;
const MIN_H3_CONNECTION_LIMIT: usize = 4_096;
const MIN_H2_STREAM_LIMIT_PER_CONNECTION: usize = 256;
const MIN_H3_REQUEST_LIMIT_PER_CONNECTION: usize = 256;
const MIN_ORIGIN_CONNECT_LIMIT: usize = 16_384;
const MIN_BACKGROUND_WORK_LIMIT: usize = 256;
const MIN_CACHE_BUDGET_BYTES: u64 = 128 * 1024 * 1024;
const MIN_BLOOM_BUDGET_BYTES: u64 = 32 * 1024 * 1024;
const MIN_NEGATIVE_CACHE_ENTRIES: usize = 262_144;

const MAX_HTTP_CONNECTION_LIMIT: usize = 100_000_000;
const MAX_TCP_CONNECTION_LIMIT: usize = 100_000_000;
const MAX_H3_CONNECTION_LIMIT: usize = 10_000_000;
const MAX_H2_STREAM_LIMIT_PER_CONNECTION: usize = 65_535;
const MAX_H3_REQUEST_LIMIT_PER_CONNECTION: usize = 65_535;
const MAX_ORIGIN_CONNECT_LIMIT: usize = 100_000_000;
const MAX_BACKGROUND_WORK_LIMIT: usize = 1_000_000;
const MAX_CACHE_BUDGET_BYTES: u64 = 512 * 1024 * 1024 * 1024;
const MAX_BLOOM_BUDGET_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_NEGATIVE_CACHE_ENTRIES: usize = 64_000_000;

const MIN_LISTENER_BACKLOG: i32 = 32_768;
const MAX_LISTENER_BACKLOG: i32 = 65_535;
const MIN_PINGORA_KEEPALIVE_POOL_PER_THREAD: usize = 256;
const MAX_PINGORA_KEEPALIVE_POOL_PER_THREAD: usize = 65_535;

pub struct MemoryGovernor {
    http_connections: AtomicU64,
    tcp_connections: AtomicU64,
    h3_connections: AtomicU64,
    h2_streams: AtomicU64,
    h3_requests: AtomicU64,
    origin_connects: AtomicU64,
    background_work: AtomicU64,
    cached_total_bytes: AtomicU64,
    cached_used_bytes: AtomicU64,
    cached_available_bytes: AtomicU64,
    cached_at_millis: AtomicU64,
}

pub struct AdmissionPermit<'a> {
    governor: &'a MemoryGovernor,
    class: AdmissionClass,
}

pub type StaticAdmissionPermit = AdmissionPermit<'static>;

impl MemoryGovernor {
    pub const fn new() -> Self {
        Self {
            http_connections: AtomicU64::new(0),
            tcp_connections: AtomicU64::new(0),
            h3_connections: AtomicU64::new(0),
            h2_streams: AtomicU64::new(0),
            h3_requests: AtomicU64::new(0),
            origin_connects: AtomicU64::new(0),
            background_work: AtomicU64::new(0),
            cached_total_bytes: AtomicU64::new(0),
            cached_used_bytes: AtomicU64::new(0),
            cached_available_bytes: AtomicU64::new(0),
            cached_at_millis: AtomicU64::new(0),
        }
    }

    pub fn try_admit(&self, class: AdmissionClass) -> Option<AdmissionPermit<'_>> {
        let counter = self.counter(class);
        let current = counter.fetch_add(1, Ordering::AcqRel) + 1;
        if current <= self.limit_for(class) as u64 {
            Some(AdmissionPermit {
                governor: self,
                class,
            })
        } else {
            counter.fetch_sub(1, Ordering::AcqRel);
            None
        }
    }

    pub fn limit_for(&self, class: AdmissionClass) -> usize {
        let snapshot = self.memory_snapshot();
        match class {
            AdmissionClass::HttpConnection => connection_limit(
                snapshot.connection_budget_bytes,
                HTTP_CONN_ESTIMATED_BYTES,
                MIN_HTTP_CONNECTION_LIMIT,
                MAX_HTTP_CONNECTION_LIMIT,
            ),
            AdmissionClass::TcpConnection => connection_limit(
                snapshot.connection_budget_bytes,
                TCP_CONN_ESTIMATED_BYTES,
                MIN_TCP_CONNECTION_LIMIT,
                MAX_TCP_CONNECTION_LIMIT,
            ),
            AdmissionClass::Http3Connection => connection_limit(
                snapshot.connection_budget_bytes / 2,
                H3_CONN_ESTIMATED_BYTES,
                MIN_H3_CONNECTION_LIMIT,
                MAX_H3_CONNECTION_LIMIT,
            ),
            AdmissionClass::Http2Stream => connection_limit(
                snapshot.connection_budget_bytes / 32,
                H2_STREAM_ESTIMATED_BYTES,
                MIN_H2_STREAM_LIMIT_PER_CONNECTION,
                MAX_H2_STREAM_LIMIT_PER_CONNECTION,
            ),
            AdmissionClass::Http3Request => connection_limit(
                snapshot.connection_budget_bytes / 32,
                H3_REQUEST_ESTIMATED_BYTES,
                MIN_H3_REQUEST_LIMIT_PER_CONNECTION,
                MAX_H3_REQUEST_LIMIT_PER_CONNECTION,
            ),
            AdmissionClass::OriginConnect => connection_limit(
                snapshot.connection_budget_bytes,
                ORIGIN_CONNECT_ESTIMATED_BYTES,
                MIN_ORIGIN_CONNECT_LIMIT,
                MAX_ORIGIN_CONNECT_LIMIT,
            ),
            AdmissionClass::BackgroundWork => connection_limit(
                snapshot.cache_budget_bytes / 8,
                BACKGROUND_WORK_ESTIMATED_BYTES,
                MIN_BACKGROUND_WORK_LIMIT,
                MAX_BACKGROUND_WORK_LIMIT,
            ),
        }
    }

    pub fn cache_budget_bytes(&self) -> u64 {
        self.memory_snapshot().cache_budget_bytes
    }

    pub fn bloom_budget_bytes(&self) -> u64 {
        self.memory_snapshot().bloom_budget_bytes
    }

    pub fn negative_cache_limit(&self) -> usize {
        connection_limit(
            self.memory_snapshot().bloom_budget_bytes,
            NEGATIVE_CACHE_ESTIMATED_BYTES,
            MIN_NEGATIVE_CACHE_ENTRIES,
            MAX_NEGATIVE_CACHE_ENTRIES,
        )
    }

    pub fn is_memory_pressure_high(&self) -> bool {
        let snapshot = self.memory_snapshot();
        snapshot.available_bytes < snapshot.total_bytes / 10
    }

    pub fn listener_backlog(&self) -> i32 {
        let snapshot = self.memory_snapshot();
        let estimated_live_conns = self
            .http_connections
            .load(Ordering::Relaxed)
            .saturating_add(self.tcp_connections.load(Ordering::Relaxed))
            .saturating_add(self.h3_connections.load(Ordering::Relaxed));
        let target = connection_limit(
            snapshot.connection_budget_bytes / 64,
            HTTP_CONN_ESTIMATED_BYTES,
            MIN_LISTENER_BACKLOG as usize,
            MAX_LISTENER_BACKLOG as usize,
        )
        .max((estimated_live_conns / 32) as usize);
        clamp_i32(target, MIN_LISTENER_BACKLOG, MAX_LISTENER_BACKLOG)
    }

    pub fn pingora_keepalive_pool_size(&self, threads: usize) -> usize {
        let snapshot = self.memory_snapshot();
        let threads = threads.max(1);
        let global_target = connection_limit(
            snapshot.keepalive_budget_bytes,
            KEEPALIVE_CONN_ESTIMATED_BYTES,
            MIN_PINGORA_KEEPALIVE_POOL_PER_THREAD * threads,
            MAX_PINGORA_KEEPALIVE_POOL_PER_THREAD * threads,
        );
        (global_target / threads).clamp(
            MIN_PINGORA_KEEPALIVE_POOL_PER_THREAD,
            MAX_PINGORA_KEEPALIVE_POOL_PER_THREAD,
        )
    }

    pub fn snapshot(&self, pingora_threads: usize) -> GovernorSnapshot {
        let mem = self.memory_snapshot();
        GovernorSnapshot {
            memory_total_bytes: mem.total_bytes,
            memory_used_bytes: mem.used_bytes,
            memory_available_bytes: mem.available_bytes,
            connection_budget_bytes: mem.connection_budget_bytes,
            keepalive_budget_bytes: mem.keepalive_budget_bytes,
            estimated_http_connections: self.http_connections.load(Ordering::Relaxed),
            estimated_tcp_connections: self.tcp_connections.load(Ordering::Relaxed),
            estimated_h3_connections: self.h3_connections.load(Ordering::Relaxed),
            estimated_h2_streams: self.h2_streams.load(Ordering::Relaxed),
            estimated_h3_requests: self.h3_requests.load(Ordering::Relaxed),
            estimated_origin_connects: self.origin_connects.load(Ordering::Relaxed),
            estimated_background_work: self.background_work.load(Ordering::Relaxed),
            http_connection_limit: self.limit_for(AdmissionClass::HttpConnection),
            tcp_connection_limit: self.limit_for(AdmissionClass::TcpConnection),
            h3_connection_limit: self.limit_for(AdmissionClass::Http3Connection),
            h2_stream_limit_per_connection: self.limit_for(AdmissionClass::Http2Stream),
            h3_request_limit_per_connection: self.limit_for(AdmissionClass::Http3Request),
            origin_connect_limit: self.limit_for(AdmissionClass::OriginConnect),
            background_work_limit: self.limit_for(AdmissionClass::BackgroundWork),
            cache_budget_bytes: mem.cache_budget_bytes,
            bloom_budget_bytes: mem.bloom_budget_bytes,
            negative_cache_limit: self.negative_cache_limit(),
            listener_backlog: self.listener_backlog(),
            pingora_keepalive_pool_size: self.pingora_keepalive_pool_size(pingora_threads),
        }
    }

    fn counter(&self, class: AdmissionClass) -> &AtomicU64 {
        match class {
            AdmissionClass::HttpConnection => &self.http_connections,
            AdmissionClass::TcpConnection => &self.tcp_connections,
            AdmissionClass::Http3Connection => &self.h3_connections,
            AdmissionClass::Http2Stream => &self.h2_streams,
            AdmissionClass::Http3Request => &self.h3_requests,
            AdmissionClass::OriginConnect => &self.origin_connects,
            AdmissionClass::BackgroundWork => &self.background_work,
        }
    }

    fn memory_snapshot(&self) -> BudgetedMemorySnapshot {
        let now = crate::utils::time::system_timestamp_millis();
        let cached_at = self.cached_at_millis.load(Ordering::Relaxed) as i64;
        if cached_at > 0 && now.saturating_sub(cached_at) < SNAPSHOT_TTL_MS {
            return BudgetedMemorySnapshot {
                total_bytes: self.cached_total_bytes.load(Ordering::Relaxed),
                used_bytes: self.cached_used_bytes.load(Ordering::Relaxed),
                available_bytes: self.cached_available_bytes.load(Ordering::Relaxed),
                connection_budget_bytes: budget_from_available(
                    self.cached_total_bytes.load(Ordering::Relaxed),
                    self.cached_available_bytes.load(Ordering::Relaxed),
                    CONNECTION_BUDGET_PCT,
                ),
                keepalive_budget_bytes: budget_from_available(
                    self.cached_total_bytes.load(Ordering::Relaxed),
                    self.cached_available_bytes.load(Ordering::Relaxed),
                    KEEPALIVE_BUDGET_PCT,
                ),
                cache_budget_bytes: cache_budget_from_available(
                    self.cached_total_bytes.load(Ordering::Relaxed),
                    self.cached_available_bytes.load(Ordering::Relaxed),
                ),
                bloom_budget_bytes: bounded_budget_from_available(
                    self.cached_total_bytes.load(Ordering::Relaxed),
                    self.cached_available_bytes.load(Ordering::Relaxed),
                    BLOOM_BUDGET_PCT,
                    MIN_BLOOM_BUDGET_BYTES,
                    MAX_BLOOM_BUDGET_BYTES,
                ),
            };
        }

        let snapshot = read_memory_snapshot();
        self.cached_total_bytes
            .store(snapshot.total_bytes, Ordering::Relaxed);
        self.cached_used_bytes
            .store(snapshot.used_bytes, Ordering::Relaxed);
        self.cached_available_bytes
            .store(snapshot.available_bytes, Ordering::Relaxed);
        self.cached_at_millis.store(now as u64, Ordering::Relaxed);

        BudgetedMemorySnapshot {
            total_bytes: snapshot.total_bytes,
            used_bytes: snapshot.used_bytes,
            available_bytes: snapshot.available_bytes,
            connection_budget_bytes: budget_from_available(
                snapshot.total_bytes,
                snapshot.available_bytes,
                CONNECTION_BUDGET_PCT,
            ),
            keepalive_budget_bytes: budget_from_available(
                snapshot.total_bytes,
                snapshot.available_bytes,
                KEEPALIVE_BUDGET_PCT,
            ),
            cache_budget_bytes: cache_budget_from_available(
                snapshot.total_bytes,
                snapshot.available_bytes,
            ),
            bloom_budget_bytes: bounded_budget_from_available(
                snapshot.total_bytes,
                snapshot.available_bytes,
                BLOOM_BUDGET_PCT,
                MIN_BLOOM_BUDGET_BYTES,
                MAX_BLOOM_BUDGET_BYTES,
            ),
        }
    }
}

impl Drop for AdmissionPermit<'_> {
    fn drop(&mut self) {
        self.governor
            .counter(self.class)
            .fetch_sub(1, Ordering::AcqRel);
    }
}

struct BudgetedMemorySnapshot {
    total_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
    connection_budget_bytes: u64,
    keepalive_budget_bytes: u64,
    cache_budget_bytes: u64,
    bloom_budget_bytes: u64,
}

fn read_memory_snapshot() -> MemorySnapshot {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();

    #[allow(unused_mut)]
    let mut total_bytes = sys.total_memory().max(MIN_MEMORY_TOTAL_BYTES);
    #[allow(unused_mut)]
    let mut used_bytes = sys.used_memory().min(total_bytes);

    #[cfg(target_os = "linux")]
    {
        if let Some((cgroup_total, cgroup_used)) = linux_cgroup_memory_limit() {
            total_bytes = cgroup_total.max(MIN_MEMORY_TOTAL_BYTES);
            used_bytes = cgroup_used.min(total_bytes);
        }
    }

    let hard_reserve = total_bytes.saturating_mul(RESERVE_HEADROOM_PCT) / 100;
    let available_bytes = total_bytes
        .saturating_sub(used_bytes)
        .saturating_sub(hard_reserve)
        .max(total_bytes / 100)
        .max(256 * 1024 * 1024);

    MemorySnapshot {
        total_bytes,
        used_bytes,
        available_bytes,
    }
}

#[cfg(target_os = "linux")]
fn linux_cgroup_memory_limit() -> Option<(u64, u64)> {
    if let Ok(limit_str) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        && let Ok(limit) = limit_str.trim().parse::<u64>()
        && limit > 0
        && limit < 1024_u64.pow(4)
    {
        let used = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0);
        return Some((limit, used));
    }

    let limit_str = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()?;
    if limit_str.trim().eq_ignore_ascii_case("max") {
        return None;
    }
    let limit = limit_str.trim().parse::<u64>().ok()?;
    if limit == 0 {
        return None;
    }
    let used = std::fs::read_to_string("/sys/fs/cgroup/memory.current")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0);
    Some((limit, used))
}

fn budget_from_available(total_bytes: u64, available_bytes: u64, budget_pct: u64) -> u64 {
    let by_available = available_bytes.saturating_mul(budget_pct) / 100;
    let by_total = total_bytes.saturating_mul(budget_pct) / 100;
    by_available.min(by_total).max(64 * 1024 * 1024)
}

fn bounded_budget_from_available(
    total_bytes: u64,
    available_bytes: u64,
    budget_pct: u64,
    min_budget: u64,
    max_budget: u64,
) -> u64 {
    let by_available = available_bytes.saturating_mul(budget_pct) / 100;
    let by_total = total_bytes.saturating_mul(budget_pct) / 100;
    by_available.min(by_total).clamp(min_budget, max_budget)
}

fn cache_budget_from_available(total_bytes: u64, available_bytes: u64) -> u64 {
    bounded_budget_from_available(
        total_bytes,
        available_bytes,
        CACHE_BUDGET_PCT,
        MIN_CACHE_BUDGET_BYTES,
        MAX_CACHE_BUDGET_BYTES,
    )
}

fn connection_limit(
    budget_bytes: u64,
    estimated_unit_bytes: u64,
    min_limit: usize,
    max_limit: usize,
) -> usize {
    let estimated = (budget_bytes / estimated_unit_bytes.max(1))
        .max(min_limit as u64)
        .min(max_limit as u64);
    estimated as usize
}

fn clamp_i32(value: usize, min_limit: i32, max_limit: i32) -> i32 {
    let value = value.min(max_limit as usize).max(min_limit as usize);
    value as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governor_rolls_back_when_limit_is_full() {
        let governor = MemoryGovernor::new();
        let mut permits = Vec::new();
        let limit = governor.limit_for(AdmissionClass::Http2Stream);
        for _ in 0..limit {
            permits.push(governor.try_admit(AdmissionClass::Http2Stream).unwrap());
        }
        assert!(governor.try_admit(AdmissionClass::Http2Stream).is_none());
        drop(permits.pop());
        assert!(governor.try_admit(AdmissionClass::Http2Stream).is_some());
    }

    #[test]
    fn backlog_and_keepalive_stay_in_expected_bounds() {
        let governor = MemoryGovernor::new();
        let backlog = governor.listener_backlog();
        assert!((MIN_LISTENER_BACKLOG..=MAX_LISTENER_BACKLOG).contains(&backlog));
        let keepalive = governor.pingora_keepalive_pool_size(16);
        assert!(
            (MIN_PINGORA_KEEPALIVE_POOL_PER_THREAD..=MAX_PINGORA_KEEPALIVE_POOL_PER_THREAD)
                .contains(&keepalive)
        );
    }
}
