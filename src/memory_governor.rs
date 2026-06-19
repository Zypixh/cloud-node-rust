use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionClass {
    HttpConnection,
    TcpConnection,
    Http3Connection,
    UdpSession,
    Http2Stream,
    Http3Request,
    OriginConnect,
    BackgroundWork,
    RequestBodyWaf,
    ResponseBodyWaf,
    ResponseTransform,
    CacheRevalidate,
    CacheWrite,
}

#[derive(Clone, Copy, Debug)]
pub struct GovernorSnapshot {
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub memory_available_bytes: u64,
    pub fd_soft_limit: u64,
    pub http_fd_budget: u64,
    pub tcp_fd_budget: u64,
    pub udp_fd_budget: u64,
    pub origin_fd_budget: u64,
    pub keepalive_fd_budget: u64,
    pub cpu_parallelism: usize,
    pub connection_budget_bytes: u64,
    pub connection_admission_used_bytes: u64,
    pub keepalive_budget_bytes: u64,
    pub estimated_http_connections: u64,
    pub estimated_tcp_connections: u64,
    pub estimated_h3_connections: u64,
    pub estimated_udp_sessions: u64,
    pub estimated_h2_streams: u64,
    pub estimated_h3_requests: u64,
    pub estimated_origin_connects: u64,
    pub estimated_background_work: u64,
    pub http_connection_limit: usize,
    pub tcp_connection_limit: usize,
    pub h3_connection_limit: usize,
    pub udp_session_limit: usize,
    pub udp_route_limit_per_port: usize,
    pub udp_session_queue_size: usize,
    pub udp_socket_buffer_size: usize,
    pub h3_datagram_queue_size: usize,
    pub h2_stream_global_limit: usize,
    pub h2_stream_limit_per_connection: usize,
    pub h3_request_global_limit: usize,
    pub h3_request_limit_per_connection: usize,
    pub origin_connect_limit: usize,
    pub background_work_limit: usize,
    pub request_body_waf_limit: usize,
    pub response_body_waf_limit: usize,
    pub response_transform_limit: usize,
    pub cache_revalidate_limit: usize,
    pub cache_write_limit: usize,
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
    fd_soft_limit: u64,
    cpu_parallelism: usize,
}

pub static MEMORY_GOVERNOR: LazyLock<MemoryGovernor> = LazyLock::new(MemoryGovernor::new);

const SNAPSHOT_TTL_MS: i64 = 2_000;
const MIN_MEMORY_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const RESERVE_HEADROOM_PCT: u64 = 30;
const CONNECTION_BUDGET_PCT: u64 = 45;
const KEEPALIVE_BUDGET_PCT: u64 = 12;
const CACHE_BUDGET_PCT: u64 = 25;
const BLOOM_BUDGET_PCT: u64 = 5;
const FD_RESERVE: u64 = 512;
const MIN_FD_SOFT_LIMIT: u64 = 1_024;
const HTTP_FD_BUDGET_PCT: u64 = 35;
const TCP_FD_BUDGET_PCT: u64 = 25;
const UDP_FD_BUDGET_PCT: u64 = 25;
const ORIGIN_FD_BUDGET_PCT: u64 = 25;
const KEEPALIVE_FD_BUDGET_PCT: u64 = 10;

const HTTP_CONN_ESTIMATED_BYTES: u64 = 32 * 1024;
const TCP_CONN_ESTIMATED_BYTES: u64 = 24 * 1024;
const H3_CONN_ESTIMATED_BYTES: u64 = 48 * 1024;
const UDP_SESSION_ESTIMATED_BYTES: u64 = 96 * 1024;
const UDP_DATAGRAM_ESTIMATED_BYTES: u64 = 2 * 1024;
const H2_STREAM_ESTIMATED_BYTES: u64 = 16 * 1024;
const H3_REQUEST_ESTIMATED_BYTES: u64 = 24 * 1024;
const ORIGIN_CONNECT_ESTIMATED_BYTES: u64 = 32 * 1024;
const BACKGROUND_WORK_ESTIMATED_BYTES: u64 = 64 * 1024;
const REQUEST_BODY_WAF_ESTIMATED_BYTES: u64 = 2 * 1024 * 1024;
const RESPONSE_BODY_WAF_ESTIMATED_BYTES: u64 = 512 * 1024;
const RESPONSE_TRANSFORM_ESTIMATED_BYTES: u64 = 16 * 1024 * 1024;
const CACHE_REVALIDATE_ESTIMATED_BYTES: u64 = 64 * 1024;
const CACHE_WRITE_ESTIMATED_BYTES: u64 = 1 * 1024 * 1024;
const KEEPALIVE_CONN_ESTIMATED_BYTES: u64 = 16 * 1024;
const NEGATIVE_CACHE_ESTIMATED_BYTES: u64 = 160;

const MIN_HTTP_CONNECTION_LIMIT: usize = 16_384;
const MIN_TCP_CONNECTION_LIMIT: usize = 16_384;
const MIN_H3_CONNECTION_LIMIT: usize = 4_096;
const MIN_UDP_SESSION_LIMIT: usize = 4_096;
const MIN_UDP_ROUTE_LIMIT_PER_PORT: usize = 4_096;
const MIN_UDP_SESSION_QUEUE_SIZE: usize = 64;
const MIN_H3_DATAGRAM_QUEUE_SIZE: usize = 1_024;
const MIN_H2_STREAM_GLOBAL_LIMIT: usize = 4_096;
const MIN_H2_STREAM_LIMIT_PER_CONNECTION: usize = 256;
const MIN_H3_REQUEST_GLOBAL_LIMIT: usize = 4_096;
const MIN_H3_REQUEST_LIMIT_PER_CONNECTION: usize = 256;
const MIN_ORIGIN_CONNECT_LIMIT: usize = 16_384;
const MIN_BACKGROUND_WORK_LIMIT: usize = 256;
const MIN_REQUEST_BODY_WAF_LIMIT: usize = 128;
const MIN_RESPONSE_BODY_WAF_LIMIT: usize = 256;
const MIN_RESPONSE_TRANSFORM_LIMIT: usize = 32;
const MIN_CACHE_REVALIDATE_LIMIT: usize = 64;
const MIN_CACHE_WRITE_LIMIT: usize = 128;
const MIN_CACHE_BUDGET_BYTES: u64 = 128 * 1024 * 1024;
const MIN_BLOOM_BUDGET_BYTES: u64 = 32 * 1024 * 1024;
const MIN_NEGATIVE_CACHE_ENTRIES: usize = 262_144;

const MAX_HTTP_CONNECTION_LIMIT: usize = 100_000_000;
const MAX_TCP_CONNECTION_LIMIT: usize = 100_000_000;
const MAX_H3_CONNECTION_LIMIT: usize = 10_000_000;
const MAX_UDP_SESSION_LIMIT: usize = 100_000_000;
const MAX_UDP_ROUTE_LIMIT_PER_PORT: usize = 100_000_000;
const MAX_UDP_SESSION_QUEUE_SIZE: usize = 2_048;
const MAX_H3_DATAGRAM_QUEUE_SIZE: usize = 65_536;
const MAX_H2_STREAM_GLOBAL_LIMIT: usize = 100_000_000;
const MAX_H2_STREAM_LIMIT_PER_CONNECTION: usize = 65_535;
const MAX_H3_REQUEST_GLOBAL_LIMIT: usize = 100_000_000;
const MAX_H3_REQUEST_LIMIT_PER_CONNECTION: usize = 65_535;
const MAX_ORIGIN_CONNECT_LIMIT: usize = 100_000_000;
const MAX_BACKGROUND_WORK_LIMIT: usize = 1_000_000;
const MAX_REQUEST_BODY_WAF_LIMIT: usize = 1_000_000;
const MAX_RESPONSE_BODY_WAF_LIMIT: usize = 1_000_000;
const MAX_RESPONSE_TRANSFORM_LIMIT: usize = 1_000_000;
const MAX_CACHE_REVALIDATE_LIMIT: usize = 100_000;
const MAX_CACHE_WRITE_LIMIT: usize = 1_000_000;
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
    udp_sessions: AtomicU64,
    h2_streams: AtomicU64,
    h3_requests: AtomicU64,
    origin_connects: AtomicU64,
    shared_connection_bytes: AtomicU64,
    background_work: AtomicU64,
    request_body_waf: AtomicU64,
    response_body_waf: AtomicU64,
    response_transform: AtomicU64,
    cache_revalidate: AtomicU64,
    cache_write: AtomicU64,
    cached_total_bytes: AtomicU64,
    cached_used_bytes: AtomicU64,
    cached_available_bytes: AtomicU64,
    cached_at_millis: AtomicU64,
}

pub struct AdmissionPermit<'a> {
    governor: &'a MemoryGovernor,
    class: AdmissionClass,
    shared_connection_charge_bytes: u64,
}

pub type StaticAdmissionPermit = AdmissionPermit<'static>;

impl MemoryGovernor {
    pub const fn new() -> Self {
        Self {
            http_connections: AtomicU64::new(0),
            tcp_connections: AtomicU64::new(0),
            h3_connections: AtomicU64::new(0),
            udp_sessions: AtomicU64::new(0),
            h2_streams: AtomicU64::new(0),
            h3_requests: AtomicU64::new(0),
            origin_connects: AtomicU64::new(0),
            shared_connection_bytes: AtomicU64::new(0),
            background_work: AtomicU64::new(0),
            request_body_waf: AtomicU64::new(0),
            response_body_waf: AtomicU64::new(0),
            response_transform: AtomicU64::new(0),
            cache_revalidate: AtomicU64::new(0),
            cache_write: AtomicU64::new(0),
            cached_total_bytes: AtomicU64::new(0),
            cached_used_bytes: AtomicU64::new(0),
            cached_available_bytes: AtomicU64::new(0),
            cached_at_millis: AtomicU64::new(0),
        }
    }

    pub fn try_admit(&self, class: AdmissionClass) -> Option<AdmissionPermit<'_>> {
        let counter = self.counter(class);
        let current = counter.fetch_add(1, Ordering::AcqRel) + 1;
        if current > self.limit_for(class) as u64 {
            counter.fetch_sub(1, Ordering::AcqRel);
            return None;
        }

        let shared_connection_charge_bytes = shared_connection_charge_bytes(class);
        if shared_connection_charge_bytes > 0 {
            let budget = shared_connection_admission_budget(&self.memory_snapshot());
            let used = self
                .shared_connection_bytes
                .fetch_add(shared_connection_charge_bytes, Ordering::AcqRel)
                .saturating_add(shared_connection_charge_bytes);
            if used > budget {
                self.shared_connection_bytes
                    .fetch_sub(shared_connection_charge_bytes, Ordering::AcqRel);
                counter.fetch_sub(1, Ordering::AcqRel);
                return None;
            }
        }

        Some(AdmissionPermit {
            governor: self,
            class,
            shared_connection_charge_bytes,
        })
    }

    pub fn limit_for(&self, class: AdmissionClass) -> usize {
        let snapshot = self.memory_snapshot();
        match class {
            AdmissionClass::HttpConnection => runtime_limit(
                &snapshot,
                AdmissionClass::HttpConnection,
                MIN_HTTP_CONNECTION_LIMIT,
                MAX_HTTP_CONNECTION_LIMIT,
            ),
            AdmissionClass::TcpConnection => runtime_limit(
                &snapshot,
                AdmissionClass::TcpConnection,
                MIN_TCP_CONNECTION_LIMIT,
                MAX_TCP_CONNECTION_LIMIT,
            ),
            AdmissionClass::Http3Connection => runtime_limit(
                &snapshot,
                AdmissionClass::Http3Connection,
                MIN_H3_CONNECTION_LIMIT,
                MAX_H3_CONNECTION_LIMIT,
            ),
            AdmissionClass::UdpSession => runtime_limit(
                &snapshot,
                AdmissionClass::UdpSession,
                MIN_UDP_SESSION_LIMIT,
                MAX_UDP_SESSION_LIMIT,
            ),
            AdmissionClass::Http2Stream => runtime_limit(
                &snapshot,
                AdmissionClass::Http2Stream,
                MIN_H2_STREAM_GLOBAL_LIMIT,
                MAX_H2_STREAM_GLOBAL_LIMIT,
            ),
            AdmissionClass::Http3Request => runtime_limit(
                &snapshot,
                AdmissionClass::Http3Request,
                MIN_H3_REQUEST_GLOBAL_LIMIT,
                MAX_H3_REQUEST_GLOBAL_LIMIT,
            ),
            AdmissionClass::OriginConnect => runtime_limit(
                &snapshot,
                AdmissionClass::OriginConnect,
                MIN_ORIGIN_CONNECT_LIMIT,
                MAX_ORIGIN_CONNECT_LIMIT,
            ),
            AdmissionClass::BackgroundWork => connection_limit(
                snapshot.cache_budget_bytes / 8,
                BACKGROUND_WORK_ESTIMATED_BYTES,
                MIN_BACKGROUND_WORK_LIMIT,
                MAX_BACKGROUND_WORK_LIMIT,
            ),
            AdmissionClass::RequestBodyWaf => connection_limit(
                snapshot.available_bytes / 8,
                REQUEST_BODY_WAF_ESTIMATED_BYTES,
                MIN_REQUEST_BODY_WAF_LIMIT,
                MAX_REQUEST_BODY_WAF_LIMIT,
            ),
            AdmissionClass::ResponseBodyWaf => connection_limit(
                snapshot.available_bytes / 8,
                RESPONSE_BODY_WAF_ESTIMATED_BYTES,
                MIN_RESPONSE_BODY_WAF_LIMIT,
                MAX_RESPONSE_BODY_WAF_LIMIT,
            ),
            AdmissionClass::ResponseTransform => connection_limit(
                snapshot.available_bytes / 6,
                RESPONSE_TRANSFORM_ESTIMATED_BYTES,
                MIN_RESPONSE_TRANSFORM_LIMIT,
                MAX_RESPONSE_TRANSFORM_LIMIT,
            ),
            AdmissionClass::CacheRevalidate => connection_limit(
                snapshot.available_bytes / 16,
                CACHE_REVALIDATE_ESTIMATED_BYTES,
                MIN_CACHE_REVALIDATE_LIMIT,
                MAX_CACHE_REVALIDATE_LIMIT,
            ),
            AdmissionClass::CacheWrite => connection_limit(
                if memory_pressure_high(&snapshot) {
                    snapshot.cache_budget_bytes / 32
                } else {
                    snapshot.cache_budget_bytes / 4
                },
                CACHE_WRITE_ESTIMATED_BYTES,
                if memory_pressure_high(&snapshot) {
                    MIN_CACHE_WRITE_LIMIT / 4
                } else {
                    MIN_CACHE_WRITE_LIMIT
                },
                MAX_CACHE_WRITE_LIMIT,
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
        memory_pressure_high(&snapshot)
    }

    pub fn listener_backlog(&self) -> i32 {
        let snapshot = self.memory_snapshot();
        let estimated_live_conns = self
            .http_connections
            .load(Ordering::Relaxed)
            .saturating_add(self.tcp_connections.load(Ordering::Relaxed))
            .saturating_add(self.h3_connections.load(Ordering::Relaxed))
            .saturating_add(self.udp_sessions.load(Ordering::Relaxed));
        let target = connection_limit(
            snapshot.connection_budget_bytes / 64,
            HTTP_CONN_ESTIMATED_BYTES,
            MIN_LISTENER_BACKLOG as usize,
            MAX_LISTENER_BACKLOG as usize,
        )
        .max((estimated_live_conns / 32) as usize);
        clamp_i32(target, MIN_LISTENER_BACKLOG, MAX_LISTENER_BACKLOG)
    }

    pub fn h2_stream_limit_per_connection(&self) -> usize {
        let snapshot = self.memory_snapshot();
        multiplexed_per_connection_limit(
            &snapshot,
            H2_STREAM_ESTIMATED_BYTES,
            MIN_H2_STREAM_LIMIT_PER_CONNECTION,
            MAX_H2_STREAM_LIMIT_PER_CONNECTION,
        )
    }

    pub fn h3_request_limit_per_connection(&self) -> usize {
        let snapshot = self.memory_snapshot();
        multiplexed_per_connection_limit(
            &snapshot,
            H3_REQUEST_ESTIMATED_BYTES,
            MIN_H3_REQUEST_LIMIT_PER_CONNECTION,
            MAX_H3_REQUEST_LIMIT_PER_CONNECTION,
        )
    }

    pub fn udp_route_limit_per_port(&self) -> usize {
        let session_limit = self.limit_for(AdmissionClass::UdpSession);
        session_limit.clamp(MIN_UDP_ROUTE_LIMIT_PER_PORT, MAX_UDP_ROUTE_LIMIT_PER_PORT)
    }

    pub fn udp_session_queue_size(&self) -> usize {
        let snapshot = self.memory_snapshot();
        let memory_target = connection_limit(
            snapshot.connection_budget_bytes / 256,
            UDP_DATAGRAM_ESTIMATED_BYTES,
            MIN_UDP_SESSION_QUEUE_SIZE,
            MAX_UDP_SESSION_QUEUE_SIZE,
        );
        let cpu_target = snapshot.cpu_parallelism.max(1).saturating_mul(64);
        let target = memory_target.max(cpu_target);
        if memory_pressure_high(&snapshot) {
            target.clamp(MIN_UDP_SESSION_QUEUE_SIZE, 256)
        } else {
            target.clamp(MIN_UDP_SESSION_QUEUE_SIZE, MAX_UDP_SESSION_QUEUE_SIZE)
        }
    }

    pub fn h3_datagram_queue_size(&self) -> usize {
        let snapshot = self.memory_snapshot();
        let target = connection_limit(
            snapshot.connection_budget_bytes / 128,
            UDP_DATAGRAM_ESTIMATED_BYTES,
            MIN_H3_DATAGRAM_QUEUE_SIZE,
            MAX_H3_DATAGRAM_QUEUE_SIZE,
        );
        if memory_pressure_high(&snapshot) {
            target.clamp(MIN_H3_DATAGRAM_QUEUE_SIZE, 8_192)
        } else {
            target
        }
    }

    pub fn udp_socket_buffer_size(&self) -> usize {
        let snapshot = self.memory_snapshot();
        if memory_pressure_high(&snapshot) {
            2 * 1024 * 1024
        } else if snapshot.total_bytes >= 32 * 1024 * 1024 * 1024 {
            16 * 1024 * 1024
        } else {
            4 * 1024 * 1024
        }
    }

    pub fn pingora_keepalive_pool_size(&self, threads: usize) -> usize {
        let snapshot = self.memory_snapshot();
        let threads = threads.max(1);
        let memory_target = connection_limit(
            snapshot.keepalive_budget_bytes,
            KEEPALIVE_CONN_ESTIMATED_BYTES,
            1,
            MAX_PINGORA_KEEPALIVE_POOL_PER_THREAD.saturating_mul(threads),
        );
        let fd_target = fd_budget(&snapshot, KEEPALIVE_FD_BUDGET_PCT) as usize;
        let global_target = memory_target.min(fd_target.max(1)).clamp(
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
            fd_soft_limit: mem.fd_soft_limit,
            http_fd_budget: fd_budget(&mem, HTTP_FD_BUDGET_PCT),
            tcp_fd_budget: fd_budget(&mem, TCP_FD_BUDGET_PCT),
            udp_fd_budget: fd_budget(&mem, UDP_FD_BUDGET_PCT),
            origin_fd_budget: fd_budget(&mem, ORIGIN_FD_BUDGET_PCT),
            keepalive_fd_budget: fd_budget(&mem, KEEPALIVE_FD_BUDGET_PCT),
            cpu_parallelism: mem.cpu_parallelism,
            connection_budget_bytes: mem.connection_budget_bytes,
            connection_admission_used_bytes: self.shared_connection_bytes.load(Ordering::Relaxed),
            keepalive_budget_bytes: mem.keepalive_budget_bytes,
            estimated_http_connections: self.http_connections.load(Ordering::Relaxed),
            estimated_tcp_connections: self.tcp_connections.load(Ordering::Relaxed),
            estimated_h3_connections: self.h3_connections.load(Ordering::Relaxed),
            estimated_udp_sessions: self.udp_sessions.load(Ordering::Relaxed),
            estimated_h2_streams: self.h2_streams.load(Ordering::Relaxed),
            estimated_h3_requests: self.h3_requests.load(Ordering::Relaxed),
            estimated_origin_connects: self.origin_connects.load(Ordering::Relaxed),
            estimated_background_work: self.background_work.load(Ordering::Relaxed),
            http_connection_limit: self.limit_for(AdmissionClass::HttpConnection),
            tcp_connection_limit: self.limit_for(AdmissionClass::TcpConnection),
            h3_connection_limit: self.limit_for(AdmissionClass::Http3Connection),
            udp_session_limit: self.limit_for(AdmissionClass::UdpSession),
            udp_route_limit_per_port: self.udp_route_limit_per_port(),
            udp_session_queue_size: self.udp_session_queue_size(),
            udp_socket_buffer_size: self.udp_socket_buffer_size(),
            h3_datagram_queue_size: self.h3_datagram_queue_size(),
            h2_stream_global_limit: self.limit_for(AdmissionClass::Http2Stream),
            h2_stream_limit_per_connection: self.h2_stream_limit_per_connection(),
            h3_request_global_limit: self.limit_for(AdmissionClass::Http3Request),
            h3_request_limit_per_connection: self.h3_request_limit_per_connection(),
            origin_connect_limit: self.limit_for(AdmissionClass::OriginConnect),
            background_work_limit: self.limit_for(AdmissionClass::BackgroundWork),
            request_body_waf_limit: self.limit_for(AdmissionClass::RequestBodyWaf),
            response_body_waf_limit: self.limit_for(AdmissionClass::ResponseBodyWaf),
            response_transform_limit: self.limit_for(AdmissionClass::ResponseTransform),
            cache_revalidate_limit: self.limit_for(AdmissionClass::CacheRevalidate),
            cache_write_limit: self.limit_for(AdmissionClass::CacheWrite),
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
            AdmissionClass::UdpSession => &self.udp_sessions,
            AdmissionClass::Http2Stream => &self.h2_streams,
            AdmissionClass::Http3Request => &self.h3_requests,
            AdmissionClass::OriginConnect => &self.origin_connects,
            AdmissionClass::BackgroundWork => &self.background_work,
            AdmissionClass::RequestBodyWaf => &self.request_body_waf,
            AdmissionClass::ResponseBodyWaf => &self.response_body_waf,
            AdmissionClass::ResponseTransform => &self.response_transform,
            AdmissionClass::CacheRevalidate => &self.cache_revalidate,
            AdmissionClass::CacheWrite => &self.cache_write,
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
                fd_soft_limit: read_fd_soft_limit(),
                cpu_parallelism: std::thread::available_parallelism()
                    .map(usize::from)
                    .unwrap_or(1),
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
            fd_soft_limit: snapshot.fd_soft_limit,
            cpu_parallelism: snapshot.cpu_parallelism,
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
        if self.shared_connection_charge_bytes > 0 {
            self.governor
                .shared_connection_bytes
                .fetch_sub(self.shared_connection_charge_bytes, Ordering::AcqRel);
        }
    }
}

struct BudgetedMemorySnapshot {
    total_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
    fd_soft_limit: u64,
    cpu_parallelism: usize,
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
        fd_soft_limit: read_fd_soft_limit(),
        cpu_parallelism: std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1),
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

fn memory_pressure_high(snapshot: &BudgetedMemorySnapshot) -> bool {
    snapshot.available_bytes < snapshot.total_bytes / 10
}

fn fd_budget(snapshot: &BudgetedMemorySnapshot, budget_pct: u64) -> u64 {
    snapshot
        .fd_soft_limit
        .saturating_sub(FD_RESERVE)
        .saturating_mul(budget_pct)
        / 100
}

fn shared_connection_admission_budget(snapshot: &BudgetedMemorySnapshot) -> u64 {
    snapshot.connection_budget_bytes
}

fn shared_connection_charge_bytes(class: AdmissionClass) -> u64 {
    match class {
        AdmissionClass::HttpConnection => HTTP_CONN_ESTIMATED_BYTES,
        AdmissionClass::TcpConnection => TCP_CONN_ESTIMATED_BYTES,
        AdmissionClass::Http3Connection => H3_CONN_ESTIMATED_BYTES,
        AdmissionClass::UdpSession => UDP_SESSION_ESTIMATED_BYTES,
        AdmissionClass::Http2Stream => H2_STREAM_ESTIMATED_BYTES,
        AdmissionClass::Http3Request => H3_REQUEST_ESTIMATED_BYTES,
        AdmissionClass::OriginConnect => ORIGIN_CONNECT_ESTIMATED_BYTES,
        AdmissionClass::BackgroundWork
        | AdmissionClass::RequestBodyWaf
        | AdmissionClass::ResponseBodyWaf
        | AdmissionClass::ResponseTransform
        | AdmissionClass::CacheRevalidate
        | AdmissionClass::CacheWrite => 0,
    }
}

fn runtime_limit(
    snapshot: &BudgetedMemorySnapshot,
    class: AdmissionClass,
    min_limit: usize,
    max_limit: usize,
) -> usize {
    let (memory_budget, estimated_bytes, fd_pct, cpu_floor_per_core) = match class {
        AdmissionClass::HttpConnection => (
            snapshot.connection_budget_bytes,
            HTTP_CONN_ESTIMATED_BYTES,
            Some(HTTP_FD_BUDGET_PCT),
            16_384,
        ),
        AdmissionClass::TcpConnection => (
            snapshot.connection_budget_bytes,
            TCP_CONN_ESTIMATED_BYTES,
            Some(TCP_FD_BUDGET_PCT),
            16_384,
        ),
        AdmissionClass::Http3Connection => (
            snapshot.connection_budget_bytes / 2,
            H3_CONN_ESTIMATED_BYTES,
            None,
            4_096,
        ),
        AdmissionClass::UdpSession => (
            snapshot.connection_budget_bytes / 2,
            UDP_SESSION_ESTIMATED_BYTES,
            Some(UDP_FD_BUDGET_PCT),
            4_096,
        ),
        AdmissionClass::Http2Stream => (
            snapshot.connection_budget_bytes / 8,
            H2_STREAM_ESTIMATED_BYTES,
            None,
            4_096,
        ),
        AdmissionClass::Http3Request => (
            snapshot.connection_budget_bytes / 8,
            H3_REQUEST_ESTIMATED_BYTES,
            None,
            4_096,
        ),
        AdmissionClass::OriginConnect => (
            snapshot.connection_budget_bytes,
            ORIGIN_CONNECT_ESTIMATED_BYTES,
            Some(ORIGIN_FD_BUDGET_PCT),
            16_384,
        ),
        AdmissionClass::BackgroundWork
        | AdmissionClass::RequestBodyWaf
        | AdmissionClass::ResponseBodyWaf
        | AdmissionClass::ResponseTransform
        | AdmissionClass::CacheRevalidate
        | AdmissionClass::CacheWrite => return min_limit,
    };
    let memory_target = connection_limit(memory_budget, estimated_bytes, 1, max_limit);
    let cpu_floor = snapshot
        .cpu_parallelism
        .max(1)
        .saturating_mul(cpu_floor_per_core);
    let mut target = memory_target.max(cpu_floor).clamp(min_limit, max_limit);
    if let Some(fd_pct) = fd_pct {
        let fd_target = fd_budget(snapshot, fd_pct) as usize;
        if fd_target > 0 {
            target = target.min(fd_target);
        }
    }
    target.clamp(1, max_limit)
}

fn multiplexed_per_connection_limit(
    snapshot: &BudgetedMemorySnapshot,
    estimated_unit_bytes: u64,
    min_limit: usize,
    max_limit: usize,
) -> usize {
    let memory_target = connection_limit(
        snapshot.connection_budget_bytes / 64,
        estimated_unit_bytes,
        min_limit,
        max_limit,
    );
    let cpu_target = snapshot.cpu_parallelism.max(1).saturating_mul(256);
    memory_target.max(cpu_target).clamp(min_limit, max_limit)
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

#[cfg(unix)]
fn read_fd_soft_limit() -> u64 {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) == 0 };
    if ok {
        (limits.rlim_cur as u64).max(MIN_FD_SOFT_LIMIT)
    } else {
        MIN_FD_SOFT_LIMIT
    }
}

#[cfg(not(unix))]
fn read_fd_soft_limit() -> u64 {
    1_048_576
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_snapshot(
        total_gib: u64,
        available_gib: u64,
        fd_soft_limit: u64,
        cpu: usize,
    ) -> BudgetedMemorySnapshot {
        let total_bytes = total_gib * 1024 * 1024 * 1024;
        let available_bytes = available_gib * 1024 * 1024 * 1024;
        BudgetedMemorySnapshot {
            total_bytes,
            used_bytes: total_bytes.saturating_sub(available_bytes),
            available_bytes,
            fd_soft_limit,
            cpu_parallelism: cpu,
            connection_budget_bytes: budget_from_available(
                total_bytes,
                available_bytes,
                CONNECTION_BUDGET_PCT,
            ),
            keepalive_budget_bytes: budget_from_available(
                total_bytes,
                available_bytes,
                KEEPALIVE_BUDGET_PCT,
            ),
            cache_budget_bytes: cache_budget_from_available(total_bytes, available_bytes),
            bloom_budget_bytes: bounded_budget_from_available(
                total_bytes,
                available_bytes,
                BLOOM_BUDGET_PCT,
                MIN_BLOOM_BUDGET_BYTES,
                MAX_BLOOM_BUDGET_BYTES,
            ),
        }
    }

    #[test]
    fn governor_rolls_back_when_limit_is_full() {
        let governor = MemoryGovernor::new();
        let mut permits = Vec::new();
        let class = AdmissionClass::ResponseTransform;
        let limit = governor.limit_for(class);
        for _ in 0..limit {
            permits.push(governor.try_admit(class).unwrap());
        }
        assert!(governor.try_admit(class).is_none());
        drop(permits.pop());
        assert!(governor.try_admit(class).is_some());
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

    #[test]
    fn high_cost_admission_classes_have_limits_and_release() {
        let governor = MemoryGovernor::new();
        for class in [
            AdmissionClass::UdpSession,
            AdmissionClass::RequestBodyWaf,
            AdmissionClass::ResponseBodyWaf,
            AdmissionClass::ResponseTransform,
            AdmissionClass::CacheRevalidate,
            AdmissionClass::CacheWrite,
        ] {
            assert!(governor.limit_for(class) > 0);
            let permit = governor.try_admit(class).expect("class should admit");
            assert_eq!(governor.counter(class).load(Ordering::Acquire), 1);
            drop(permit);
            assert_eq!(governor.counter(class).load(Ordering::Acquire), 0);
        }
        assert_eq!(governor.shared_connection_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn shared_connection_admission_rolls_back_when_budget_is_full() {
        let governor = MemoryGovernor::new();
        let budget = shared_connection_admission_budget(&governor.memory_snapshot());
        let baseline = budget.saturating_sub(HTTP_CONN_ESTIMATED_BYTES / 2);

        governor
            .shared_connection_bytes
            .store(baseline, Ordering::Release);
        assert!(governor.try_admit(AdmissionClass::HttpConnection).is_none());
        assert_eq!(
            governor
                .counter(AdmissionClass::HttpConnection)
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            governor.shared_connection_bytes.load(Ordering::Acquire),
            baseline
        );

        let baseline = budget.saturating_sub(HTTP_CONN_ESTIMATED_BYTES);
        governor
            .shared_connection_bytes
            .store(baseline, Ordering::Release);
        let permit = governor
            .try_admit(AdmissionClass::HttpConnection)
            .expect("exactly one HTTP connection should fit");
        assert_eq!(
            governor.shared_connection_bytes.load(Ordering::Acquire),
            baseline + HTTP_CONN_ESTIMATED_BYTES
        );
        drop(permit);
        assert_eq!(
            governor.shared_connection_bytes.load(Ordering::Acquire),
            baseline
        );
    }

    #[test]
    fn shared_connection_budget_is_elastic_not_average_partitioned() {
        let small = synthetic_snapshot(2, 1, 65_535, 2);
        let full_budget = shared_connection_admission_budget(&small);
        let averaged_budget = full_budget / 5;
        let http_capacity_from_full_budget = full_budget / HTTP_CONN_ESTIMATED_BYTES;
        let http_capacity_from_average = averaged_budget / HTTP_CONN_ESTIMATED_BYTES;

        assert_eq!(full_budget, small.connection_budget_bytes);
        assert!(http_capacity_from_full_budget > http_capacity_from_average);
        assert!(
            runtime_limit(
                &small,
                AdmissionClass::HttpConnection,
                MIN_HTTP_CONNECTION_LIMIT,
                MAX_HTTP_CONNECTION_LIMIT,
            ) as u64
                >= http_capacity_from_full_budget
        );
    }

    #[test]
    fn admission_profile_scales_with_machine_size_and_fd_budget() {
        let small = synthetic_snapshot(2, 1, 65_535, 2);
        let medium = synthetic_snapshot(16, 8, 1_048_576, 4);
        let large = synthetic_snapshot(1024, 768, 16_777_216, 128);

        let small_http = runtime_limit(
            &small,
            AdmissionClass::HttpConnection,
            MIN_HTTP_CONNECTION_LIMIT,
            MAX_HTTP_CONNECTION_LIMIT,
        );
        let medium_http = runtime_limit(
            &medium,
            AdmissionClass::HttpConnection,
            MIN_HTTP_CONNECTION_LIMIT,
            MAX_HTTP_CONNECTION_LIMIT,
        );
        let large_http = runtime_limit(
            &large,
            AdmissionClass::HttpConnection,
            MIN_HTTP_CONNECTION_LIMIT,
            MAX_HTTP_CONNECTION_LIMIT,
        );

        assert!(small_http >= 16_000);
        assert!(medium_http > small_http);
        assert!(large_http > medium_http);
        assert!(large_http > 65_535);

        let large_h2_global = runtime_limit(
            &large,
            AdmissionClass::Http2Stream,
            MIN_H2_STREAM_GLOBAL_LIMIT,
            MAX_H2_STREAM_GLOBAL_LIMIT,
        );
        let large_h2_per_conn = multiplexed_per_connection_limit(
            &large,
            H2_STREAM_ESTIMATED_BYTES,
            MIN_H2_STREAM_LIMIT_PER_CONNECTION,
            MAX_H2_STREAM_LIMIT_PER_CONNECTION,
        );
        assert!(large_h2_global > MAX_H2_STREAM_LIMIT_PER_CONNECTION);
        assert_eq!(large_h2_per_conn, MAX_H2_STREAM_LIMIT_PER_CONNECTION);
    }

    #[test]
    fn low_fd_limit_reduces_connection_admission_without_touching_protocol_caps() {
        let low_fd = synthetic_snapshot(16, 8, 4_096, 8);
        let http = runtime_limit(
            &low_fd,
            AdmissionClass::HttpConnection,
            MIN_HTTP_CONNECTION_LIMIT,
            MAX_HTTP_CONNECTION_LIMIT,
        );
        let origin = runtime_limit(
            &low_fd,
            AdmissionClass::OriginConnect,
            MIN_ORIGIN_CONNECT_LIMIT,
            MAX_ORIGIN_CONNECT_LIMIT,
        );
        let udp = runtime_limit(
            &low_fd,
            AdmissionClass::UdpSession,
            MIN_UDP_SESSION_LIMIT,
            MAX_UDP_SESSION_LIMIT,
        );
        assert!(http <= fd_budget(&low_fd, HTTP_FD_BUDGET_PCT) as usize);
        assert!(origin <= fd_budget(&low_fd, ORIGIN_FD_BUDGET_PCT) as usize);
        assert!(udp <= fd_budget(&low_fd, UDP_FD_BUDGET_PCT) as usize);

        let h3_per_conn = multiplexed_per_connection_limit(
            &low_fd,
            H3_REQUEST_ESTIMATED_BYTES,
            MIN_H3_REQUEST_LIMIT_PER_CONNECTION,
            MAX_H3_REQUEST_LIMIT_PER_CONNECTION,
        );
        assert!(h3_per_conn >= MIN_H3_REQUEST_LIMIT_PER_CONNECTION);
    }
}
