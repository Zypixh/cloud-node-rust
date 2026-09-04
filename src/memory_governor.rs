use std::cell::Cell;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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
    CacheReadMemory,
    ClusterInternalConnection,
    RpcStreamCommand,
    SniRelay,
}

const ADMISSION_CLASS_COUNT: usize = 17;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdmissionRejectSnapshot {
    pub http_connection: u64,
    pub tcp_connection: u64,
    pub h3_connection: u64,
    pub udp_session: u64,
    pub h2_stream: u64,
    pub h3_request: u64,
    pub origin_connect: u64,
    pub background_work: u64,
    pub request_body_waf: u64,
    pub response_body_waf: u64,
    pub response_transform: u64,
    pub cache_revalidate: u64,
    pub cache_write: u64,
    pub cache_read_memory: u64,
    pub cluster_internal_connection: u64,
    pub rpc_stream_command: u64,
    pub sni_relay: u64,
}

impl AdmissionRejectSnapshot {
    pub fn total(self) -> u64 {
        self.http_connection
            .saturating_add(self.tcp_connection)
            .saturating_add(self.h3_connection)
            .saturating_add(self.udp_session)
            .saturating_add(self.h2_stream)
            .saturating_add(self.h3_request)
            .saturating_add(self.origin_connect)
            .saturating_add(self.background_work)
            .saturating_add(self.request_body_waf)
            .saturating_add(self.response_body_waf)
            .saturating_add(self.response_transform)
            .saturating_add(self.cache_revalidate)
            .saturating_add(self.cache_write)
            .saturating_add(self.cache_read_memory)
            .saturating_add(self.cluster_internal_connection)
            .saturating_add(self.rpc_stream_command)
            .saturating_add(self.sni_relay)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GovernorSnapshot {
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub memory_available_bytes: u64,
    pub memory_pressure_level: MemoryPressureLevel,
    pub fd_soft_limit: u64,
    pub fd_used: u64,
    pub fd_used_pct: u64,
    pub fd_pressure_level: MemoryPressureLevel,
    pub http_fd_budget: u64,
    pub tcp_fd_budget: u64,
    pub udp_fd_budget: u64,
    pub origin_fd_budget: u64,
    pub keepalive_fd_budget: u64,
    pub cpu_parallelism: usize,
    pub connection_budget_bytes: u64,
    pub connection_admission_used_bytes: u64,
    pub zero_copy_relay_active: u64,
    pub zero_copy_relay_limit: usize,
    pub zero_copy_relay_used_bytes: u64,
    pub zero_copy_relay_budget_bytes: u64,
    pub udp_queued_bytes: u64,
    pub udp_queued_bytes_budget: u64,
    pub admission_rejects: AdmissionRejectSnapshot,
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
    pub h3_datagram_queue_budget_bytes: usize,
    pub quic_pending_route_limit_per_port: usize,
    pub quic_pending_reassembly_budget_bytes: usize,
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
    pub cache_read_memory_limit: usize,
    pub cluster_internal_connection_limit: usize,
    pub rpc_stream_command_limit: usize,
    pub cache_read_memory_used_bytes: u64,
    pub cache_read_memory_budget_bytes: u64,
    pub cache_read_memory_object_limit_bytes: u64,
    pub cache_budget_bytes: u64,
    pub bloom_budget_bytes: u64,
    pub negative_cache_limit: usize,
    pub listener_backlog: i32,
    pub pingora_worker_threads: usize,
    pub http_accept_workers: usize,
    pub tcp_accept_workers: usize,
    pub udp_demux_workers: usize,
    pub access_log_queue_capacity: usize,
    pub access_log_batch_size: usize,
    pub node_log_queue_capacity: usize,
    pub metrics_queue_capacity: usize,
    pub firewall_ip_limiter_capacity: usize,
    pub firewall_rolling_counter_capacity: usize,
    pub firewall_ip_bw_counter_capacity: usize,
    pub firewall_candidate_stats_capacity: usize,
    pub l4_aggregate_state_budget_bytes: u64,
    pub kernel_sync_queue_budget_bytes: u64,
    pub cardinality_state_budget_bytes: u64,
    pub regex_cache_budget_bytes: u64,
    pub logging_retry_budget_bytes: u64,
    pub local_log_queue_budget_bytes: u64,
    pub ip_report_queue_budget_bytes: u64,
    pub af_xdp_budget_bytes: u64,
    pub pingora_keepalive_pool_size: usize,
    pub resident_memory: ResidentMemorySnapshot,
    pub cgroup_managed: bool,
    pub cgroup_memory_max_bytes: u64,
    pub cgroup_memory_high_bytes: u64,
    pub cgroup_swap_max_bytes: u64,
    pub process_rss_bytes: u64,
    pub process_pss_bytes: u64,
    pub process_anon_rss_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResidentMemorySnapshot {
    pub total_used_bytes: u64,
    pub total_budget_bytes: u64,
    pub cache_metadata_used_bytes: u64,
    pub cache_access_log_used_bytes: u64,
    pub surrogate_index_used_bytes: u64,
    pub bloom_filter_used_bytes: u64,
    pub negative_cache_used_bytes: u64,
    pub pressure_level: MemoryPressureLevel,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResidentCategory {
    CacheMetadata,
    CacheAccessLog,
    SurrogateIndex,
    BloomFilter,
    NegativeCache,
}

impl ResidentCategory {
    const COUNT: usize = 5;
    const fn index(self) -> usize {
        match self {
            Self::CacheMetadata => 0,
            Self::CacheAccessLog => 1,
            Self::SurrogateIndex => 2,
            Self::BloomFilter => 3,
            Self::NegativeCache => 4,
        }
    }
}

#[derive(Debug)]
struct ResidentMemoryAccounting {
    used: [AtomicU64; ResidentCategory::COUNT],
    total: AtomicU64,
    owners: Mutex<HashMap<(ResidentCategory, String), u64>>,
    mutation: Mutex<()>,
}

impl ResidentMemoryAccounting {
    fn new() -> Self {
        Self {
            used: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            total: AtomicU64::new(0),
            owners: Mutex::new(HashMap::new()),
            mutation: Mutex::new(()),
        }
    }
}

struct MemorySnapshot {
    total_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
    fd_soft_limit: u64,
    cpu_parallelism: usize,
    cgroup_managed: bool,
    cgroup_memory_max_bytes: u64,
    cgroup_memory_high_bytes: u64,
    cgroup_swap_max_bytes: u64,
    process_rss_bytes: u64,
    process_pss_bytes: u64,
    process_anon_rss_bytes: u64,
}

pub static MEMORY_GOVERNOR: LazyLock<MemoryGovernor> = LazyLock::new(MemoryGovernor::new);

// Observing pressure can synchronously trigger cache reclamation. Cache
// initialization itself asks the governor for a budget, so without a
// per-thread guard that path recursively initializes CACHE and overflows the
// stack when the first observation is already under pressure.
thread_local! {
    static PRESSURE_RECLAIM_IN_PROGRESS: Cell<bool> = const { Cell::new(false) };
    // resident_memory_replace_owned holds the owner map while calculating a
    // budget. That calculation can synchronously reclaim the cache, whose
    // Bloom accounting calls this method again. Reject the nested accounting
    // attempt instead of recursively locking the owner map.
    static RESIDENT_OWNER_UPDATE_IN_PROGRESS: Cell<bool> = const { Cell::new(false) };
}

pub fn reported_memory_totals() -> (i64, i64) {
    let snapshot = MEMORY_GOVERNOR.snapshot(MEMORY_GOVERNOR.pingora_worker_threads());
    (
        snapshot.memory_total_bytes.min(i64::MAX as u64) as i64,
        snapshot.memory_used_bytes.min(i64::MAX as u64) as i64,
    )
}

const SNAPSHOT_TTL_MS: i64 = 2_000;
const FD_SNAPSHOT_TTL_MS: i64 = 250;
const MIN_MEMORY_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const RESERVE_HEADROOM_PCT: u64 = 30;
const CONNECTION_BUDGET_PCT: u64 = 45;
const KEEPALIVE_BUDGET_PCT: u64 = 12;
const CACHE_BUDGET_PCT: u64 = 25;
const BLOOM_BUDGET_PCT: u64 = 5;
const STATE_BUDGET_PCT: u64 = 8;
const EVENT_QUEUE_BUDGET_PCT: u64 = 2;
const FD_RESERVE: u64 = 512;
const MIN_FD_SOFT_LIMIT: u64 = 1_024;
const HTTP_FD_BUDGET_PCT: u64 = 35;
const TCP_FD_BUDGET_PCT: u64 = 25;
const UDP_FD_BUDGET_PCT: u64 = 25;
const ORIGIN_FD_BUDGET_PCT: u64 = 25;
const KEEPALIVE_FD_BUDGET_PCT: u64 = 10;

const HTTP_CONN_ESTIMATED_BYTES: u64 = 32 * 1024;
const TCP_CONN_ESTIMATED_BYTES: u64 = 24 * 1024;
const SNI_RELAY_ESTIMATED_BYTES: u64 = 256 * 1024;
const H3_CONN_ESTIMATED_BYTES: u64 = 48 * 1024;
const UDP_SESSION_ESTIMATED_BYTES: u64 = 96 * 1024;
const UDP_DATAGRAM_ESTIMATED_BYTES: u64 = 2 * 1024;
const ZERO_COPY_RELAY_ESTIMATED_BYTES: u64 = 768 * 1024;
const ZERO_COPY_RELAY_FD_EQUIVALENT: u64 = 10;
const ZERO_COPY_RELAY_BLOCKING_TASKS: u64 = 2;
const H2_STREAM_ESTIMATED_BYTES: u64 = 16 * 1024;
const H3_REQUEST_ESTIMATED_BYTES: u64 = 24 * 1024;
const ORIGIN_CONNECT_ESTIMATED_BYTES: u64 = 32 * 1024;
const BACKGROUND_WORK_ESTIMATED_BYTES: u64 = 64 * 1024;
const REQUEST_BODY_WAF_ESTIMATED_BYTES: u64 = 2 * 1024 * 1024;
const RESPONSE_BODY_WAF_ESTIMATED_BYTES: u64 = 512 * 1024;
const RESPONSE_TRANSFORM_ESTIMATED_BYTES: u64 = 16 * 1024 * 1024;
const CACHE_REVALIDATE_ESTIMATED_BYTES: u64 = 64 * 1024;
const CACHE_WRITE_ESTIMATED_BYTES: u64 = 1 * 1024 * 1024;
const CACHE_READ_MEMORY_ESTIMATED_BYTES: u64 = 4 * 1024 * 1024;
const CLUSTER_INTERNAL_CONNECTION_ESTIMATED_BYTES: u64 = 64 * 1024;
const RPC_STREAM_COMMAND_ESTIMATED_BYTES: u64 = 256 * 1024;
const KEEPALIVE_CONN_ESTIMATED_BYTES: u64 = 16 * 1024;
const NEGATIVE_CACHE_ESTIMATED_BYTES: u64 = 160;
const FIREWALL_IP_LIMITER_ESTIMATED_BYTES: u64 = 1024;
const FIREWALL_ROLLING_COUNTER_ESTIMATED_BYTES: u64 = 2304;
const FIREWALL_IP_BW_COUNTER_ESTIMATED_BYTES: u64 = 256;
const FIREWALL_CANDIDATE_STATS_ESTIMATED_BYTES: u64 = 128;
const ACCESS_LOG_EVENT_ESTIMATED_BYTES: u64 = 1536;
const NODE_LOG_EVENT_ESTIMATED_BYTES: u64 = 512;
const HTTP_DIMENSION_EVENT_ESTIMATED_BYTES: u64 = 512;
const MIN_RELAY_COPY_BUFFER_BYTES: usize = 16 * 1024;
const LOW_RELAY_COPY_BUFFER_BYTES: usize = 32 * 1024;
const DEFAULT_RELAY_COPY_BUFFER_BYTES: usize = 64 * 1024;
const HIGH_RELAY_COPY_BUFFER_BYTES: usize = 128 * 1024;
const MAX_RELAY_COPY_BUFFER_BYTES: usize = 256 * 1024;

const MIN_HTTP_CONNECTION_LIMIT: usize = 16_384;
const MIN_TCP_CONNECTION_LIMIT: usize = 16_384;
const MIN_H3_CONNECTION_LIMIT: usize = 4_096;
const MIN_UDP_SESSION_LIMIT: usize = 4_096;
const MIN_UDP_SESSION_QUEUE_SIZE: usize = 64;
const MIN_H3_DATAGRAM_QUEUE_SIZE: usize = 1_024;
const MIN_H3_DATAGRAM_QUEUE_SIZE_HIGH: usize = 256;
const MIN_H3_DATAGRAM_QUEUE_SIZE_CRITICAL: usize = 64;
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
const MIN_CACHE_READ_MEMORY_LIMIT: usize = 8;
const MIN_CLUSTER_INTERNAL_CONNECTION_LIMIT: usize = 32;
const MIN_RPC_STREAM_COMMAND_LIMIT: usize = 16;
const MIN_CACHE_BUDGET_BYTES: u64 = 128 * 1024 * 1024;
const MIN_BLOOM_BUDGET_BYTES: u64 = 32 * 1024 * 1024;
const MIN_NEGATIVE_CACHE_ENTRIES: usize = 262_144;

const MAX_HTTP_CONNECTION_LIMIT: usize = 100_000_000;
const MAX_TCP_CONNECTION_LIMIT: usize = 100_000_000;
const MAX_H3_CONNECTION_LIMIT: usize = 10_000_000;
const MAX_UDP_SESSION_LIMIT: usize = 100_000_000;
const MAX_UDP_ROUTE_LIMIT_PER_PORT: usize = 100_000_000;
const MAX_UDP_SESSION_QUEUE_SIZE: usize = 2_048;
const MIN_UDP_QUEUED_BYTES_BUDGET: u64 = 8 * 1024 * 1024;
const MAX_UDP_QUEUED_BYTES_BUDGET: u64 = 512 * 1024 * 1024;
const MAX_H3_DATAGRAM_QUEUE_SIZE: usize = 65_536;
const MAX_QUIC_PENDING_ROUTE_LIMIT_PER_PORT: usize = 2_048;
const MIN_QUIC_PENDING_ROUTE_LIMIT_PER_PORT: usize = 128;
const MAX_QUIC_PENDING_REASSEMBLY_BUDGET_BYTES: usize = 64 * 1024 * 1024;
const MIN_QUIC_PENDING_REASSEMBLY_BUDGET_BYTES: usize = 512 * 1024;
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
const MAX_CACHE_READ_MEMORY_LIMIT: usize = 1_000_000;
const MAX_CLUSTER_INTERNAL_CONNECTION_LIMIT: usize = 65_536;
const MAX_RPC_STREAM_COMMAND_LIMIT: usize = 65_536;
const CACHE_READ_MEMORY_MAX_OBJECT_BYTES: u64 = 50 * 1024 * 1024;
const CACHE_READ_MEMORY_MEDIUM_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
const CACHE_READ_MEMORY_SMALL_OBJECT_BYTES: u64 = 4 * 1024 * 1024;
const CACHE_READ_MEMORY_PRESSURE_OBJECT_BYTES: u64 = 512 * 1024;
const MAX_CACHE_BUDGET_BYTES: u64 = 512 * 1024 * 1024 * 1024;
const MAX_BLOOM_BUDGET_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_NEGATIVE_CACHE_ENTRIES: usize = 64_000_000;

const MIN_LISTENER_BACKLOG: i32 = 8_192;
const MAX_LISTENER_BACKLOG: i32 = 65_535;
const MIN_PINGORA_THREADS: usize = 1;
const MAX_PINGORA_THREADS: usize = 256;
const MAX_HTTP_ACCEPT_WORKERS_PER_PORT: usize = 64;
const MAX_TCP_ACCEPT_WORKERS_PER_PORT: usize = 64;
const MAX_UDP_DEMUX_WORKERS_PER_PORT: usize = 128;
const MIN_PINGORA_KEEPALIVE_POOL_PER_THREAD: usize = 256;
const MAX_PINGORA_KEEPALIVE_POOL_PER_THREAD: usize = 65_535;
const MIN_ACCESS_LOG_QUEUE_CAPACITY: usize = 2_048;
const MAX_ACCESS_LOG_QUEUE_CAPACITY: usize = 1_000_000;
const MIN_ACCESS_LOG_BATCH_SIZE: usize = 512;
const MAX_ACCESS_LOG_BATCH_SIZE: usize = 10_000;
const MIN_NODE_LOG_QUEUE_CAPACITY: usize = 512;
const MAX_NODE_LOG_QUEUE_CAPACITY: usize = 100_000;
const MIN_METRICS_QUEUE_CAPACITY: usize = 2_048;
const MAX_METRICS_QUEUE_CAPACITY: usize = 1_000_000;
const MIN_FIREWALL_IP_LIMITERS: usize = 32_768;
const MAX_FIREWALL_IP_LIMITERS: usize = 32_000_000;
const MIN_FIREWALL_ROLLING_COUNTERS: usize = 16_384;
const MAX_FIREWALL_ROLLING_COUNTERS: usize = 16_000_000;
const MIN_FIREWALL_IP_BW_COUNTERS: usize = 32_768;
const MAX_FIREWALL_IP_BW_COUNTERS: usize = 16_000_000;
const MIN_FIREWALL_CANDIDATE_STATS: usize = 4_096;
const MAX_FIREWALL_CANDIDATE_STATS: usize = 2_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigSyncBudget {
    pub available_bytes: u64,
    pub pressure_level: MemoryPressureLevel,
    pub staging_budget_bytes: u64,
    pub commit_reserve_bytes: u64,
    pub allow_new_prepare: bool,
    pub allow_commit: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MemoryPressureLevel {
    Normal,
    Elevated,
    High,
    Critical,
}

impl MemoryPressureLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            MemoryPressureLevel::Normal => "normal",
            MemoryPressureLevel::Elevated => "elevated",
            MemoryPressureLevel::High => "high",
            MemoryPressureLevel::Critical => "critical",
        }
    }
}

impl Default for MemoryPressureLevel {
    fn default() -> Self {
        Self::Normal
    }
}

pub struct MemoryGovernor {
    http_connections: AtomicU64,
    tcp_connections: AtomicU64,
    h3_connections: AtomicU64,
    udp_sessions: AtomicU64,
    h2_streams: AtomicU64,
    h3_requests: AtomicU64,
    origin_connects: AtomicU64,
    shared_connection_bytes: AtomicU64,
    zero_copy_relays: AtomicU64,
    zero_copy_relay_bytes: AtomicU64,
    udp_queued_bytes: AtomicU64,
    background_work: AtomicU64,
    request_body_waf: AtomicU64,
    response_body_waf: AtomicU64,
    response_transform: AtomicU64,
    cache_revalidate: AtomicU64,
    cache_write: AtomicU64,
    cache_read_memory: AtomicU64,
    cluster_internal_connections: AtomicU64,
    rpc_stream_commands: AtomicU64,
    sni_relays: AtomicU64,
    cache_read_memory_bytes: AtomicU64,
    admission_rejects: [AtomicU64; ADMISSION_CLASS_COUNT],
    cached_total_bytes: AtomicU64,
    cached_used_bytes: AtomicU64,
    cached_available_bytes: AtomicU64,
    cached_fd_soft_limit: AtomicU64,
    cached_cpu_parallelism: AtomicU64,
    cached_fd_used: AtomicU64,
    cached_fd_used_at_millis: AtomicU64,
    cached_at_millis: AtomicU64,
    cached_cgroup_managed: AtomicU64,
    cached_cgroup_memory_max_bytes: AtomicU64,
    cached_cgroup_memory_high_bytes: AtomicU64,
    cached_cgroup_swap_max_bytes: AtomicU64,
    cached_process_rss_bytes: AtomicU64,
    cached_process_pss_bytes: AtomicU64,
    cached_process_anon_rss_bytes: AtomicU64,
    resident: ResidentMemoryAccounting,
    #[cfg(test)]
    fd_count_reads: AtomicU64,
}

pub struct AdmissionPermit<'a> {
    governor: &'a MemoryGovernor,
    class: AdmissionClass,
    shared_connection_charge_bytes: u64,
    cache_read_memory_charge_bytes: u64,
}

pub type StaticAdmissionPermit = AdmissionPermit<'static>;

pub struct ZeroCopyRelayPermit<'a> {
    governor: &'a MemoryGovernor,
    charge_bytes: u64,
}

pub type StaticZeroCopyRelayPermit = ZeroCopyRelayPermit<'static>;

pub struct UdpQueueBytePermit<'a> {
    governor: &'a MemoryGovernor,
    bytes: u64,
}

pub type StaticUdpQueueBytePermit = UdpQueueBytePermit<'static>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FdEquivalentSnapshot {
    pub soft_limit: u64,
    pub used: u64,
    pub used_pct: u64,
    pub pressure_level: MemoryPressureLevel,
}

impl MemoryGovernor {
    pub fn new() -> Self {
        Self {
            http_connections: AtomicU64::new(0),
            tcp_connections: AtomicU64::new(0),
            h3_connections: AtomicU64::new(0),
            udp_sessions: AtomicU64::new(0),
            h2_streams: AtomicU64::new(0),
            h3_requests: AtomicU64::new(0),
            origin_connects: AtomicU64::new(0),
            shared_connection_bytes: AtomicU64::new(0),
            zero_copy_relays: AtomicU64::new(0),
            zero_copy_relay_bytes: AtomicU64::new(0),
            udp_queued_bytes: AtomicU64::new(0),
            background_work: AtomicU64::new(0),
            request_body_waf: AtomicU64::new(0),
            response_body_waf: AtomicU64::new(0),
            response_transform: AtomicU64::new(0),
            cache_revalidate: AtomicU64::new(0),
            cache_write: AtomicU64::new(0),
            cache_read_memory: AtomicU64::new(0),
            cluster_internal_connections: AtomicU64::new(0),
            rpc_stream_commands: AtomicU64::new(0),
            sni_relays: AtomicU64::new(0),
            cache_read_memory_bytes: AtomicU64::new(0),
            admission_rejects: std::array::from_fn(|_| AtomicU64::new(0)),
            cached_total_bytes: AtomicU64::new(0),
            cached_used_bytes: AtomicU64::new(0),
            cached_available_bytes: AtomicU64::new(0),
            cached_fd_soft_limit: AtomicU64::new(0),
            cached_cpu_parallelism: AtomicU64::new(0),
            cached_fd_used: AtomicU64::new(0),
            cached_fd_used_at_millis: AtomicU64::new(0),
            cached_at_millis: AtomicU64::new(0),
            cached_cgroup_managed: AtomicU64::new(0),
            cached_cgroup_memory_max_bytes: AtomicU64::new(0),
            cached_cgroup_memory_high_bytes: AtomicU64::new(0),
            cached_cgroup_swap_max_bytes: AtomicU64::new(u64::MAX),
            cached_process_rss_bytes: AtomicU64::new(0),
            cached_process_pss_bytes: AtomicU64::new(0),
            cached_process_anon_rss_bytes: AtomicU64::new(0),
            resident: ResidentMemoryAccounting::new(),
            #[cfg(test)]
            fd_count_reads: AtomicU64::new(0),
        }
    }

    pub fn try_admit_sni_relay(&self) -> Option<AdmissionPermit<'_>> {
        self.try_admit(AdmissionClass::SniRelay)
    }

    pub fn relay_socket_buffer_bytes(&self) -> usize {
        match self.current_memory_pressure_level() {
            MemoryPressureLevel::Critical => 256 * 1024,
            MemoryPressureLevel::High => 512 * 1024,
            MemoryPressureLevel::Elevated => 768 * 1024,
            MemoryPressureLevel::Normal => 1024 * 1024,
        }
    }

    pub fn try_admit(&self, class: AdmissionClass) -> Option<AdmissionPermit<'_>> {
        let cache_read_memory_charge_bytes = if class == AdmissionClass::CacheReadMemory {
            CACHE_READ_MEMORY_ESTIMATED_BYTES
        } else {
            0
        };
        self.try_admit_with_charges(class, cache_read_memory_charge_bytes)
    }

    pub fn try_admit_cache_read(&self, bytes: u64) -> Option<AdmissionPermit<'_>> {
        let bytes = bytes.max(1);
        if bytes > self.cache_read_memory_object_limit_bytes() {
            self.record_reject(AdmissionClass::CacheReadMemory);
            return None;
        }
        self.try_admit_with_charges(AdmissionClass::CacheReadMemory, bytes)
    }

    pub fn try_admit_zero_copy_relay(&self) -> Option<ZeroCopyRelayPermit<'_>> {
        if self.is_connection_admission_pressure_high()
            || self.fd_equivalent_snapshot().pressure_level >= MemoryPressureLevel::High
        {
            return None;
        }

        let limit = self.zero_copy_relay_limit() as u64;
        let current = self.zero_copy_relays.fetch_add(1, Ordering::AcqRel) + 1;
        if current > limit {
            self.zero_copy_relays.fetch_sub(1, Ordering::AcqRel);
            return None;
        }

        let budget = self.zero_copy_relay_budget_bytes().max(1);
        let used = self
            .zero_copy_relay_bytes
            .fetch_add(ZERO_COPY_RELAY_ESTIMATED_BYTES, Ordering::AcqRel)
            .saturating_add(ZERO_COPY_RELAY_ESTIMATED_BYTES);
        if used > budget {
            self.zero_copy_relay_bytes
                .fetch_sub(ZERO_COPY_RELAY_ESTIMATED_BYTES, Ordering::AcqRel);
            self.zero_copy_relays.fetch_sub(1, Ordering::AcqRel);
            return None;
        }

        Some(ZeroCopyRelayPermit {
            governor: self,
            charge_bytes: ZERO_COPY_RELAY_ESTIMATED_BYTES,
        })
    }

    pub fn try_reserve_udp_queue_bytes(&self, bytes: usize) -> Option<UdpQueueBytePermit<'_>> {
        let bytes = bytes.max(1) as u64;
        let budget = self.udp_queued_bytes_budget().max(1);
        let mut current = self.udp_queued_bytes.load(Ordering::Acquire);
        loop {
            let next = current.saturating_add(bytes);
            if next > budget {
                return None;
            }
            match self.udp_queued_bytes.compare_exchange(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(UdpQueueBytePermit {
                        governor: self,
                        bytes,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn try_admit_with_charges(
        &self,
        class: AdmissionClass,
        cache_read_memory_charge_bytes: u64,
    ) -> Option<AdmissionPermit<'_>> {
        let counter = self.counter(class);
        let current = counter.fetch_add(1, Ordering::AcqRel) + 1;
        if current > self.limit_for(class) as u64 {
            counter.fetch_sub(1, Ordering::AcqRel);
            self.record_reject(class);
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
                self.record_reject(class);
                return None;
            }
        }

        if cache_read_memory_charge_bytes > 0 {
            let budget = cache_read_memory_budget_bytes(&self.memory_snapshot());
            let used = self
                .cache_read_memory_bytes
                .fetch_add(cache_read_memory_charge_bytes, Ordering::AcqRel)
                .saturating_add(cache_read_memory_charge_bytes);
            if used > budget {
                self.cache_read_memory_bytes
                    .fetch_sub(cache_read_memory_charge_bytes, Ordering::AcqRel);
                if shared_connection_charge_bytes > 0 {
                    self.shared_connection_bytes
                        .fetch_sub(shared_connection_charge_bytes, Ordering::AcqRel);
                }
                counter.fetch_sub(1, Ordering::AcqRel);
                self.record_reject(class);
                return None;
            }
        }

        Some(AdmissionPermit {
            governor: self,
            class,
            shared_connection_charge_bytes,
            cache_read_memory_charge_bytes,
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
                pressure_adjusted_min_limit(&snapshot, MIN_REQUEST_BODY_WAF_LIMIT, 32, 8),
                MAX_REQUEST_BODY_WAF_LIMIT,
            ),
            AdmissionClass::ResponseBodyWaf => connection_limit(
                snapshot.available_bytes / 8,
                RESPONSE_BODY_WAF_ESTIMATED_BYTES,
                pressure_adjusted_min_limit(&snapshot, MIN_RESPONSE_BODY_WAF_LIMIT, 64, 16),
                MAX_RESPONSE_BODY_WAF_LIMIT,
            ),
            AdmissionClass::ResponseTransform => connection_limit(
                snapshot.available_bytes / 6,
                RESPONSE_TRANSFORM_ESTIMATED_BYTES,
                pressure_adjusted_min_limit(&snapshot, MIN_RESPONSE_TRANSFORM_LIMIT, 8, 2),
                MAX_RESPONSE_TRANSFORM_LIMIT,
            ),
            AdmissionClass::CacheRevalidate => connection_limit(
                snapshot.available_bytes / 16,
                CACHE_REVALIDATE_ESTIMATED_BYTES,
                pressure_adjusted_min_limit(&snapshot, MIN_CACHE_REVALIDATE_LIMIT, 16, 4),
                MAX_CACHE_REVALIDATE_LIMIT,
            ),
            AdmissionClass::CacheWrite => connection_limit(
                if memory_pressure_high(&snapshot) {
                    snapshot.cache_budget_bytes / 32
                } else {
                    snapshot.cache_budget_bytes / 4
                },
                CACHE_WRITE_ESTIMATED_BYTES,
                pressure_adjusted_min_limit(&snapshot, MIN_CACHE_WRITE_LIMIT, 16, 4),
                MAX_CACHE_WRITE_LIMIT,
            ),
            AdmissionClass::CacheReadMemory => connection_limit(
                cache_read_memory_budget_bytes(&snapshot),
                CACHE_READ_MEMORY_ESTIMATED_BYTES,
                pressure_adjusted_min_limit(&snapshot, MIN_CACHE_READ_MEMORY_LIMIT, 4, 1),
                MAX_CACHE_READ_MEMORY_LIMIT,
            ),
            AdmissionClass::ClusterInternalConnection => connection_limit(
                state_budget_bytes(&snapshot) / 64,
                CLUSTER_INTERNAL_CONNECTION_ESTIMATED_BYTES,
                pressure_adjusted_min_limit(
                    &snapshot,
                    MIN_CLUSTER_INTERNAL_CONNECTION_LIMIT,
                    16,
                    4,
                ),
                MAX_CLUSTER_INTERNAL_CONNECTION_LIMIT,
            ),
            AdmissionClass::RpcStreamCommand => connection_limit(
                event_queue_budget_bytes(&snapshot) / 8,
                RPC_STREAM_COMMAND_ESTIMATED_BYTES,
                pressure_adjusted_min_limit(&snapshot, MIN_RPC_STREAM_COMMAND_LIMIT, 8, 2),
                MAX_RPC_STREAM_COMMAND_LIMIT,
            ),
            AdmissionClass::SniRelay => runtime_limit(
                &snapshot,
                AdmissionClass::SniRelay,
                MIN_TCP_CONNECTION_LIMIT,
                MAX_TCP_CONNECTION_LIMIT,
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

    pub fn current_memory_pressure_level(&self) -> MemoryPressureLevel {
        memory_pressure_level(&self.memory_snapshot())
    }

    pub fn config_sync_budget(&self) -> ConfigSyncBudget {
        config_sync_budget_for_snapshot(&self.memory_snapshot())
    }

    pub fn relay_copy_buffer_bytes(&self) -> usize {
        let snapshot = self.memory_snapshot();
        let active = self
            .tcp_connections
            .load(Ordering::Relaxed)
            .saturating_add(self.sni_relays.load(Ordering::Relaxed));
        relay_copy_buffer_bytes(&snapshot, active)
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
        let pressure_cap = match self
            .fd_equivalent_snapshot()
            .pressure_level
            .max(memory_pressure_level(&snapshot))
        {
            MemoryPressureLevel::Normal => MAX_LISTENER_BACKLOG,
            MemoryPressureLevel::Elevated => 32_768,
            MemoryPressureLevel::High => 16_384,
            MemoryPressureLevel::Critical => 8_192,
        };
        clamp_i32(target, MIN_LISTENER_BACKLOG, pressure_cap)
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
        session_limit.clamp(1, MAX_UDP_ROUTE_LIMIT_PER_PORT)
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
        let active_sessions = self.udp_sessions.load(Ordering::Relaxed).max(1);
        let active_adjusted = if active_sessions >= 65_536 {
            target.min(64)
        } else if active_sessions >= 16_384 {
            target.min(128)
        } else if active_sessions >= 4_096 {
            target.min(512)
        } else {
            target
        };
        if memory_pressure_high(&snapshot) || self.udp_queue_utilization_pct() >= 80 {
            active_adjusted.clamp(MIN_UDP_SESSION_QUEUE_SIZE, 256)
        } else {
            active_adjusted.clamp(MIN_UDP_SESSION_QUEUE_SIZE, MAX_UDP_SESSION_QUEUE_SIZE)
        }
    }

    pub fn udp_queued_bytes(&self) -> u64 {
        self.udp_queued_bytes.load(Ordering::Relaxed)
    }

    pub fn udp_queued_bytes_budget(&self) -> u64 {
        udp_queued_bytes_budget(&self.memory_snapshot())
    }

    pub fn udp_queue_utilization_pct(&self) -> u64 {
        self.udp_queued_bytes()
            .saturating_mul(100)
            .saturating_div(self.udp_queued_bytes_budget().max(1))
    }

    pub fn h3_datagram_queue_size(&self) -> usize {
        h3_datagram_queue_size(&self.memory_snapshot())
    }

    pub fn h3_datagram_queue_budget_bytes(&self) -> usize {
        h3_datagram_queue_budget_bytes(&self.memory_snapshot())
    }

    pub fn quic_pending_route_limit_per_port(&self) -> usize {
        quic_pending_route_limit_per_port(&self.memory_snapshot(), self.udp_route_limit_per_port())
    }

    pub fn quic_pending_reassembly_budget_bytes(&self) -> usize {
        quic_pending_reassembly_budget_bytes(&self.memory_snapshot())
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

    pub fn cache_read_memory_object_limit_bytes(&self) -> u64 {
        cache_read_memory_object_limit_bytes(&self.memory_snapshot())
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
        let global_floor = if fd_target >= MIN_PINGORA_KEEPALIVE_POOL_PER_THREAD * threads {
            MIN_PINGORA_KEEPALIVE_POOL_PER_THREAD * threads
        } else {
            threads
        };
        let global_ceiling = MAX_PINGORA_KEEPALIVE_POOL_PER_THREAD * threads;
        let global_target = memory_target
            .min(fd_target.max(threads))
            .clamp(global_floor, global_ceiling);
        (global_target / threads).clamp(1, MAX_PINGORA_KEEPALIVE_POOL_PER_THREAD)
    }

    pub fn pingora_worker_threads(&self) -> usize {
        pingora_worker_threads(&self.memory_snapshot())
    }

    pub fn http_accept_worker_count(&self) -> usize {
        http_accept_worker_count(&self.memory_snapshot())
    }

    pub fn tcp_accept_worker_count(&self) -> usize {
        tcp_accept_worker_count(&self.memory_snapshot())
    }

    pub fn udp_demux_worker_count(&self) -> usize {
        udp_demux_worker_count(&self.memory_snapshot())
    }

    pub fn connection_admission_used_bytes(&self) -> u64 {
        self.shared_connection_bytes.load(Ordering::Relaxed)
    }

    pub fn connection_admission_budget_bytes(&self) -> u64 {
        shared_connection_admission_budget(&self.memory_snapshot())
    }

    pub fn connection_admission_utilization_pct(&self) -> u64 {
        let budget = self.connection_admission_budget_bytes().max(1);
        self.connection_admission_used_bytes()
            .saturating_mul(100)
            .saturating_div(budget)
    }

    pub fn fd_equivalent_snapshot(&self) -> FdEquivalentSnapshot {
        let snapshot = self.memory_snapshot();
        let live_fd_count = self.live_fd_count();
        let estimated_extra = self.origin_connects.load(Ordering::Relaxed).saturating_add(
            self.zero_copy_relays
                .load(Ordering::Relaxed)
                .saturating_mul(ZERO_COPY_RELAY_FD_EQUIVALENT),
        );
        let used = live_fd_count.saturating_add(estimated_extra);
        let soft_limit = snapshot.fd_soft_limit.max(1);
        let used_pct = used.saturating_mul(100).saturating_div(soft_limit);
        FdEquivalentSnapshot {
            soft_limit,
            used,
            used_pct,
            pressure_level: pressure_level_from_pct(used_pct),
        }
    }

    fn live_fd_count(&self) -> u64 {
        let now = crate::utils::time::system_timestamp_millis();
        let cached_at = self.cached_fd_used_at_millis.load(Ordering::Relaxed) as i64;
        if cached_at > 0 && now.saturating_sub(cached_at) < FD_SNAPSHOT_TTL_MS {
            return self.cached_fd_used.load(Ordering::Relaxed);
        }
        let fallback = self.cached_fd_used.load(Ordering::Relaxed);
        let live_fd_count = self.read_current_fd_count().unwrap_or(fallback);
        self.cached_fd_used.store(live_fd_count, Ordering::Relaxed);
        self.cached_fd_used_at_millis
            .store(now.max(0) as u64, Ordering::Relaxed);
        live_fd_count
    }

    fn read_current_fd_count(&self) -> Option<u64> {
        #[cfg(test)]
        self.fd_count_reads.fetch_add(1, Ordering::Relaxed);
        read_current_fd_count()
    }

    pub fn is_connection_admission_pressure_high(&self) -> bool {
        let snapshot = self.memory_snapshot();
        memory_pressure_high(&snapshot)
            || self.fd_equivalent_snapshot().pressure_level >= MemoryPressureLevel::High
            || self.connection_admission_used_bytes().saturating_mul(100)
                >= shared_connection_admission_budget(&snapshot)
                    .max(1)
                    .saturating_mul(80)
    }

    pub fn tcp_relay_pressure_idle_timeout(&self) -> Option<Duration> {
        let snapshot = self.memory_snapshot();
        let budget = shared_connection_admission_budget(&snapshot).max(1);
        let used_pct = self
            .connection_admission_used_bytes()
            .saturating_mul(100)
            .saturating_div(budget);
        let fd_level = self.fd_equivalent_snapshot().pressure_level;
        match memory_pressure_level(&snapshot).max(fd_level) {
            MemoryPressureLevel::Critical => Some(Duration::from_secs(2)),
            MemoryPressureLevel::High => Some(Duration::from_secs(5)),
            MemoryPressureLevel::Elevated => Some(Duration::from_secs(15)),
            MemoryPressureLevel::Normal if used_pct >= 90 => Some(Duration::from_secs(15)),
            MemoryPressureLevel::Normal if used_pct >= 80 => Some(Duration::from_secs(30)),
            _ => None,
        }
    }

    pub fn zero_copy_relay_limit(&self) -> usize {
        let snapshot = self.memory_snapshot();
        let memory_target = connection_limit(
            zero_copy_relay_budget_bytes(&snapshot),
            ZERO_COPY_RELAY_ESTIMATED_BYTES,
            1,
            MAX_TCP_CONNECTION_LIMIT,
        );
        let fd_target = fd_budget(&snapshot, TCP_FD_BUDGET_PCT)
            .saturating_div(ZERO_COPY_RELAY_FD_EQUIVALENT.max(1))
            .max(1) as usize;
        let blocking_target = snapshot
            .cpu_parallelism
            .max(1)
            .saturating_mul(128)
            .saturating_div(ZERO_COPY_RELAY_BLOCKING_TASKS as usize)
            .max(1);
        memory_target.min(fd_target).min(blocking_target).max(1)
    }

    pub fn zero_copy_relay_active(&self) -> u64 {
        self.zero_copy_relays.load(Ordering::Relaxed)
    }

    pub fn zero_copy_relay_used_bytes(&self) -> u64 {
        self.zero_copy_relay_bytes.load(Ordering::Relaxed)
    }

    pub fn zero_copy_relay_budget_bytes(&self) -> u64 {
        zero_copy_relay_budget_bytes(&self.memory_snapshot())
    }

    pub fn tcp_active_limit_per_ip(&self) -> usize {
        let total_limit = self.limit_for(AdmissionClass::TcpConnection).max(1);
        match self.tcp_like_pressure_level() {
            MemoryPressureLevel::Normal => (total_limit / 16).clamp(8_192, 65_536),
            MemoryPressureLevel::Elevated => (total_limit / 128).clamp(1_024, 8_192),
            MemoryPressureLevel::High => (total_limit / 1_024).clamp(128, 2_048),
            MemoryPressureLevel::Critical => (total_limit / 4_096).clamp(16, 512),
        }
    }

    fn tcp_like_pressure_level(&self) -> MemoryPressureLevel {
        let snapshot = self.memory_snapshot();
        let connection_pct = self
            .connection_admission_used_bytes()
            .saturating_mul(100)
            .saturating_div(shared_connection_admission_budget(&snapshot).max(1));
        let connection_level = if connection_pct >= 95 {
            MemoryPressureLevel::Critical
        } else if connection_pct >= 85 {
            MemoryPressureLevel::High
        } else if connection_pct >= 70 {
            MemoryPressureLevel::Elevated
        } else {
            MemoryPressureLevel::Normal
        };
        memory_pressure_level(&snapshot).max(connection_level)
    }

    pub fn admission_status_line(&self) -> String {
        let snapshot = self.snapshot(self.pingora_worker_threads());
        format!(
            "conn_used={} conn_budget={} conn_used_pct={} pressure={} l4_pressure={} fd_used={} fd_soft_limit={} fd_used_pct={} fd_pressure={} zero_copy_active={} zero_copy_limit={} udp_queued={} udp_queue_budget={} udp_queue_pct={} http_active={} tcp_active={} h3_active={} udp_active={} http_limit={} tcp_limit={} h3_limit={} udp_limit={} tcp_per_ip_limit={} rejects={{http:{},tcp:{},h3:{},udp:{},origin:{}}}",
            snapshot.connection_admission_used_bytes,
            snapshot.connection_budget_bytes,
            self.connection_admission_utilization_pct(),
            snapshot.memory_pressure_level.as_str(),
            self.tcp_like_pressure_level().as_str(),
            snapshot.fd_used,
            snapshot.fd_soft_limit,
            snapshot.fd_used_pct,
            snapshot.fd_pressure_level.as_str(),
            snapshot.zero_copy_relay_active,
            snapshot.zero_copy_relay_limit,
            snapshot.udp_queued_bytes,
            snapshot.udp_queued_bytes_budget,
            self.udp_queue_utilization_pct(),
            snapshot.estimated_http_connections,
            snapshot.estimated_tcp_connections,
            snapshot.estimated_h3_connections,
            snapshot.estimated_udp_sessions,
            snapshot.http_connection_limit,
            snapshot.tcp_connection_limit,
            snapshot.h3_connection_limit,
            snapshot.udp_session_limit,
            self.tcp_active_limit_per_ip(),
            snapshot.admission_rejects.http_connection,
            snapshot.admission_rejects.tcp_connection,
            snapshot.admission_rejects.h3_connection,
            snapshot.admission_rejects.udp_session,
            snapshot.admission_rejects.origin_connect,
        )
    }

    pub fn access_log_queue_capacity(&self) -> usize {
        access_log_queue_capacity(&self.memory_snapshot())
    }

    pub fn access_log_batch_size(&self) -> usize {
        access_log_batch_size(&self.memory_snapshot())
    }

    pub fn node_log_queue_capacity(&self) -> usize {
        node_log_queue_capacity(&self.memory_snapshot())
    }

    pub fn metrics_queue_capacity(&self) -> usize {
        metrics_queue_capacity(&self.memory_snapshot())
    }

    pub fn firewall_ip_limiter_capacity(&self) -> usize {
        firewall_ip_limiter_capacity(&self.memory_snapshot())
    }

    pub fn firewall_rolling_counter_capacity(&self) -> usize {
        firewall_rolling_counter_capacity(&self.memory_snapshot())
    }

    pub fn firewall_ip_bw_counter_capacity(&self) -> usize {
        firewall_ip_bw_counter_capacity(&self.memory_snapshot())
    }

    pub fn firewall_candidate_stats_capacity(&self) -> usize {
        firewall_candidate_stats_capacity(&self.memory_snapshot())
    }

    pub fn resident_memory_snapshot(&self) -> ResidentMemorySnapshot {
        let used = |category: ResidentCategory| {
            self.resident.used[category.index()].load(Ordering::Acquire)
        };
        let total_used_bytes = self.resident.total.load(Ordering::Acquire);
        let snapshot = self.memory_snapshot();
        let total_budget_bytes = snapshot
            .cache_budget_bytes
            .saturating_add(snapshot.bloom_budget_bytes);
        let pressure_level = if total_used_bytes >= total_budget_bytes.max(1) {
            MemoryPressureLevel::Critical
        } else if total_used_bytes.saturating_mul(100)
            >= total_budget_bytes.max(1).saturating_mul(90)
        {
            MemoryPressureLevel::High
        } else if total_used_bytes.saturating_mul(100)
            >= total_budget_bytes.max(1).saturating_mul(75)
        {
            MemoryPressureLevel::Elevated
        } else {
            MemoryPressureLevel::Normal
        };
        ResidentMemorySnapshot {
            total_used_bytes,
            total_budget_bytes,
            cache_metadata_used_bytes: used(ResidentCategory::CacheMetadata),
            cache_access_log_used_bytes: used(ResidentCategory::CacheAccessLog),
            surrogate_index_used_bytes: used(ResidentCategory::SurrogateIndex),
            bloom_filter_used_bytes: used(ResidentCategory::BloomFilter),
            negative_cache_used_bytes: used(ResidentCategory::NegativeCache),
            pressure_level,
        }
    }

    pub fn resident_memory_replace(
        &self,
        category: ResidentCategory,
        old_bytes: u64,
        new_bytes: u64,
    ) -> bool {
        let _mutation = self
            .resident
            .mutation
            .lock()
            .expect("resident accounting lock poisoned");
        let slot = &self.resident.used[category.index()];
        let total = &self.resident.total;
        if old_bytes == new_bytes {
            return true;
        }
        if new_bytes > old_bytes {
            let delta = new_bytes - old_bytes;
            let budget = match category {
                ResidentCategory::CacheMetadata
                | ResidentCategory::CacheAccessLog
                | ResidentCategory::SurrogateIndex => self.memory_snapshot().cache_budget_bytes,
                ResidentCategory::BloomFilter | ResidentCategory::NegativeCache => {
                    self.memory_snapshot().bloom_budget_bytes
                }
            };
            let current = total.load(Ordering::Acquire);
            if current.saturating_add(delta) > budget.max(1) {
                return false;
            }
            total.fetch_add(delta, Ordering::AcqRel);
            slot.fetch_add(delta, Ordering::AcqRel);
        } else {
            let delta = old_bytes - new_bytes;
            slot.fetch_sub(delta.min(slot.load(Ordering::Acquire)), Ordering::AcqRel);
            total.fetch_sub(delta.min(total.load(Ordering::Acquire)), Ordering::AcqRel);
        }
        true
    }

    pub fn resident_memory_replace_owned(
        &self,
        category: ResidentCategory,
        owner: &str,
        new_bytes: u64,
    ) -> bool {
        RESIDENT_OWNER_UPDATE_IN_PROGRESS.with(|in_progress| {
            if in_progress.replace(true) {
                return false;
            }
            let result = (|| {
                let mut owners = self
                    .resident
                    .owners
                    .lock()
                    .expect("resident accounting lock poisoned");
                let key = (category, owner.to_string());
                let old_bytes = owners.get(&key).copied().unwrap_or(0);
                if !self.resident_memory_replace(category, old_bytes, new_bytes) {
                    return false;
                }
                if new_bytes == 0 {
                    owners.remove(&key);
                } else {
                    owners.insert(key, new_bytes);
                }
                true
            })();
            in_progress.set(false);
            result
        })
    }

    pub fn resident_memory_remove(&self, category: ResidentCategory, bytes: u64) {
        let _ = self.resident_memory_replace(category, bytes, 0);
    }

    pub fn snapshot(&self, pingora_threads: usize) -> GovernorSnapshot {
        let mem = self.memory_snapshot();
        let fd_snapshot = self.fd_equivalent_snapshot();
        GovernorSnapshot {
            memory_total_bytes: mem.total_bytes,
            memory_used_bytes: mem.used_bytes,
            memory_available_bytes: mem.available_bytes,
            memory_pressure_level: memory_pressure_level(&mem),
            fd_soft_limit: mem.fd_soft_limit,
            fd_used: fd_snapshot.used,
            fd_used_pct: fd_snapshot.used_pct,
            fd_pressure_level: fd_snapshot.pressure_level,
            http_fd_budget: fd_budget(&mem, HTTP_FD_BUDGET_PCT),
            tcp_fd_budget: fd_budget(&mem, TCP_FD_BUDGET_PCT),
            udp_fd_budget: fd_budget(&mem, UDP_FD_BUDGET_PCT),
            origin_fd_budget: fd_budget(&mem, ORIGIN_FD_BUDGET_PCT),
            keepalive_fd_budget: fd_budget(&mem, KEEPALIVE_FD_BUDGET_PCT),
            cpu_parallelism: mem.cpu_parallelism,
            connection_budget_bytes: mem.connection_budget_bytes,
            connection_admission_used_bytes: self.shared_connection_bytes.load(Ordering::Relaxed),
            zero_copy_relay_active: self.zero_copy_relay_active(),
            zero_copy_relay_limit: self.zero_copy_relay_limit(),
            zero_copy_relay_used_bytes: self.zero_copy_relay_used_bytes(),
            zero_copy_relay_budget_bytes: self.zero_copy_relay_budget_bytes(),
            udp_queued_bytes: self.udp_queued_bytes(),
            udp_queued_bytes_budget: self.udp_queued_bytes_budget(),
            admission_rejects: self.admission_reject_snapshot(),
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
            h3_datagram_queue_size: h3_datagram_queue_size(&mem),
            h3_datagram_queue_budget_bytes: h3_datagram_queue_budget_bytes(&mem),
            quic_pending_route_limit_per_port: quic_pending_route_limit_per_port(
                &mem,
                self.udp_route_limit_per_port(),
            ),
            quic_pending_reassembly_budget_bytes: quic_pending_reassembly_budget_bytes(&mem),
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
            cache_read_memory_limit: self.limit_for(AdmissionClass::CacheReadMemory),
            cluster_internal_connection_limit: self
                .limit_for(AdmissionClass::ClusterInternalConnection),
            rpc_stream_command_limit: self.limit_for(AdmissionClass::RpcStreamCommand),
            cache_read_memory_used_bytes: self.cache_read_memory_bytes.load(Ordering::Relaxed),
            cache_read_memory_budget_bytes: cache_read_memory_budget_bytes(&mem),
            cache_read_memory_object_limit_bytes: cache_read_memory_object_limit_bytes(&mem),
            cache_budget_bytes: mem.cache_budget_bytes,
            bloom_budget_bytes: mem.bloom_budget_bytes,
            negative_cache_limit: self.negative_cache_limit(),
            listener_backlog: self.listener_backlog(),
            pingora_worker_threads: pingora_worker_threads(&mem),
            http_accept_workers: http_accept_worker_count(&mem),
            tcp_accept_workers: tcp_accept_worker_count(&mem),
            udp_demux_workers: udp_demux_worker_count(&mem),
            access_log_queue_capacity: access_log_queue_capacity(&mem),
            access_log_batch_size: access_log_batch_size(&mem),
            node_log_queue_capacity: node_log_queue_capacity(&mem),
            metrics_queue_capacity: metrics_queue_capacity(&mem),
            firewall_ip_limiter_capacity: firewall_ip_limiter_capacity(&mem),
            firewall_rolling_counter_capacity: firewall_rolling_counter_capacity(&mem),
            firewall_ip_bw_counter_capacity: firewall_ip_bw_counter_capacity(&mem),
            firewall_candidate_stats_capacity: firewall_candidate_stats_capacity(&mem),
            l4_aggregate_state_budget_bytes: state_budget_bytes(&mem) / 8,
            kernel_sync_queue_budget_bytes: state_budget_bytes(&mem) / 16,
            cardinality_state_budget_bytes: state_budget_bytes(&mem) / 8,
            regex_cache_budget_bytes: state_budget_bytes(&mem) / 8,
            logging_retry_budget_bytes: event_queue_budget_bytes(&mem) / 3,
            local_log_queue_budget_bytes: event_queue_budget_bytes(&mem) / 8,
            ip_report_queue_budget_bytes: event_queue_budget_bytes(&mem) / 8,
            af_xdp_budget_bytes: state_budget_bytes(&mem) / 4,
            pingora_keepalive_pool_size: self.pingora_keepalive_pool_size(pingora_threads),
            resident_memory: self.resident_memory_snapshot(),
            cgroup_managed: mem.cgroup_managed,
            cgroup_memory_max_bytes: mem.cgroup_memory_max_bytes,
            cgroup_memory_high_bytes: mem.cgroup_memory_high_bytes,
            cgroup_swap_max_bytes: mem.cgroup_swap_max_bytes,
            process_rss_bytes: mem.process_rss_bytes,
            process_pss_bytes: mem.process_pss_bytes,
            process_anon_rss_bytes: mem.process_anon_rss_bytes,
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
            AdmissionClass::CacheReadMemory => &self.cache_read_memory,
            AdmissionClass::ClusterInternalConnection => &self.cluster_internal_connections,
            AdmissionClass::RpcStreamCommand => &self.rpc_stream_commands,
            AdmissionClass::SniRelay => &self.sni_relays,
        }
    }

    fn reject_counter(&self, class: AdmissionClass) -> &AtomicU64 {
        &self.admission_rejects[class_index(class)]
    }

    fn record_reject(&self, class: AdmissionClass) {
        self.reject_counter(class).fetch_add(1, Ordering::Relaxed);
    }

    pub fn admission_reject_snapshot(&self) -> AdmissionRejectSnapshot {
        AdmissionRejectSnapshot {
            http_connection: self
                .reject_counter(AdmissionClass::HttpConnection)
                .load(Ordering::Relaxed),
            tcp_connection: self
                .reject_counter(AdmissionClass::TcpConnection)
                .load(Ordering::Relaxed),
            h3_connection: self
                .reject_counter(AdmissionClass::Http3Connection)
                .load(Ordering::Relaxed),
            udp_session: self
                .reject_counter(AdmissionClass::UdpSession)
                .load(Ordering::Relaxed),
            h2_stream: self
                .reject_counter(AdmissionClass::Http2Stream)
                .load(Ordering::Relaxed),
            h3_request: self
                .reject_counter(AdmissionClass::Http3Request)
                .load(Ordering::Relaxed),
            origin_connect: self
                .reject_counter(AdmissionClass::OriginConnect)
                .load(Ordering::Relaxed),
            background_work: self
                .reject_counter(AdmissionClass::BackgroundWork)
                .load(Ordering::Relaxed),
            request_body_waf: self
                .reject_counter(AdmissionClass::RequestBodyWaf)
                .load(Ordering::Relaxed),
            response_body_waf: self
                .reject_counter(AdmissionClass::ResponseBodyWaf)
                .load(Ordering::Relaxed),
            response_transform: self
                .reject_counter(AdmissionClass::ResponseTransform)
                .load(Ordering::Relaxed),
            cache_revalidate: self
                .reject_counter(AdmissionClass::CacheRevalidate)
                .load(Ordering::Relaxed),
            cache_write: self
                .reject_counter(AdmissionClass::CacheWrite)
                .load(Ordering::Relaxed),
            cache_read_memory: self
                .reject_counter(AdmissionClass::CacheReadMemory)
                .load(Ordering::Relaxed),
            cluster_internal_connection: self
                .reject_counter(AdmissionClass::ClusterInternalConnection)
                .load(Ordering::Relaxed),
            rpc_stream_command: self
                .reject_counter(AdmissionClass::RpcStreamCommand)
                .load(Ordering::Relaxed),
            sni_relay: self
                .reject_counter(AdmissionClass::SniRelay)
                .load(Ordering::Relaxed),
        }
    }

    fn memory_snapshot(&self) -> BudgetedMemorySnapshot {
        let now = crate::utils::time::system_timestamp_millis();
        let cached_at = self.cached_at_millis.load(Ordering::Relaxed) as i64;
        if cached_at > 0 && now.saturating_sub(cached_at) < SNAPSHOT_TTL_MS {
            let mem = self.budgeted_from_cached();
            notify_pressure_reclaim(memory_pressure_level(&mem));
            return mem;
        }

        let snapshot = read_memory_snapshot();
        self.cached_total_bytes
            .store(snapshot.total_bytes, Ordering::Relaxed);
        self.cached_used_bytes
            .store(snapshot.used_bytes, Ordering::Relaxed);
        self.cached_available_bytes
            .store(snapshot.available_bytes, Ordering::Relaxed);
        self.cached_fd_soft_limit
            .store(snapshot.fd_soft_limit, Ordering::Relaxed);
        self.cached_cpu_parallelism
            .store(snapshot.cpu_parallelism as u64, Ordering::Relaxed);
        self.cached_cgroup_managed
            .store(u64::from(snapshot.cgroup_managed), Ordering::Relaxed);
        self.cached_cgroup_memory_max_bytes
            .store(snapshot.cgroup_memory_max_bytes, Ordering::Relaxed);
        self.cached_cgroup_memory_high_bytes
            .store(snapshot.cgroup_memory_high_bytes, Ordering::Relaxed);
        self.cached_cgroup_swap_max_bytes
            .store(snapshot.cgroup_swap_max_bytes, Ordering::Relaxed);
        self.cached_process_rss_bytes
            .store(snapshot.process_rss_bytes, Ordering::Relaxed);
        self.cached_process_pss_bytes
            .store(snapshot.process_pss_bytes, Ordering::Relaxed);
        self.cached_process_anon_rss_bytes
            .store(snapshot.process_anon_rss_bytes, Ordering::Relaxed);
        self.cached_at_millis.store(now as u64, Ordering::Relaxed);
        let mem = self.budgeted_from_cached();
        notify_pressure_reclaim(memory_pressure_level(&mem));
        mem
    }

    fn budgeted_from_cached(&self) -> BudgetedMemorySnapshot {
        let total_bytes = self.cached_total_bytes.load(Ordering::Relaxed);
        let available_bytes = self.cached_available_bytes.load(Ordering::Relaxed);
        BudgetedMemorySnapshot {
            total_bytes,
            used_bytes: self.cached_used_bytes.load(Ordering::Relaxed),
            available_bytes,
            fd_soft_limit: self.cached_fd_soft_limit.load(Ordering::Relaxed).max(1),
            cpu_parallelism: self.cached_cpu_parallelism.load(Ordering::Relaxed).max(1) as usize,
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
                effective_min_bloom_budget_bytes(total_bytes),
                MAX_BLOOM_BUDGET_BYTES,
            ),
            cgroup_managed: self.cached_cgroup_managed.load(Ordering::Relaxed) != 0,
            cgroup_memory_max_bytes: self.cached_cgroup_memory_max_bytes.load(Ordering::Relaxed),
            cgroup_memory_high_bytes: self.cached_cgroup_memory_high_bytes.load(Ordering::Relaxed),
            cgroup_swap_max_bytes: self.cached_cgroup_swap_max_bytes.load(Ordering::Relaxed),
            process_rss_bytes: self.cached_process_rss_bytes.load(Ordering::Relaxed),
            process_pss_bytes: self.cached_process_pss_bytes.load(Ordering::Relaxed),
            process_anon_rss_bytes: self.cached_process_anon_rss_bytes.load(Ordering::Relaxed),
        }
    }
}

fn notify_pressure_reclaim(level: MemoryPressureLevel) {
    PRESSURE_RECLAIM_IN_PROGRESS.with(|in_progress| {
        if in_progress.replace(true) {
            return;
        }
        crate::memory_reclaim::on_memory_pressure_observed(level);
        in_progress.set(false);
    });
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
        if self.cache_read_memory_charge_bytes > 0 {
            self.governor
                .cache_read_memory_bytes
                .fetch_sub(self.cache_read_memory_charge_bytes, Ordering::AcqRel);
        }
    }
}

impl Drop for ZeroCopyRelayPermit<'_> {
    fn drop(&mut self) {
        self.governor
            .zero_copy_relays
            .fetch_sub(1, Ordering::AcqRel);
        self.governor
            .zero_copy_relay_bytes
            .fetch_sub(self.charge_bytes, Ordering::AcqRel);
    }
}

impl Drop for UdpQueueBytePermit<'_> {
    fn drop(&mut self) {
        self.governor
            .udp_queued_bytes
            .fetch_sub(self.bytes, Ordering::AcqRel);
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
    cgroup_managed: bool,
    cgroup_memory_max_bytes: u64,
    cgroup_memory_high_bytes: u64,
    cgroup_swap_max_bytes: u64,
    process_rss_bytes: u64,
    process_pss_bytes: u64,
    process_anon_rss_bytes: u64,
}

impl Default for BudgetedMemorySnapshot {
    fn default() -> Self {
        Self {
            total_bytes: 0,
            used_bytes: 0,
            available_bytes: 0,
            fd_soft_limit: 1,
            cpu_parallelism: 1,
            connection_budget_bytes: 0,
            keepalive_budget_bytes: 0,
            cache_budget_bytes: 0,
            bloom_budget_bytes: 0,
            cgroup_managed: false,
            cgroup_memory_max_bytes: 0,
            cgroup_memory_high_bytes: 0,
            cgroup_swap_max_bytes: u64::MAX,
            process_rss_bytes: 0,
            process_pss_bytes: 0,
            process_anon_rss_bytes: 0,
        }
    }
}

fn read_memory_snapshot() -> MemorySnapshot {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();

    #[allow(unused_mut)]
    let mut total_bytes = sys.total_memory().max(MIN_MEMORY_TOTAL_BYTES);
    #[allow(unused_mut)]
    let mut used_bytes = sys.used_memory().min(total_bytes);
    #[allow(unused_mut)]
    let mut available_before_reserve = total_bytes.saturating_sub(used_bytes);
    #[cfg(target_os = "linux")]
    let (
        mut cgroup_managed,
        mut cgroup_memory_max_bytes,
        mut cgroup_memory_high_bytes,
        mut cgroup_swap_max_bytes,
    ) = (false, 0, 0, u64::MAX);
    #[cfg(not(target_os = "linux"))]
    let (cgroup_managed, cgroup_memory_max_bytes, cgroup_memory_high_bytes, cgroup_swap_max_bytes) =
        (false, 0, 0, u64::MAX);

    #[cfg(target_os = "linux")]
    {
        match linux_cgroup_memory_effective() {
            Some(cgroup) => {
                cgroup_managed = true;
                cgroup_memory_max_bytes = cgroup.max_bytes.unwrap_or(0);
                cgroup_memory_high_bytes = cgroup.high_bytes.unwrap_or(0);
                cgroup_swap_max_bytes = cgroup.swap_max_bytes.unwrap_or(u64::MAX);
                if let Some(max) = cgroup.max_bytes {
                    total_bytes = max.max(1);
                    used_bytes = cgroup.current_bytes.min(total_bytes);
                    available_before_reserve = total_bytes.saturating_sub(used_bytes);
                } else if let Some(mem_available) = linux_mem_available_bytes() {
                    available_before_reserve = mem_available.min(total_bytes);
                    used_bytes = total_bytes.saturating_sub(available_before_reserve);
                }
                if let Some(high) = cgroup.high_bytes
                    && high > 0
                    && cgroup.current_bytes >= high
                {
                    available_before_reserve = available_before_reserve.min(total_bytes / 20);
                    used_bytes = total_bytes.saturating_sub(available_before_reserve);
                }
            }
            None => {
                if let Some(mem_available) = linux_mem_available_bytes() {
                    available_before_reserve = mem_available.min(total_bytes);
                    used_bytes = total_bytes.saturating_sub(available_before_reserve);
                }
            }
        }
    }

    let rss = read_process_rss_sample();
    let available_bytes = available_after_reserve(total_bytes, available_before_reserve);

    MemorySnapshot {
        total_bytes,
        used_bytes,
        available_bytes,
        fd_soft_limit: read_fd_soft_limit(),
        cpu_parallelism: std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1),
        cgroup_managed,
        cgroup_memory_max_bytes,
        cgroup_memory_high_bytes,
        cgroup_swap_max_bytes,
        process_rss_bytes: rss.rss_bytes,
        process_pss_bytes: rss.pss_bytes,
        process_anon_rss_bytes: rss.anon_bytes,
    }
}

struct ProcessRssSample {
    rss_bytes: u64,
    pss_bytes: u64,
    anon_bytes: u64,
}

fn read_process_rss_sample() -> ProcessRssSample {
    #[cfg(target_os = "linux")]
    {
        if let Some(sample) = linux_process_rss_sample() {
            return sample;
        }
    }
    ProcessRssSample {
        rss_bytes: 0,
        pss_bytes: 0,
        anon_bytes: 0,
    }
}

#[cfg(target_os = "linux")]
fn linux_process_rss_sample() -> Option<ProcessRssSample> {
    let mut rss_bytes = 0;
    let mut pss_bytes = 0;
    let mut anon_bytes = 0;
    if let Ok(rollup) = std::fs::read_to_string("/proc/self/smaps_rollup") {
        for line in rollup.lines() {
            if let Some(value) = linux_smaps_kib(line, "Rss:") {
                rss_bytes = value.saturating_mul(1024);
            } else if let Some(value) = linux_smaps_kib(line, "Pss:") {
                pss_bytes = value.saturating_mul(1024);
            } else if let Some(value) = linux_smaps_kib(line, "Anonymous:") {
                anon_bytes = value.saturating_mul(1024);
            }
        }
    }
    if rss_bytes == 0
        && let Ok(status) = std::fs::read_to_string("/proc/self/status")
    {
        for line in status.lines() {
            if let Some(value) = linux_smaps_kib(line, "VmRSS:") {
                rss_bytes = value.saturating_mul(1024);
            } else if let Some(value) = linux_smaps_kib(line, "RssAnon:") {
                anon_bytes = value.saturating_mul(1024);
            }
        }
    }
    (rss_bytes > 0).then_some(ProcessRssSample {
        rss_bytes,
        pss_bytes,
        anon_bytes,
    })
}

#[cfg(target_os = "linux")]
fn linux_smaps_kib(line: &str, prefix: &str) -> Option<u64> {
    let rest = line.strip_prefix(prefix)?;
    rest.split_whitespace().next()?.parse().ok()
}

#[cfg(target_os = "linux")]
struct CgroupMemoryEffective {
    max_bytes: Option<u64>,
    high_bytes: Option<u64>,
    swap_max_bytes: Option<u64>,
    current_bytes: u64,
}

#[cfg(target_os = "linux")]
fn linux_cgroup_memory_effective() -> Option<CgroupMemoryEffective> {
    if let Some(effective) = linux_cgroup_v2_effective() {
        return Some(effective);
    }
    linux_cgroup_v1_effective()
}

#[cfg(target_os = "linux")]
fn linux_cgroup_v2_effective() -> Option<CgroupMemoryEffective> {
    let leaf = linux_cgroup_v2_dir()?;
    let root = std::path::Path::new("/sys/fs/cgroup");
    let current = std::fs::read_to_string(leaf.join("memory.current"))
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let inactive_file = linux_memory_stat_value(&leaf.join("memory.stat"), &["inactive_file"]);
    let mut max_bytes = None;
    let mut high_bytes = None;
    let mut swap_max_bytes = None;
    let mut dir = leaf;
    loop {
        max_bytes = min_cgroup_limit(max_bytes, linux_read_cgroup_limit(&dir.join("memory.max")));
        high_bytes = min_cgroup_limit(
            high_bytes,
            linux_read_cgroup_limit(&dir.join("memory.high")),
        );
        swap_max_bytes = min_cgroup_swap(
            swap_max_bytes,
            linux_read_cgroup_swap(&dir.join("memory.swap.max")),
        );
        if dir == root {
            break;
        }
        let Some(parent) = dir.parent() else {
            break;
        };
        if !parent.starts_with(root) {
            break;
        }
        dir = parent.to_path_buf();
    }
    Some(CgroupMemoryEffective {
        max_bytes,
        high_bytes,
        swap_max_bytes,
        current_bytes: current.saturating_sub(inactive_file),
    })
}

#[cfg(target_os = "linux")]
fn linux_cgroup_v1_effective() -> Option<CgroupMemoryEffective> {
    let limit_path = linux_cgroup_v1_file("memory.limit_in_bytes")?;
    let dir = limit_path.parent()?.to_path_buf();
    let max_bytes = linux_read_cgroup_limit(&dir.join("memory.limit_in_bytes"));
    let high_bytes = linux_read_cgroup_limit(&dir.join("memory.soft_limit_in_bytes"));
    let used = std::fs::read_to_string(dir.join("memory.usage_in_bytes"))
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let inactive_file = linux_memory_stat_value(
        &dir.join("memory.stat"),
        &["total_inactive_file", "inactive_file"],
    );
    Some(CgroupMemoryEffective {
        max_bytes,
        high_bytes,
        swap_max_bytes: linux_read_cgroup_limit(&dir.join("memory.memsw.limit_in_bytes")),
        current_bytes: used.saturating_sub(inactive_file),
    })
    .filter(|effective| effective.max_bytes.is_some() || effective.high_bytes.is_some())
}

#[cfg(target_os = "linux")]
fn linux_read_cgroup_limit(path: &std::path::Path) -> Option<u64> {
    let value = std::fs::read_to_string(path).ok()?;
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("max") {
        return None;
    }
    let parsed = trimmed.parse::<u64>().ok()?;
    if parsed == 0 || linux_cgroup_limit_is_unlimited(parsed) {
        None
    } else {
        Some(parsed)
    }
}

#[cfg(target_os = "linux")]
fn linux_read_cgroup_swap(path: &std::path::Path) -> Option<u64> {
    let value = std::fs::read_to_string(path).ok()?;
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("max") {
        return None;
    }
    let parsed = trimmed.parse::<u64>().ok()?;
    if linux_cgroup_limit_is_unlimited(parsed) {
        None
    } else {
        Some(parsed)
    }
}

#[cfg(target_os = "linux")]
fn min_cgroup_limit(current: Option<u64>, next: Option<u64>) -> Option<u64> {
    match (current, next) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, right) => right,
    }
}

#[cfg(target_os = "linux")]
fn min_cgroup_swap(current: Option<u64>, next: Option<u64>) -> Option<u64> {
    min_cgroup_limit(current, next)
}

#[cfg(target_os = "linux")]
fn linux_cgroup_v2_dir() -> Option<std::path::PathBuf> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = cgroup.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        let hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let path = parts.next()?;
        (hierarchy == "0" && controllers.is_empty()).then_some(path)
    })?;
    let relative = path.trim_start_matches('/');
    Some(std::path::Path::new("/sys/fs/cgroup").join(relative))
}

#[cfg(target_os = "linux")]
fn linux_mem_available_bytes() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        let Some(rest) = line.strip_prefix("MemAvailable:") else {
            continue;
        };
        let kib = rest.split_whitespace().next()?.parse::<u64>().ok()?;
        return Some(kib.saturating_mul(1024));
    }
    None
}

#[cfg(target_os = "linux")]
fn linux_cgroup_v1_file(file: &str) -> Option<std::path::PathBuf> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = cgroup.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        let _hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let path = parts.next()?;
        controllers
            .split(',')
            .any(|controller| controller == "memory")
            .then_some(path)
    })?;
    let relative = path.trim_start_matches('/');
    Some(
        std::path::Path::new("/sys/fs/cgroup/memory")
            .join(relative)
            .join(file),
    )
}

#[cfg(target_os = "linux")]
fn linux_memory_stat_value(path: &std::path::Path, keys: &[&str]) -> u64 {
    let Ok(stat) = std::fs::read_to_string(path) else {
        return 0;
    };
    for key in keys {
        for line in stat.lines() {
            let mut parts = line.split_whitespace();
            if parts.next() == Some(*key) {
                return parts
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0);
            }
        }
    }
    0
}

#[cfg(target_os = "linux")]
fn linux_cgroup_limit_is_unlimited(limit: u64) -> bool {
    // cgroup v1 reports "unlimited" as a value close to LONG_MAX. A real
    // large-memory container can legitimately be 1-2 TiB, so keep the sentinel
    // threshold far above practical configured limits.
    limit >= (1_u64 << 60)
}

fn available_floor_bytes(total_bytes: u64) -> u64 {
    (total_bytes / 100).clamp(8 * 1024 * 1024, 256 * 1024 * 1024)
}

fn available_after_reserve(total_bytes: u64, available_before_reserve: u64) -> u64 {
    let hard_reserve = total_bytes.saturating_mul(RESERVE_HEADROOM_PCT) / 100;
    let floor = available_floor_bytes(total_bytes).min(available_before_reserve.max(1));
    available_before_reserve
        .saturating_sub(hard_reserve)
        .max(floor)
}

fn budget_from_available(total_bytes: u64, available_bytes: u64, budget_pct: u64) -> u64 {
    let by_available = available_bytes.saturating_mul(budget_pct) / 100;
    let by_total = total_bytes.saturating_mul(budget_pct) / 100;
    let floor = available_floor_bytes(total_bytes)
        .min(64 * 1024 * 1024)
        .min(available_bytes.max(1));
    by_available.min(by_total).max(floor)
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
    let floor = min_budget
        .min(total_bytes / 4)
        .min(available_bytes.max(1))
        .max(available_floor_bytes(total_bytes).min(available_bytes.max(1)));
    by_available.min(by_total).clamp(floor, max_budget)
}

fn cache_budget_from_available(total_bytes: u64, available_bytes: u64) -> u64 {
    bounded_budget_from_available(
        total_bytes,
        available_bytes,
        CACHE_BUDGET_PCT,
        effective_min_cache_budget_bytes(total_bytes),
        MAX_CACHE_BUDGET_BYTES,
    )
}

fn effective_min_cache_budget_bytes(total_bytes: u64) -> u64 {
    if total_bytes <= 4 * 1024 * 1024 * 1024 {
        32 * 1024 * 1024
    } else if total_bytes <= 8 * 1024 * 1024 * 1024 {
        64 * 1024 * 1024
    } else {
        MIN_CACHE_BUDGET_BYTES
    }
}

fn effective_min_bloom_budget_bytes(total_bytes: u64) -> u64 {
    if total_bytes <= 4 * 1024 * 1024 * 1024 {
        8 * 1024 * 1024
    } else if total_bytes <= 8 * 1024 * 1024 * 1024 {
        16 * 1024 * 1024
    } else {
        MIN_BLOOM_BUDGET_BYTES
    }
}

fn cache_read_memory_budget_bytes(snapshot: &BudgetedMemorySnapshot) -> u64 {
    let budget = if memory_pressure_high(snapshot) {
        snapshot.available_bytes / 32
    } else {
        snapshot.available_bytes / 8
    };
    let floor = CACHE_READ_MEMORY_ESTIMATED_BYTES.min(snapshot.available_bytes.max(1));
    budget.max(floor).min(snapshot.available_bytes.max(1))
}

fn cache_read_memory_object_limit_bytes(snapshot: &BudgetedMemorySnapshot) -> u64 {
    if memory_pressure_high(snapshot) {
        return CACHE_READ_MEMORY_PRESSURE_OBJECT_BYTES;
    }
    if snapshot.total_bytes <= 4 * 1024 * 1024 * 1024 {
        CACHE_READ_MEMORY_SMALL_OBJECT_BYTES
    } else if snapshot.total_bytes <= 16 * 1024 * 1024 * 1024 {
        CACHE_READ_MEMORY_MEDIUM_OBJECT_BYTES
    } else {
        CACHE_READ_MEMORY_MAX_OBJECT_BYTES
    }
}

fn relay_copy_buffer_bytes(
    snapshot: &BudgetedMemorySnapshot,
    active_tcp_connections: u64,
) -> usize {
    let pressure_cap = match memory_pressure_level(snapshot) {
        MemoryPressureLevel::Critical => MIN_RELAY_COPY_BUFFER_BYTES,
        MemoryPressureLevel::High => LOW_RELAY_COPY_BUFFER_BYTES,
        MemoryPressureLevel::Elevated => DEFAULT_RELAY_COPY_BUFFER_BYTES,
        MemoryPressureLevel::Normal if snapshot.total_bytes >= 64 * 1024 * 1024 * 1024 => {
            MAX_RELAY_COPY_BUFFER_BYTES
        }
        MemoryPressureLevel::Normal if snapshot.total_bytes >= 16 * 1024 * 1024 * 1024 => {
            HIGH_RELAY_COPY_BUFFER_BYTES
        }
        MemoryPressureLevel::Normal => DEFAULT_RELAY_COPY_BUFFER_BYTES,
    };
    let active = active_tcp_connections.max(1);
    let relay_budget = (snapshot.connection_budget_bytes / 6).min(snapshot.available_bytes / 8);
    let per_direction_budget = (relay_budget / active / 2) as usize;
    let budget_cap = relay_buffer_step(per_direction_budget);
    pressure_cap
        .min(budget_cap)
        .max(MIN_RELAY_COPY_BUFFER_BYTES)
}

fn relay_buffer_step(bytes: usize) -> usize {
    if bytes >= MAX_RELAY_COPY_BUFFER_BYTES {
        MAX_RELAY_COPY_BUFFER_BYTES
    } else if bytes >= HIGH_RELAY_COPY_BUFFER_BYTES {
        HIGH_RELAY_COPY_BUFFER_BYTES
    } else if bytes >= DEFAULT_RELAY_COPY_BUFFER_BYTES {
        DEFAULT_RELAY_COPY_BUFFER_BYTES
    } else if bytes >= LOW_RELAY_COPY_BUFFER_BYTES {
        LOW_RELAY_COPY_BUFFER_BYTES
    } else {
        MIN_RELAY_COPY_BUFFER_BYTES
    }
}

fn pingora_worker_threads(snapshot: &BudgetedMemorySnapshot) -> usize {
    let cpu = snapshot.cpu_parallelism.max(1);
    let memory_per_worker = if memory_pressure_high(snapshot) {
        256 * 1024 * 1024
    } else {
        128 * 1024 * 1024
    };
    let memory_target = (snapshot.total_bytes / memory_per_worker).max(1) as usize;
    cpu.min(memory_target)
        .clamp(MIN_PINGORA_THREADS, MAX_PINGORA_THREADS)
}

fn http_accept_worker_count(snapshot: &BudgetedMemorySnapshot) -> usize {
    let cpu = snapshot.cpu_parallelism.max(1);
    let base = if cpu <= 4 {
        2
    } else if cpu <= 16 {
        (cpu / 3).max(2)
    } else {
        cpu / 3
    };
    let memory_target = connection_limit(
        snapshot.connection_budget_bytes / 512,
        HTTP_CONN_ESTIMATED_BYTES,
        1,
        MAX_HTTP_ACCEPT_WORKERS_PER_PORT,
    );
    let pressure_cap = if memory_pressure_high(snapshot) {
        MAX_HTTP_ACCEPT_WORKERS_PER_PORT / 4
    } else {
        MAX_HTTP_ACCEPT_WORKERS_PER_PORT
    };
    base.max(2).min(memory_target).clamp(2, pressure_cap.max(2))
}

fn tcp_accept_worker_count(snapshot: &BudgetedMemorySnapshot) -> usize {
    let cpu = snapshot.cpu_parallelism.max(1);
    let base = if cpu <= 2 {
        1
    } else if cpu <= 8 {
        cpu / 2
    } else {
        cpu.saturating_mul(3) / 4
    };
    let memory_target = connection_limit(
        snapshot.connection_budget_bytes / 512,
        TCP_CONN_ESTIMATED_BYTES,
        1,
        MAX_TCP_ACCEPT_WORKERS_PER_PORT,
    );
    let pressure_cap = if memory_pressure_high(snapshot) {
        MAX_TCP_ACCEPT_WORKERS_PER_PORT / 4
    } else {
        MAX_TCP_ACCEPT_WORKERS_PER_PORT
    };
    base.max(1).min(memory_target).clamp(1, pressure_cap.max(1))
}

fn udp_demux_worker_count(snapshot: &BudgetedMemorySnapshot) -> usize {
    let cpu = snapshot.cpu_parallelism.max(1);
    let base = if cpu <= 2 {
        1
    } else if cpu <= 8 {
        cpu / 2
    } else {
        cpu.saturating_mul(3) / 4
    };
    let memory_target = connection_limit(
        snapshot.connection_budget_bytes / 512,
        UDP_SESSION_ESTIMATED_BYTES,
        1,
        MAX_UDP_DEMUX_WORKERS_PER_PORT,
    );
    let pressure_cap = if memory_pressure_high(snapshot) {
        MAX_UDP_DEMUX_WORKERS_PER_PORT / 4
    } else {
        MAX_UDP_DEMUX_WORKERS_PER_PORT
    };
    base.max(1).min(memory_target).clamp(1, pressure_cap.max(1))
}

fn event_queue_budget_bytes(snapshot: &BudgetedMemorySnapshot) -> u64 {
    bounded_budget_from_available(
        snapshot.total_bytes,
        snapshot.available_bytes,
        EVENT_QUEUE_BUDGET_PCT,
        8 * 1024 * 1024,
        1024 * 1024 * 1024,
    )
}

fn access_log_queue_capacity(snapshot: &BudgetedMemorySnapshot) -> usize {
    connection_limit(
        event_queue_budget_bytes(snapshot) / 2,
        ACCESS_LOG_EVENT_ESTIMATED_BYTES,
        MIN_ACCESS_LOG_QUEUE_CAPACITY,
        MAX_ACCESS_LOG_QUEUE_CAPACITY,
    )
}

fn access_log_batch_size(snapshot: &BudgetedMemorySnapshot) -> usize {
    (access_log_queue_capacity(snapshot) / 10)
        .clamp(MIN_ACCESS_LOG_BATCH_SIZE, MAX_ACCESS_LOG_BATCH_SIZE)
}

fn node_log_queue_capacity(snapshot: &BudgetedMemorySnapshot) -> usize {
    connection_limit(
        event_queue_budget_bytes(snapshot) / 16,
        NODE_LOG_EVENT_ESTIMATED_BYTES,
        MIN_NODE_LOG_QUEUE_CAPACITY,
        MAX_NODE_LOG_QUEUE_CAPACITY,
    )
}

fn metrics_queue_capacity(snapshot: &BudgetedMemorySnapshot) -> usize {
    connection_limit(
        event_queue_budget_bytes(snapshot) / 2,
        HTTP_DIMENSION_EVENT_ESTIMATED_BYTES,
        MIN_METRICS_QUEUE_CAPACITY,
        MAX_METRICS_QUEUE_CAPACITY,
    )
}

fn state_budget_bytes(snapshot: &BudgetedMemorySnapshot) -> u64 {
    let budget = bounded_budget_from_available(
        snapshot.total_bytes,
        snapshot.available_bytes,
        STATE_BUDGET_PCT,
        32 * 1024 * 1024,
        64 * 1024 * 1024 * 1024,
    );
    if memory_pressure_high(snapshot) {
        budget / 4
    } else {
        budget
    }
}

fn h3_datagram_queue_size(snapshot: &BudgetedMemorySnapshot) -> usize {
    let min_limit = match memory_pressure_level(snapshot) {
        MemoryPressureLevel::Normal | MemoryPressureLevel::Elevated => MIN_H3_DATAGRAM_QUEUE_SIZE,
        MemoryPressureLevel::High => MIN_H3_DATAGRAM_QUEUE_SIZE_HIGH,
        MemoryPressureLevel::Critical => MIN_H3_DATAGRAM_QUEUE_SIZE_CRITICAL,
    };
    let target = connection_limit(
        snapshot.connection_budget_bytes / 128,
        UDP_DATAGRAM_ESTIMATED_BYTES,
        min_limit,
        MAX_H3_DATAGRAM_QUEUE_SIZE,
    );
    if memory_pressure_high(snapshot) {
        target.clamp(min_limit, 8_192)
    } else {
        target
    }
}

fn h3_datagram_queue_budget_bytes(snapshot: &BudgetedMemorySnapshot) -> usize {
    let target = if memory_pressure_high(snapshot) {
        snapshot.available_bytes / 16
    } else {
        snapshot.connection_budget_bytes / 64
    };
    let queue_floor = (h3_datagram_queue_size(snapshot) as u64)
        .saturating_mul(UDP_DATAGRAM_ESTIMATED_BYTES)
        .min(snapshot.available_bytes.max(1));
    let floor = queue_floor
        .min(8 * 1024 * 1024)
        .max(MIN_QUIC_PENDING_REASSEMBLY_BUDGET_BYTES as u64)
        .min(snapshot.available_bytes.max(1));
    target
        .clamp(floor, MAX_QUIC_PENDING_REASSEMBLY_BUDGET_BYTES as u64)
        .min(usize::MAX as u64) as usize
}

fn udp_queued_bytes_budget(snapshot: &BudgetedMemorySnapshot) -> u64 {
    let target = if memory_pressure_high(snapshot) {
        snapshot.available_bytes / 32
    } else {
        snapshot.connection_budget_bytes / 32
    };
    target
        .clamp(MIN_UDP_QUEUED_BYTES_BUDGET, MAX_UDP_QUEUED_BYTES_BUDGET)
        .min(snapshot.available_bytes.max(1))
}

fn zero_copy_relay_budget_bytes(snapshot: &BudgetedMemorySnapshot) -> u64 {
    let target = if memory_pressure_high(snapshot) {
        snapshot.connection_budget_bytes / 64
    } else {
        snapshot.connection_budget_bytes / 16
    };
    target.clamp(
        ZERO_COPY_RELAY_ESTIMATED_BYTES,
        snapshot
            .connection_budget_bytes
            .max(ZERO_COPY_RELAY_ESTIMATED_BYTES),
    )
}

fn quic_pending_route_limit_per_port(
    snapshot: &BudgetedMemorySnapshot,
    udp_route_limit_per_port: usize,
) -> usize {
    let pressure_cap = match memory_pressure_level(snapshot) {
        MemoryPressureLevel::Normal | MemoryPressureLevel::Elevated => {
            MAX_QUIC_PENDING_ROUTE_LIMIT_PER_PORT
        }
        MemoryPressureLevel::High => MAX_QUIC_PENDING_ROUTE_LIMIT_PER_PORT / 2,
        MemoryPressureLevel::Critical => MAX_QUIC_PENDING_ROUTE_LIMIT_PER_PORT / 4,
    };
    let ceiling = pressure_cap.min(udp_route_limit_per_port.max(1));
    let floor = MIN_QUIC_PENDING_ROUTE_LIMIT_PER_PORT.min(ceiling).max(1);
    (udp_route_limit_per_port / 8)
        .max(1)
        .clamp(floor, ceiling.max(1))
}

fn quic_pending_reassembly_budget_bytes(snapshot: &BudgetedMemorySnapshot) -> usize {
    let target = if memory_pressure_high(snapshot) {
        snapshot.available_bytes / 32
    } else {
        snapshot.connection_budget_bytes / 128
    };
    let floor =
        (MIN_QUIC_PENDING_REASSEMBLY_BUDGET_BYTES as u64).min(snapshot.available_bytes.max(1));
    target
        .clamp(floor, MAX_QUIC_PENDING_REASSEMBLY_BUDGET_BYTES as u64)
        .min(snapshot.available_bytes.max(1))
        .min(usize::MAX as u64) as usize
}

fn firewall_ip_limiter_capacity(snapshot: &BudgetedMemorySnapshot) -> usize {
    connection_limit(
        state_budget_bytes(snapshot) / 3,
        FIREWALL_IP_LIMITER_ESTIMATED_BYTES,
        MIN_FIREWALL_IP_LIMITERS,
        MAX_FIREWALL_IP_LIMITERS,
    )
}

fn firewall_rolling_counter_capacity(snapshot: &BudgetedMemorySnapshot) -> usize {
    connection_limit(
        state_budget_bytes(snapshot) / 3,
        FIREWALL_ROLLING_COUNTER_ESTIMATED_BYTES,
        MIN_FIREWALL_ROLLING_COUNTERS,
        MAX_FIREWALL_ROLLING_COUNTERS,
    )
}

fn firewall_ip_bw_counter_capacity(snapshot: &BudgetedMemorySnapshot) -> usize {
    connection_limit(
        state_budget_bytes(snapshot) / 4,
        FIREWALL_IP_BW_COUNTER_ESTIMATED_BYTES,
        MIN_FIREWALL_IP_BW_COUNTERS,
        MAX_FIREWALL_IP_BW_COUNTERS,
    )
}

fn firewall_candidate_stats_capacity(snapshot: &BudgetedMemorySnapshot) -> usize {
    connection_limit(
        state_budget_bytes(snapshot) / 16,
        FIREWALL_CANDIDATE_STATS_ESTIMATED_BYTES,
        MIN_FIREWALL_CANDIDATE_STATS,
        MAX_FIREWALL_CANDIDATE_STATS,
    )
}

fn memory_pressure_high(snapshot: &BudgetedMemorySnapshot) -> bool {
    matches!(
        memory_pressure_level(snapshot),
        MemoryPressureLevel::High | MemoryPressureLevel::Critical
    )
}

fn config_sync_budget_for_snapshot(snapshot: &BudgetedMemorySnapshot) -> ConfigSyncBudget {
    let pressure_level = memory_pressure_level(snapshot);
    let available_bytes = snapshot.available_bytes;
    let (commit_reserve_bytes, staging_budget_bytes, allow_new_prepare, allow_commit) =
        match pressure_level {
            MemoryPressureLevel::Normal => {
                let commit_reserve_bytes = available_bytes / 3;
                (
                    commit_reserve_bytes,
                    available_bytes
                        .saturating_sub(commit_reserve_bytes)
                        .saturating_div(4),
                    true,
                    true,
                )
            }
            MemoryPressureLevel::Elevated => {
                let commit_reserve_bytes = available_bytes / 2;
                (
                    commit_reserve_bytes,
                    available_bytes
                        .saturating_sub(commit_reserve_bytes)
                        .saturating_div(4),
                    true,
                    true,
                )
            }
            MemoryPressureLevel::High => (
                available_bytes.saturating_mul(2).saturating_div(3),
                0,
                false,
                true,
            ),
            MemoryPressureLevel::Critical => (available_bytes, 0, false, false),
        };
    ConfigSyncBudget {
        available_bytes,
        pressure_level,
        staging_budget_bytes,
        commit_reserve_bytes,
        allow_new_prepare,
        allow_commit,
    }
}

fn memory_pressure_level(snapshot: &BudgetedMemorySnapshot) -> MemoryPressureLevel {
    let mut level = if snapshot.available_bytes <= snapshot.total_bytes / 50
        || snapshot.available_bytes <= 64 * 1024 * 1024
    {
        MemoryPressureLevel::Critical
    } else if snapshot.available_bytes < snapshot.total_bytes / 10 {
        MemoryPressureLevel::High
    } else if snapshot.available_bytes < snapshot.total_bytes / 5 {
        MemoryPressureLevel::Elevated
    } else {
        MemoryPressureLevel::Normal
    };
    if snapshot.cgroup_memory_high_bytes > 0
        && snapshot.used_bytes >= snapshot.cgroup_memory_high_bytes
    {
        level = level.max(MemoryPressureLevel::High);
    }
    if snapshot.process_rss_bytes > 0
        && snapshot.cgroup_memory_max_bytes > 0
        && snapshot.process_rss_bytes.saturating_mul(100)
            >= snapshot.cgroup_memory_max_bytes.saturating_mul(90)
    {
        level = level.max(MemoryPressureLevel::High);
    }
    if snapshot.process_rss_bytes > 0
        && snapshot.cgroup_memory_max_bytes > 0
        && snapshot.process_rss_bytes >= snapshot.cgroup_memory_max_bytes
    {
        level = MemoryPressureLevel::Critical;
    }
    level
}

pub fn pressure_level_from_pct(pct: u64) -> MemoryPressureLevel {
    if pct >= 95 {
        MemoryPressureLevel::Critical
    } else if pct >= 85 {
        MemoryPressureLevel::High
    } else if pct >= 70 {
        MemoryPressureLevel::Elevated
    } else {
        MemoryPressureLevel::Normal
    }
}

fn pressure_adjusted_min_limit(
    snapshot: &BudgetedMemorySnapshot,
    normal: usize,
    high: usize,
    critical: usize,
) -> usize {
    match memory_pressure_level(snapshot) {
        MemoryPressureLevel::Normal | MemoryPressureLevel::Elevated => normal.max(1),
        MemoryPressureLevel::High => high.max(1),
        MemoryPressureLevel::Critical => critical.max(1),
    }
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
        | AdmissionClass::CacheWrite
        | AdmissionClass::CacheReadMemory
        | AdmissionClass::ClusterInternalConnection
        | AdmissionClass::RpcStreamCommand => 0,
        AdmissionClass::SniRelay => SNI_RELAY_ESTIMATED_BYTES,
    }
}

fn class_index(class: AdmissionClass) -> usize {
    match class {
        AdmissionClass::HttpConnection => 0,
        AdmissionClass::TcpConnection => 1,
        AdmissionClass::Http3Connection => 2,
        AdmissionClass::UdpSession => 3,
        AdmissionClass::Http2Stream => 4,
        AdmissionClass::Http3Request => 5,
        AdmissionClass::OriginConnect => 6,
        AdmissionClass::BackgroundWork => 7,
        AdmissionClass::RequestBodyWaf => 8,
        AdmissionClass::ResponseBodyWaf => 9,
        AdmissionClass::ResponseTransform => 10,
        AdmissionClass::CacheRevalidate => 11,
        AdmissionClass::CacheWrite => 12,
        AdmissionClass::CacheReadMemory => 13,
        AdmissionClass::ClusterInternalConnection => 14,
        AdmissionClass::RpcStreamCommand => 15,
        AdmissionClass::SniRelay => 16,
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
        AdmissionClass::SniRelay => (
            snapshot.connection_budget_bytes / 2,
            SNI_RELAY_ESTIMATED_BYTES,
            Some(TCP_FD_BUDGET_PCT),
            8_192,
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
        | AdmissionClass::CacheWrite
        | AdmissionClass::CacheReadMemory
        | AdmissionClass::ClusterInternalConnection
        | AdmissionClass::RpcStreamCommand => return min_limit,
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

#[cfg(target_os = "linux")]
fn read_current_fd_count() -> Option<u64> {
    std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.count() as u64)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn read_current_fd_count() -> Option<u64> {
    let pid = std::process::id();
    let path = format!("/dev/fd");
    std::fs::read_dir(path)
        .ok()
        .map(|entries| entries.count() as u64)
        .or_else(|| {
            let path = format!("/proc/{}/fd", pid);
            std::fs::read_dir(path)
                .ok()
                .map(|entries| entries.count() as u64)
        })
}

#[cfg(not(unix))]
fn read_current_fd_count() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_governor_memory(
        governor: &MemoryGovernor,
        total_bytes: u64,
        available_bytes: u64,
        fd_soft_limit: u64,
        fd_used: u64,
    ) {
        let now = crate::utils::time::system_timestamp_millis().max(0) as u64;
        governor
            .cached_total_bytes
            .store(total_bytes, Ordering::Release);
        governor.cached_used_bytes.store(
            total_bytes.saturating_sub(available_bytes),
            Ordering::Release,
        );
        governor
            .cached_available_bytes
            .store(available_bytes, Ordering::Release);
        governor
            .cached_fd_soft_limit
            .store(fd_soft_limit, Ordering::Release);
        governor.cached_fd_used.store(fd_used, Ordering::Release);
        governor
            .cached_fd_used_at_millis
            .store(now, Ordering::Release);
        governor.cached_at_millis.store(now, Ordering::Release);
    }

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
            ..Default::default()
        }
    }

    #[test]
    fn config_sync_budget_tightens_and_defers_with_pressure() {
        let normal = config_sync_budget_for_snapshot(&synthetic_snapshot(16, 12, 1_048_576, 8));
        let elevated = config_sync_budget_for_snapshot(&synthetic_snapshot(16, 3, 1_048_576, 8));
        let high = config_sync_budget_for_snapshot(&synthetic_snapshot(16, 1, 1_048_576, 8));
        let critical = config_sync_budget_for_snapshot(&synthetic_snapshot(16, 0, 1_048_576, 8));

        assert_eq!(normal.pressure_level, MemoryPressureLevel::Normal);
        assert_eq!(elevated.pressure_level, MemoryPressureLevel::Elevated);
        assert_eq!(high.pressure_level, MemoryPressureLevel::High);
        assert_eq!(critical.pressure_level, MemoryPressureLevel::Critical);
        assert!(normal.allow_new_prepare && normal.allow_commit);
        assert!(elevated.allow_new_prepare && elevated.allow_commit);
        assert!(elevated.staging_budget_bytes < normal.staging_budget_bytes);
        assert!(!high.allow_new_prepare && high.allow_commit);
        assert_eq!(high.staging_budget_bytes, 0);
        assert!(!critical.allow_new_prepare && !critical.allow_commit);
        assert_eq!(critical.staging_budget_bytes, 0);
        for budget in [normal, elevated, high, critical] {
            assert!(budget.commit_reserve_bytes <= budget.available_bytes);
            assert!(budget.staging_budget_bytes <= budget.available_bytes);
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
        assert_eq!(governor.admission_reject_snapshot().response_transform, 1);
        drop(permits.pop());
        assert!(governor.try_admit(class).is_some());
    }

    #[test]
    fn backlog_and_keepalive_stay_in_expected_bounds() {
        let governor = MemoryGovernor::new();
        let backlog = governor.listener_backlog();
        assert!((MIN_LISTENER_BACKLOG..=MAX_LISTENER_BACKLOG).contains(&backlog));
        let snapshot = governor.memory_snapshot();
        let keepalive = governor.pingora_keepalive_pool_size(16);
        assert!(
            (1..=MAX_PINGORA_KEEPALIVE_POOL_PER_THREAD).contains(&keepalive),
            "keepalive pool should stay positive and under the hard max"
        );
        if fd_budget(&snapshot, KEEPALIVE_FD_BUDGET_PCT) as usize
            >= MIN_PINGORA_KEEPALIVE_POOL_PER_THREAD * 16
        {
            assert!(keepalive >= MIN_PINGORA_KEEPALIVE_POOL_PER_THREAD);
        }
    }

    #[test]
    fn fd_equivalent_snapshot_reuses_cached_fd_count() {
        let governor = MemoryGovernor::new();
        governor.cached_fd_used.store(0, Ordering::Relaxed);
        governor
            .cached_fd_used_at_millis
            .store(0, Ordering::Relaxed);
        governor.fd_count_reads.store(0, Ordering::Relaxed);

        let _ = governor.fd_equivalent_snapshot();
        let reads_after_first = governor.fd_count_reads.load(Ordering::Relaxed);
        assert_eq!(reads_after_first, 1);

        for _ in 0..32 {
            let _ = governor.fd_equivalent_snapshot();
        }
        assert_eq!(
            governor.fd_count_reads.load(Ordering::Relaxed),
            reads_after_first
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
            AdmissionClass::CacheReadMemory,
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
    fn cache_read_memory_admission_tracks_bytes_and_object_limit() {
        let governor = MemoryGovernor::new();
        let object_limit = governor.cache_read_memory_object_limit_bytes();
        assert!(
            governor
                .try_admit_cache_read(object_limit.saturating_add(1))
                .is_none()
        );
        assert_eq!(governor.admission_reject_snapshot().cache_read_memory, 1);

        let budget = cache_read_memory_budget_bytes(&governor.memory_snapshot());
        let charge = object_limit.min(CACHE_READ_MEMORY_ESTIMATED_BYTES).max(1);
        let baseline = budget.saturating_sub(charge / 2);
        governor
            .cache_read_memory_bytes
            .store(baseline, Ordering::Release);
        assert!(governor.try_admit_cache_read(charge).is_none());
        assert_eq!(governor.admission_reject_snapshot().cache_read_memory, 2);
        assert_eq!(
            governor
                .counter(AdmissionClass::CacheReadMemory)
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            governor.cache_read_memory_bytes.load(Ordering::Acquire),
            baseline
        );

        let baseline = budget.saturating_sub(charge);
        governor
            .cache_read_memory_bytes
            .store(baseline, Ordering::Release);
        let permit = governor
            .try_admit_cache_read(charge)
            .expect("cache read should fit exactly");
        assert_eq!(
            governor.cache_read_memory_bytes.load(Ordering::Acquire),
            baseline + charge
        );
        drop(permit);
        assert_eq!(
            governor.cache_read_memory_bytes.load(Ordering::Acquire),
            baseline
        );
    }

    #[test]
    fn zero_copy_relay_admission_tracks_bytes_and_releases() {
        let governor = MemoryGovernor::new();
        let total = 64 * 1024 * 1024 * 1024;
        let available = 48 * 1024 * 1024 * 1024;
        governor.cached_total_bytes.store(total, Ordering::Release);
        governor
            .cached_used_bytes
            .store(total - available, Ordering::Release);
        governor
            .cached_available_bytes
            .store(available, Ordering::Release);
        governor
            .cached_fd_soft_limit
            .store(1_048_576, Ordering::Release);
        governor.cached_cpu_parallelism.store(8, Ordering::Release);
        governor.cached_at_millis.store(
            crate::utils::time::system_timestamp_millis() as u64,
            Ordering::Release,
        );
        let permit = governor
            .try_admit_zero_copy_relay()
            .expect("zero-copy relay should fit in a fresh governor");
        assert_eq!(governor.zero_copy_relay_active(), 1);
        assert_eq!(
            governor.zero_copy_relay_used_bytes(),
            ZERO_COPY_RELAY_ESTIMATED_BYTES
        );
        drop(permit);
        assert_eq!(governor.zero_copy_relay_active(), 0);
        assert_eq!(governor.zero_copy_relay_used_bytes(), 0);
    }

    #[test]
    fn udp_queue_byte_permit_tracks_budget_and_releases() {
        let governor = MemoryGovernor::new();
        let permit = governor
            .try_reserve_udp_queue_bytes(4096)
            .expect("UDP queue byte reservation should fit");
        assert_eq!(governor.udp_queued_bytes(), 4096);
        drop(permit);
        assert_eq!(governor.udp_queued_bytes(), 0);

        let budget = governor.udp_queued_bytes_budget();
        governor
            .udp_queued_bytes
            .store(budget.saturating_sub(10), Ordering::Release);
        assert!(governor.try_reserve_udp_queue_bytes(11).is_none());
        assert_eq!(governor.udp_queued_bytes(), budget.saturating_sub(10));
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
        assert_eq!(governor.admission_reject_snapshot().http_connection, 1);
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
    fn relay_copy_buffer_scales_with_memory_pressure_and_active_tcp() {
        let small = synthetic_snapshot(2, 1, 65_535, 2);
        let medium = synthetic_snapshot(16, 8, 1_048_576, 8);
        let large = synthetic_snapshot(128, 96, 16_777_216, 64);
        let high_pressure = synthetic_snapshot(16, 1, 1_048_576, 8);

        assert_eq!(
            relay_copy_buffer_bytes(&small, 1),
            DEFAULT_RELAY_COPY_BUFFER_BYTES
        );
        assert_eq!(
            relay_copy_buffer_bytes(&medium, 1),
            HIGH_RELAY_COPY_BUFFER_BYTES
        );
        assert_eq!(
            relay_copy_buffer_bytes(&large, 1),
            MAX_RELAY_COPY_BUFFER_BYTES
        );
        assert_eq!(
            relay_copy_buffer_bytes(&high_pressure, 1),
            LOW_RELAY_COPY_BUFFER_BYTES
        );
        assert!(relay_copy_buffer_bytes(&large, 100_000) < relay_copy_buffer_bytes(&large, 1));
        assert_eq!(
            relay_copy_buffer_bytes(&large, u64::MAX),
            MIN_RELAY_COPY_BUFFER_BYTES
        );
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
        assert!(fd_budget(&low_fd, UDP_FD_BUDGET_PCT) < 4_096);
        let route_limit = udp.clamp(1, MAX_UDP_ROUTE_LIMIT_PER_PORT);
        assert!(route_limit <= udp.max(1));
        assert!(quic_pending_route_limit_per_port(&low_fd, route_limit) <= route_limit);

        let h3_per_conn = multiplexed_per_connection_limit(
            &low_fd,
            H3_REQUEST_ESTIMATED_BYTES,
            MIN_H3_REQUEST_LIMIT_PER_CONNECTION,
            MAX_H3_REQUEST_LIMIT_PER_CONNECTION,
        );
        assert!(h3_per_conn >= MIN_H3_REQUEST_LIMIT_PER_CONNECTION);
    }

    #[test]
    fn scheduler_scales_workers_without_legacy_caps() {
        let small = synthetic_snapshot(2, 1, 65_535, 2);
        let large = synthetic_snapshot(256, 192, 16_777_216, 128);

        assert_eq!(pingora_worker_threads(&small), 2);
        assert!(pingora_worker_threads(&large) > 32);
        assert_eq!(http_accept_worker_count(&small), 2);
        assert!(http_accept_worker_count(&large) > http_accept_worker_count(&small));
        assert_eq!(udp_demux_worker_count(&small), 1);
        assert!(udp_demux_worker_count(&large) > http_accept_worker_count(&large));
    }

    #[test]
    fn state_and_event_queues_scale_continuously_with_machine_size() {
        let small = synthetic_snapshot(2, 1, 65_535, 2);
        let medium = synthetic_snapshot(16, 8, 1_048_576, 8);
        let large = synthetic_snapshot(1024, 768, 16_777_216, 128);

        assert!(firewall_ip_limiter_capacity(&small) < 2_000_000);
        assert!(firewall_rolling_counter_capacity(&small) < 1_000_000);
        assert!(firewall_ip_limiter_capacity(&medium) > firewall_ip_limiter_capacity(&small));
        assert!(
            firewall_rolling_counter_capacity(&large) > firewall_rolling_counter_capacity(&medium)
        );

        assert!(access_log_queue_capacity(&small) < 100_000);
        assert!(metrics_queue_capacity(&small) < 100_000);
        assert!(access_log_queue_capacity(&large) > access_log_queue_capacity(&small));
        assert!(metrics_queue_capacity(&large) > metrics_queue_capacity(&small));
        assert!(access_log_batch_size(&small) <= access_log_batch_size(&large));
    }

    #[test]
    fn small_machine_uses_reduced_cache_and_bloom_floors() {
        let small = synthetic_snapshot(2, 1, 65_535, 2);
        let large = synthetic_snapshot(32, 24, 1_048_576, 16);
        assert!(
            cache_budget_from_available(small.total_bytes, small.available_bytes)
                <= cache_budget_from_available(large.total_bytes, large.available_bytes)
        );
        assert!(effective_min_cache_budget_bytes(small.total_bytes) < MIN_CACHE_BUDGET_BYTES);
        assert!(effective_min_bloom_budget_bytes(small.total_bytes) < MIN_BLOOM_BUDGET_BYTES);
    }

    #[test]
    fn low_available_memory_does_not_expand_fixed_budget_floors() {
        let total = 512 * 1024 * 1024;
        let available = 16 * 1024 * 1024;

        assert!(available_after_reserve(total, 1 * 1024 * 1024) <= 1024 * 1024);
        assert!(budget_from_available(total, available, CONNECTION_BUDGET_PCT) <= available);
        assert!(cache_budget_from_available(total, available) <= available);
        let critical = BudgetedMemorySnapshot {
            total_bytes: total,
            used_bytes: total.saturating_sub(available),
            available_bytes: available,
            fd_soft_limit: 65_535,
            cpu_parallelism: 4,
            connection_budget_bytes: budget_from_available(total, available, CONNECTION_BUDGET_PCT),
            keepalive_budget_bytes: budget_from_available(total, available, KEEPALIVE_BUDGET_PCT),
            cache_budget_bytes: cache_budget_from_available(total, available),
            bloom_budget_bytes: bounded_budget_from_available(
                total,
                available,
                BLOOM_BUDGET_PCT,
                MIN_BLOOM_BUDGET_BYTES,
                MAX_BLOOM_BUDGET_BYTES,
            ),
            ..Default::default()
        };
        assert!(cache_read_memory_budget_bytes(&critical) <= available);
        assert!(h3_datagram_queue_budget_bytes(&critical) <= available as usize);
        assert!(quic_pending_reassembly_budget_bytes(&critical) <= available as usize);
        assert!(
            bounded_budget_from_available(
                total,
                available,
                BLOOM_BUDGET_PCT,
                MIN_BLOOM_BUDGET_BYTES,
                MAX_BLOOM_BUDGET_BYTES,
            ) <= available
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_unlimited_threshold_does_not_hide_large_real_limits() {
        assert!(!linux_cgroup_limit_is_unlimited(2 * 1024_u64.pow(4)));
        assert!(linux_cgroup_limit_is_unlimited(1_u64 << 60));
        assert_eq!(linux_smaps_kib("Rss:     4096 kB", "Rss:"), Some(4096));
        assert_eq!(min_cgroup_limit(Some(100), Some(50)), Some(50));
        assert_eq!(min_cgroup_limit(None, Some(80)), Some(80));
    }

    #[test]
    fn pressure_reduces_high_cost_admission_minimums() {
        let critical = BudgetedMemorySnapshot {
            total_bytes: 1024 * 1024 * 1024,
            used_bytes: 1008 * 1024 * 1024,
            available_bytes: 16 * 1024 * 1024,
            fd_soft_limit: 65_535,
            cpu_parallelism: 4,
            connection_budget_bytes: 16 * 1024 * 1024,
            keepalive_budget_bytes: 8 * 1024 * 1024,
            cache_budget_bytes: 16 * 1024 * 1024,
            bloom_budget_bytes: 8 * 1024 * 1024,
            ..Default::default()
        };

        assert_eq!(
            memory_pressure_level(&critical),
            MemoryPressureLevel::Critical
        );
        assert_eq!(
            pressure_adjusted_min_limit(&critical, MIN_RESPONSE_TRANSFORM_LIMIT, 8, 2),
            2
        );
        assert_eq!(
            pressure_adjusted_min_limit(&critical, MIN_CACHE_READ_MEMORY_LIMIT, 4, 1),
            1
        );
    }

    #[test]
    fn control_plane_admission_classes_roll_back_and_track_rejects() {
        let governor = MemoryGovernor::new();
        for class in [
            AdmissionClass::ClusterInternalConnection,
            AdmissionClass::RpcStreamCommand,
        ] {
            let limit = governor.limit_for(class);
            assert!(
                limit >= 16,
                "class {class:?} should have a positive governor limit"
            );
            let mut permits = Vec::new();
            for _ in 0..limit {
                permits.push(governor.try_admit(class).expect("should admit under limit"));
            }
            assert!(
                governor.try_admit(class).is_none(),
                "class {class:?} should reject when limit is full"
            );
            assert_eq!(
                governor.counter(class).load(Ordering::Acquire),
                limit as u64
            );
            drop(permits.pop());
            assert!(governor.try_admit(class).is_some());
            drop(permits);
            assert_eq!(governor.counter(class).load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn zero_copy_relay_disabled_under_high_memory_pressure() {
        let governor = MemoryGovernor::new();
        let total = 16 * 1024 * 1024 * 1024_u64;
        seed_governor_memory(&governor, total, 32 * 1024 * 1024, 1_048_576, 128);
        assert!(governor.is_memory_pressure_high());
        assert!(governor.try_admit_zero_copy_relay().is_none());
        assert_eq!(governor.zero_copy_relay_active(), 0);
        assert_eq!(governor.zero_copy_relay_used_bytes(), 0);
    }

    #[test]
    fn zero_copy_relay_disabled_under_high_fd_pressure() {
        let governor = MemoryGovernor::new();
        let total = 16 * 1024 * 1024 * 1024_u64;
        let available = 12 * 1024 * 1024 * 1024_u64;
        seed_governor_memory(&governor, total, available, 1_024, 900);
        assert!(governor.fd_equivalent_snapshot().pressure_level >= MemoryPressureLevel::High);
        assert!(governor.try_admit_zero_copy_relay().is_none());
    }

    #[test]
    fn zero_copy_relay_disabled_when_connection_admission_is_saturated() {
        let governor = MemoryGovernor::new();
        let total = 16 * 1024 * 1024 * 1024_u64;
        let available = 12 * 1024 * 1024 * 1024_u64;
        seed_governor_memory(&governor, total, available, 1_048_576, 128);
        let budget = governor.connection_admission_budget_bytes();
        governor
            .shared_connection_bytes
            .store(budget.saturating_mul(81) / 100, Ordering::Release);
        assert!(governor.is_connection_admission_pressure_high());
        assert!(governor.try_admit_zero_copy_relay().is_none());
    }

    #[test]
    fn governor_snapshot_budget_fields_stay_within_available_memory() {
        let governor = MemoryGovernor::new();
        let scenarios = [
            (512_u64, 64_u64, 65_535_u64),
            (16_u64, 8_u64, 1_048_576_u64),
            (1024_u64, 768_u64, 16_777_216_u64),
        ];
        for (total_gib, available_gib, fd_limit) in scenarios {
            let total = total_gib * 1024 * 1024 * 1024;
            let available = available_gib * 1024 * 1024 * 1024;
            seed_governor_memory(&governor, total, available, fd_limit, 128);
            let snapshot = governor.snapshot(pingora_worker_threads(&governor.memory_snapshot()));
            assert!(
                snapshot.connection_budget_bytes <= snapshot.memory_available_bytes,
                "connection budget should not exceed available memory"
            );
            assert!(
                snapshot.cache_budget_bytes <= snapshot.memory_available_bytes,
                "cache budget should not exceed available memory"
            );
            assert!(
                snapshot.bloom_budget_bytes <= snapshot.memory_available_bytes,
                "bloom budget should not exceed available memory"
            );
            assert!(
                snapshot.cache_read_memory_budget_bytes <= snapshot.memory_available_bytes,
                "cache read budget should not exceed available memory"
            );
            assert!(
                snapshot.udp_queued_bytes_budget <= snapshot.memory_available_bytes,
                "udp queue budget should not exceed available memory"
            );
            assert!(
                snapshot.l4_aggregate_state_budget_bytes <= snapshot.memory_available_bytes,
                "L4 state budget should not exceed available memory"
            );
            assert!(
                snapshot.kernel_sync_queue_budget_bytes <= snapshot.l4_aggregate_state_budget_bytes,
                "kernel sync budget should stay within L4 aggregate budget"
            );
            assert!(
                snapshot.regex_cache_budget_bytes <= snapshot.l4_aggregate_state_budget_bytes,
                "regex cache budget should stay within L4 aggregate budget"
            );
            assert!(
                snapshot.logging_retry_budget_bytes <= snapshot.memory_available_bytes,
                "logging retry budget should not exceed available memory"
            );
            assert!(
                snapshot.local_log_queue_budget_bytes <= snapshot.memory_available_bytes,
                "local log queue budget should not exceed available memory"
            );
            assert!(
                snapshot.ip_report_queue_budget_bytes <= snapshot.memory_available_bytes,
                "ip report queue budget should not exceed available memory"
            );
            assert!(
                snapshot.af_xdp_budget_bytes <= snapshot.memory_available_bytes,
                "AF_XDP budget should not exceed available memory"
            );
            assert!(
                snapshot.cluster_internal_connection_limit > 0
                    && snapshot.rpc_stream_command_limit > 0,
                "control-plane admission limits should remain positive"
            );
        }
    }

    #[test]
    fn firewall_state_capacities_are_bounded_by_hard_guardrails() {
        let governor = MemoryGovernor::new();
        for (total_gib, available_gib) in [(16_u64, 8_u64), (512_u64, 384_u64), (2_u64, 1_u64)] {
            let total = total_gib * 1024 * 1024 * 1024;
            let available = available_gib * 1024 * 1024 * 1024;
            seed_governor_memory(&governor, total, available, 1_048_576, 256);
            let snapshot = governor.snapshot(pingora_worker_threads(&governor.memory_snapshot()));
            assert!(
                snapshot.firewall_ip_limiter_capacity <= MAX_FIREWALL_IP_LIMITERS,
                "ip limiter capacity must stay below the hard guardrail max"
            );
            assert!(
                snapshot.firewall_rolling_counter_capacity <= MAX_FIREWALL_ROLLING_COUNTERS,
                "rolling counter capacity must stay below the hard guardrail max"
            );
            assert!(
                snapshot.firewall_ip_bw_counter_capacity <= MAX_FIREWALL_IP_BW_COUNTERS,
                "bandwidth counter capacity must stay below the hard guardrail max"
            );
            assert!(
                snapshot.firewall_candidate_stats_capacity <= MAX_FIREWALL_CANDIDATE_STATS,
                "candidate stats capacity must stay below the hard guardrail max"
            );
        }

        let normal = synthetic_snapshot(16, 12, 1_048_576, 8);
        let critical = synthetic_snapshot(16, 1, 1_048_576, 8);
        assert!(
            firewall_ip_limiter_capacity(&critical) <= firewall_ip_limiter_capacity(&normal),
            "ip limiter capacity should not grow under critical memory pressure"
        );
        assert!(
            firewall_rolling_counter_capacity(&critical)
                <= firewall_rolling_counter_capacity(&normal),
            "rolling counter capacity should not grow under critical memory pressure"
        );
    }

    #[test]
    fn concurrent_http_admission_never_exceeds_limit_or_leaks_counters() {
        use std::sync::Arc;
        use std::thread;

        struct ActiveGuard {
            active: Arc<AtomicU64>,
        }

        impl Drop for ActiveGuard {
            fn drop(&mut self) {
                self.active.fetch_sub(1, Ordering::AcqRel);
            }
        }

        let governor = Arc::new(MemoryGovernor::new());
        let limit = governor.limit_for(AdmissionClass::HttpConnection);
        let thread_count = 32;
        let attempts_per_thread = limit / thread_count + 128;
        let active = Arc::new(AtomicU64::new(0));
        let peak_active = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        for _ in 0..thread_count {
            let governor = Arc::clone(&governor);
            let active = Arc::clone(&active);
            let peak_active = Arc::clone(&peak_active);
            handles.push(thread::spawn(move || {
                let mut permits = Vec::new();
                for _ in 0..attempts_per_thread {
                    if let Some(permit) = governor.try_admit(AdmissionClass::HttpConnection) {
                        let current = active.fetch_add(1, Ordering::AcqRel) + 1;
                        peak_active.fetch_max(current, Ordering::AcqRel);
                        assert!(
                            governor
                                .counter(AdmissionClass::HttpConnection)
                                .load(Ordering::Acquire)
                                <= limit as u64,
                            "live HTTP admission counter must never exceed the hard limit"
                        );
                        permits.push((
                            permit,
                            ActiveGuard {
                                active: Arc::clone(&active),
                            },
                        ));
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert!(
            peak_active.load(Ordering::Acquire) <= limit as u64,
            "peak concurrent HTTP admissions must never exceed the hard limit"
        );
        assert_eq!(
            governor
                .counter(AdmissionClass::HttpConnection)
                .load(Ordering::Acquire),
            0,
            "all HTTP admission permits must be released after concurrent stress"
        );
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn mixed_connection_admission_respects_shared_connection_budget() {
        let governor = MemoryGovernor::new();
        let budget = governor.connection_admission_budget_bytes();
        let mut permits = Vec::new();
        loop {
            match governor.try_admit(AdmissionClass::HttpConnection) {
                Some(permit) => permits.push(permit),
                None => break,
            }
        }
        assert!(
            governor.connection_admission_used_bytes() <= budget,
            "shared connection bytes must never exceed the elastic budget"
        );
        assert!(
            governor.try_admit(AdmissionClass::TcpConnection).is_none(),
            "TCP admission should also fail once the shared budget is exhausted"
        );
        drop(permits);
        assert_eq!(governor.connection_admission_used_bytes(), 0);
    }

    #[test]
    fn quic_and_udp_budgets_shrink_under_memory_pressure() {
        let normal = synthetic_snapshot(16, 12, 1_048_576, 8);
        let critical = synthetic_snapshot(16, 1, 1_048_576, 8);
        assert!(
            h3_datagram_queue_size(&critical) <= h3_datagram_queue_size(&normal),
            "H3 datagram queue should shrink under pressure"
        );
        assert!(
            h3_datagram_queue_budget_bytes(&critical) <= h3_datagram_queue_budget_bytes(&normal),
            "H3 datagram byte budget should shrink under pressure"
        );
        assert!(
            udp_queued_bytes_budget(&critical) <= udp_queued_bytes_budget(&normal),
            "UDP queued byte budget should shrink under pressure"
        );
        assert!(
            quic_pending_reassembly_budget_bytes(&critical)
                <= quic_pending_reassembly_budget_bytes(&normal),
            "QUIC reassembly budget should shrink under pressure"
        );
        assert!(
            zero_copy_relay_budget_bytes(&critical) <= zero_copy_relay_budget_bytes(&normal),
            "zero-copy relay budget should shrink under pressure"
        );
    }

    #[test]
    fn cache_read_object_limit_tightens_under_pressure() {
        let governor = MemoryGovernor::new();
        let total = 64 * 1024 * 1024 * 1024_u64;
        seed_governor_memory(&governor, total, 32 * 1024 * 1024, 1_048_576, 128);
        let pressure_limit = governor.cache_read_memory_object_limit_bytes();
        assert_eq!(
            pressure_limit, CACHE_READ_MEMORY_PRESSURE_OBJECT_BYTES,
            "cache read object limit should tighten under high memory pressure"
        );
        let oversize = pressure_limit.saturating_add(1);
        assert!(governor.try_admit_cache_read(oversize).is_none());
        assert_eq!(governor.admission_reject_snapshot().cache_read_memory, 1);
    }

    #[test]
    fn admission_reject_total_counts_control_plane_rejects() {
        let governor = MemoryGovernor::new();
        let class = AdmissionClass::RpcStreamCommand;
        let limit = governor.limit_for(class);
        let mut permits = Vec::new();
        for _ in 0..limit {
            permits.push(governor.try_admit(class).unwrap());
        }
        assert!(governor.try_admit(class).is_none());
        let rejects = governor.admission_reject_snapshot();
        assert_eq!(rejects.rpc_stream_command, 1);
        assert!(rejects.total() >= 1);
        drop(permits);
    }

    #[test]
    fn tcp_relay_idle_timeout_engages_under_pressure() {
        let governor = MemoryGovernor::new();
        let total = 16 * 1024 * 1024 * 1024_u64;
        seed_governor_memory(&governor, total, 32 * 1024 * 1024, 1_048_576, 128);
        assert!(
            governor.tcp_relay_pressure_idle_timeout().is_some(),
            "idle timeout should engage under high memory pressure"
        );

        seed_governor_memory(&governor, total, 12 * 1024 * 1024 * 1024, 1_048_576, 128);
        let budget = governor.connection_admission_budget_bytes();
        governor
            .shared_connection_bytes
            .store(budget.saturating_mul(91) / 100, Ordering::Release);
        assert!(
            governor.tcp_relay_pressure_idle_timeout().is_some(),
            "idle timeout should engage when connection admission is saturated"
        );
    }
}

#[cfg(test)]
mod resident_memory_tests {
    use super::{MemoryGovernor, ResidentCategory};

    #[test]
    fn resident_owner_replace_and_remove_are_idempotent() {
        let governor = MemoryGovernor::new();
        let category = ResidentCategory::CacheMetadata;
        assert!(governor.resident_memory_replace_owned(category, "a", 128));
        assert!(governor.resident_memory_replace_owned(category, "a", 256));
        assert_eq!(
            governor
                .resident_memory_snapshot()
                .cache_metadata_used_bytes,
            256
        );
        assert!(governor.resident_memory_replace_owned(category, "a", 0));
        assert!(governor.resident_memory_replace_owned(category, "a", 0));
        assert_eq!(governor.resident_memory_snapshot().total_used_bytes, 0);
    }
}
