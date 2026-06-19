use crate::memory_governor::MEMORY_GOVERNOR;

#[derive(Clone, Debug)]
pub struct MemoryPlan {
    pub summary: String,
    pub items: Vec<MemoryPlanItem>,
}

#[derive(Clone, Debug)]
pub struct MemoryPlanItem {
    pub area: &'static str,
    pub purpose: &'static str,
    pub policy: String,
}

pub fn current_memory_plan(pingora_threads: usize) -> MemoryPlan {
    let snapshot = MEMORY_GOVERNOR.snapshot(pingora_threads);
    MemoryPlan {
        summary: format!(
            "memory total={} used={} available={} fd_soft_limit={} cpu_parallelism={} conn_budget={} conn_admission_used={} keepalive_budget={} cache_budget={} bloom_budget={}",
            snapshot.memory_total_bytes,
            snapshot.memory_used_bytes,
            snapshot.memory_available_bytes,
            snapshot.fd_soft_limit,
            snapshot.cpu_parallelism,
            snapshot.connection_budget_bytes,
            snapshot.connection_admission_used_bytes,
            snapshot.keepalive_budget_bytes,
            snapshot.cache_budget_bytes,
            snapshot.bloom_budget_bytes
        ),
        items: vec![
            MemoryPlanItem {
                area: "downstream_http",
                purpose: "request establishment",
                policy: format!(
                    "limit={} est={}B/class backlog={}",
                    snapshot.http_connection_limit,
                    32 * 1024,
                    snapshot.listener_backlog
                ),
            },
            MemoryPlanItem {
                area: "downstream_tcp",
                purpose: "request establishment and pass-through",
                policy: format!(
                    "limit={} est={}B/class",
                    snapshot.tcp_connection_limit,
                    24 * 1024
                ),
            },
            MemoryPlanItem {
                area: "downstream_h3",
                purpose: "QUIC connection establishment",
                policy: format!(
                    "conn_limit={} request_global_limit={} request_limit_per_conn={} datagram_queue={}",
                    snapshot.h3_connection_limit,
                    snapshot.h3_request_global_limit,
                    snapshot.h3_request_limit_per_connection,
                    snapshot.h3_datagram_queue_size
                ),
            },
            MemoryPlanItem {
                area: "downstream_udp",
                purpose: "UDP and QUIC/hy2 pass-through session establishment",
                policy: format!(
                    "session_limit={} active={} route_limit_per_port={} queue_size={} socket_buffer={} fd_budget={}",
                    snapshot.udp_session_limit,
                    snapshot.estimated_udp_sessions,
                    snapshot.udp_route_limit_per_port,
                    snapshot.udp_session_queue_size,
                    snapshot.udp_socket_buffer_size,
                    snapshot.udp_fd_budget
                ),
            },
            MemoryPlanItem {
                area: "downstream_h2",
                purpose: "multiplexed request handling",
                policy: format!(
                    "stream_global_limit={} stream_limit_per_conn={}",
                    snapshot.h2_stream_global_limit, snapshot.h2_stream_limit_per_connection
                ),
            },
            MemoryPlanItem {
                area: "upstream_keepalive",
                purpose: "prioritize origin reuse without starving new requests",
                policy: format!(
                    "per_thread_pool={} across {} pingora threads",
                    snapshot.pingora_keepalive_pool_size, pingora_threads
                ),
            },
            MemoryPlanItem {
                area: "upstream_origin_connect",
                purpose: "prioritize origin establishment for cache misses, passthrough, TCP and H3 origin",
                policy: format!(
                    "limit={} active={} est={}B/class",
                    snapshot.origin_connect_limit,
                    snapshot.estimated_origin_connects,
                    32 * 1024
                ),
            },
            MemoryPlanItem {
                area: "cache_and_background",
                purpose: "use remaining memory after headroom, connection and origin budgets",
                policy: format!(
                    "cache_budget={} bloom_budget={} negative_cache_limit={} background_limit={} revalidate_limit={} cache_write_limit={} cache_read_memory_limit={} cache_read_memory_used={} cache_read_memory_budget={} cache_read_memory_object_limit={} active_background={}; connection and origin-establishment paths win during pressure",
                    snapshot.cache_budget_bytes,
                    snapshot.bloom_budget_bytes,
                    snapshot.negative_cache_limit,
                    snapshot.background_work_limit,
                    snapshot.cache_revalidate_limit,
                    snapshot.cache_write_limit,
                    snapshot.cache_read_memory_limit,
                    snapshot.cache_read_memory_used_bytes,
                    snapshot.cache_read_memory_budget_bytes,
                    snapshot.cache_read_memory_object_limit_bytes,
                    snapshot.estimated_background_work
                ),
            },
            MemoryPlanItem {
                area: "waf_body",
                purpose: "bound request/response body inspection buffers so WAF cannot starve connection and origin establishment",
                policy: format!(
                    "request_body_limit={} response_body_limit={}",
                    snapshot.request_body_waf_limit, snapshot.response_body_waf_limit
                ),
            },
            MemoryPlanItem {
                area: "response_transform",
                purpose: "bound WebP, minify and HLS transformation buffers behind connection and origin paths",
                policy: format!("limit={}", snapshot.response_transform_limit),
            },
        ],
    }
}
