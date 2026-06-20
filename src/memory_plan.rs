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
            "memory total={} used={} available={} pressure={} fd_soft_limit={} cpu_parallelism={} pingora_threads={} http_accept_workers={} udp_demux_workers={} conn_budget={} conn_admission_used={} admission_rejects_total={} keepalive_budget={} cache_budget={} bloom_budget={}",
            snapshot.memory_total_bytes,
            snapshot.memory_used_bytes,
            snapshot.memory_available_bytes,
            snapshot.memory_pressure_level.as_str(),
            snapshot.fd_soft_limit,
            snapshot.cpu_parallelism,
            snapshot.pingora_worker_threads,
            snapshot.http_accept_workers,
            snapshot.udp_demux_workers,
            snapshot.connection_budget_bytes,
            snapshot.connection_admission_used_bytes,
            snapshot.admission_rejects.total(),
            snapshot.keepalive_budget_bytes,
            snapshot.cache_budget_bytes,
            snapshot.bloom_budget_bytes
        ),
        items: vec![
            MemoryPlanItem {
                area: "downstream_http",
                purpose: "request establishment",
                policy: format!(
                    "limit={} est={}B/class backlog={} rejected={}",
                    snapshot.http_connection_limit,
                    32 * 1024,
                    snapshot.listener_backlog,
                    snapshot.admission_rejects.http_connection
                ),
            },
            MemoryPlanItem {
                area: "downstream_tcp",
                purpose: "request establishment and pass-through",
                policy: format!(
                    "limit={} est={}B/class rejected={}",
                    snapshot.tcp_connection_limit,
                    24 * 1024,
                    snapshot.admission_rejects.tcp_connection
                ),
            },
            MemoryPlanItem {
                area: "downstream_h3",
                purpose: "QUIC connection establishment",
                policy: format!(
                    "conn_limit={} request_global_limit={} request_limit_per_conn={} datagram_queue={} datagram_queue_bytes={} pending_route_limit={} pending_reassembly_bytes={} conn_rejected={} request_rejected={}",
                    snapshot.h3_connection_limit,
                    snapshot.h3_request_global_limit,
                    snapshot.h3_request_limit_per_connection,
                    snapshot.h3_datagram_queue_size,
                    snapshot.h3_datagram_queue_budget_bytes,
                    snapshot.quic_pending_route_limit_per_port,
                    snapshot.quic_pending_reassembly_budget_bytes,
                    snapshot.admission_rejects.h3_connection,
                    snapshot.admission_rejects.h3_request
                ),
            },
            MemoryPlanItem {
                area: "downstream_udp",
                purpose: "UDP and QUIC/hy2 pass-through session establishment",
                policy: format!(
                    "session_limit={} active={} route_limit_per_port={} queue_size={} socket_buffer={} fd_budget={} rejected={}",
                    snapshot.udp_session_limit,
                    snapshot.estimated_udp_sessions,
                    snapshot.udp_route_limit_per_port,
                    snapshot.udp_session_queue_size,
                    snapshot.udp_socket_buffer_size,
                    snapshot.udp_fd_budget,
                    snapshot.admission_rejects.udp_session
                ),
            },
            MemoryPlanItem {
                area: "downstream_h2",
                purpose: "multiplexed request handling",
                policy: format!(
                    "stream_global_limit={} stream_limit_per_conn={} rejected={}",
                    snapshot.h2_stream_global_limit,
                    snapshot.h2_stream_limit_per_connection,
                    snapshot.admission_rejects.h2_stream
                ),
            },
            MemoryPlanItem {
                area: "upstream_keepalive",
                purpose: "prioritize origin reuse without starving new requests",
                policy: format!(
                    "per_thread_pool={} across {} pingora threads planned={}",
                    snapshot.pingora_keepalive_pool_size,
                    pingora_threads,
                    snapshot.pingora_worker_threads
                ),
            },
            MemoryPlanItem {
                area: "upstream_origin_connect",
                purpose: "prioritize origin establishment for cache misses, passthrough, TCP and H3 origin",
                policy: format!(
                    "limit={} active={} est={}B/class rejected={}",
                    snapshot.origin_connect_limit,
                    snapshot.estimated_origin_connects,
                    32 * 1024,
                    snapshot.admission_rejects.origin_connect
                ),
            },
            MemoryPlanItem {
                area: "cache_and_background",
                purpose: "use remaining memory after headroom, connection and origin budgets",
                policy: format!(
                    "cache_budget={} bloom_budget={} negative_cache_limit={} background_limit={} revalidate_limit={} cache_write_limit={} cache_read_memory_limit={} cache_read_memory_used={} cache_read_memory_budget={} cache_read_memory_object_limit={} active_background={} rejected_background={} rejected_revalidate={} rejected_write={} rejected_read_memory={}; connection and origin-establishment paths win during pressure",
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
                    snapshot.estimated_background_work,
                    snapshot.admission_rejects.background_work,
                    snapshot.admission_rejects.cache_revalidate,
                    snapshot.admission_rejects.cache_write,
                    snapshot.admission_rejects.cache_read_memory
                ),
            },
            MemoryPlanItem {
                area: "waf_body",
                purpose: "bound request/response body inspection buffers so WAF cannot starve connection and origin establishment",
                policy: format!(
                    "request_body_limit={} response_body_limit={} request_rejected={} response_rejected={}",
                    snapshot.request_body_waf_limit,
                    snapshot.response_body_waf_limit,
                    snapshot.admission_rejects.request_body_waf,
                    snapshot.admission_rejects.response_body_waf
                ),
            },
            MemoryPlanItem {
                area: "response_transform",
                purpose: "bound WebP, minify and HLS transformation buffers behind connection and origin paths",
                policy: format!(
                    "limit={} rejected={}",
                    snapshot.response_transform_limit,
                    snapshot.admission_rejects.response_transform
                ),
            },
            MemoryPlanItem {
                area: "runtime_scheduler",
                purpose: "scale accept, UDP demux and Pingora workers from one CPU/memory/FD plan",
                policy: format!(
                    "pingora_threads={} http_accept_workers_per_port={} udp_demux_workers_per_port={} listener_backlog={}",
                    snapshot.pingora_worker_threads,
                    snapshot.http_accept_workers,
                    snapshot.udp_demux_workers,
                    snapshot.listener_backlog
                ),
            },
            MemoryPlanItem {
                area: "firewall_state",
                purpose: "bound WAF/CC local state continuously by machine scale instead of fixed normal/pressure tiers",
                policy: format!(
                    "ip_limiters={} rolling_counters={} ip_bw_counters={} candidate_stats={}",
                    snapshot.firewall_ip_limiter_capacity,
                    snapshot.firewall_rolling_counter_capacity,
                    snapshot.firewall_ip_bw_counter_capacity,
                    snapshot.firewall_candidate_stats_capacity
                ),
            },
            MemoryPlanItem {
                area: "async_events",
                purpose: "keep log and metric queues non-blocking without oversized low-end defaults",
                policy: format!(
                    "access_log_queue={} access_log_batch={} node_log_queue={} metrics_queue={}",
                    snapshot.access_log_queue_capacity,
                    snapshot.access_log_batch_size,
                    snapshot.node_log_queue_capacity,
                    snapshot.metrics_queue_capacity
                ),
            },
        ],
    }
}
