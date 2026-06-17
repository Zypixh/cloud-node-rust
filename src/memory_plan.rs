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
            "memory total={} used={} available={} conn_budget={} keepalive_budget={}",
            snapshot.memory_total_bytes,
            snapshot.memory_used_bytes,
            snapshot.memory_available_bytes,
            snapshot.connection_budget_bytes,
            snapshot.keepalive_budget_bytes
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
                    "conn_limit={} request_limit_per_conn={}",
                    snapshot.h3_connection_limit, snapshot.h3_request_limit_per_connection
                ),
            },
            MemoryPlanItem {
                area: "downstream_h2",
                purpose: "multiplexed request handling",
                policy: format!(
                    "stream_limit_per_conn={}",
                    snapshot.h2_stream_limit_per_connection
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
                area: "cache_and_background",
                purpose: "use remaining memory after headroom and connection budgets",
                policy: "connection and origin-establishment paths win during pressure".to_string(),
            },
        ],
    }
}
