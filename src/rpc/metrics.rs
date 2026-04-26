#[derive(Debug, Clone)]
pub struct ServerMetricUpdate {
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
    pub active_connections: i64,
    pub count_websocket_connections: u64,
    pub count_ips: u64,
}
