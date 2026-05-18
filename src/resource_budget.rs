use std::time::Duration;

use crate::config_models::GlobalHTTPAllConfig;

pub fn downstream_read_timeout(global_http: &GlobalHTTPAllConfig) -> Duration {
    global_http
        .auto_read_timeout
        .as_ref()
        .and_then(crate::utils::non_zero_duration)
        .unwrap_or_else(|| Duration::from_secs(10))
        .clamp(Duration::from_secs(1), Duration::from_secs(60))
}

pub fn tls_handshake_timeout(global_http: &GlobalHTTPAllConfig) -> Duration {
    downstream_read_timeout(global_http).clamp(Duration::from_secs(1), Duration::from_secs(10))
}

pub fn http2_handshake_timeout(global_http: &GlobalHTTPAllConfig) -> Duration {
    downstream_read_timeout(global_http).clamp(Duration::from_secs(1), Duration::from_secs(10))
}
