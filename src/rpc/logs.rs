use crate::api_config::ApiConfig;
use serde_json::Value;

pub async fn report_node_log(_api_config: &ApiConfig, level: &str, tag: &str, message: &str) {
    crate::logging::report_node_log(level.to_string(), tag.to_string(), message.to_string(), 0);
}

pub async fn report_node_log_with_context(
    _api_config: &ApiConfig,
    level: &str,
    tag: &str,
    message: &str,
    server_id: Option<i64>,
    _log_type: Option<&str>,
    _params: Option<Value>,
) {
    crate::logging::report_node_log(level.to_string(), tag.to_string(), message.to_string(), server_id.unwrap_or(0));
}
