use crate::api_config::ApiConfig;
use crate::logging::NodeLogReport;
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
    log_type: Option<&str>,
    params: Option<Value>,
) {
    let params_json = params.and_then(|value| serde_json::to_vec(&value).ok());
    crate::logging::report_node_log_detailed(NodeLogReport {
        level: level.to_string(),
        tag: tag.to_string(),
        message: message.to_string(),
        server_id: server_id.unwrap_or(0),
        log_type: log_type
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        params_json,
    });
}
