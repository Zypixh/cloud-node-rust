use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::RpcClient;
use serde_json::Value;

pub async fn report_server_event(
    api_config: &ApiConfig,
    server_id: i64,
    event_type: &str,
    params: Value,
) {
    if server_id <= 0 {
        return;
    }

    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut service = client.server_event_service();

    let _ = service
        .create_server_event(pb::CreateServerEventRequest {
            server_id,
            r#type: event_type.to_string(),
            params_json: serde_json::to_vec(&params).unwrap_or_default(),
        })
        .await;
}
