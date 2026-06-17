use crate::api_config::ApiConfig;
use crate::pb;

pub async fn notify_firewall_event(
    api_config: &ApiConfig,
    server_id: i64,
    policy_id: i64,
    group_id: i64,
    set_id: i64,
    source_url: String,
    source_ip: String,
    source_user_agent: String,
) {
    let client = match crate::rpc::client::SharedRpcClient::get(api_config).await {
        Ok(s) => s.as_rpc_client(),
        Err(_) => return,
    };
    let mut service = client.firewall_service();

    let _ = crate::rpc::track_rpc(service.notify_http_firewall_event(
        pb::NotifyHttpFirewallEventRequest {
            server_id,
            http_firewall_policy_id: policy_id,
            http_firewall_rule_group_id: group_id,
            http_firewall_rule_set_id: set_id,
            created_at: crate::utils::time::now_timestamp(),
            source_url,
            source_ip,
            source_user_agent,
        },
    ))
    .await;
}
