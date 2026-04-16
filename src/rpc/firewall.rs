use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::RpcClient;

pub async fn notify_firewall_event(
    api_config: &ApiConfig,
    server_id: i64,
    policy_id: i64,
    group_id: i64,
    set_id: i64,
) {
    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut service = client.firewall_service();

    let _ = service
        .notify_http_firewall_event(pb::NotifyHttpFirewallEventRequest {
            server_id,
            http_firewall_policy_id: policy_id,
            http_firewall_rule_group_id: group_id,
            http_firewall_rule_set_id: set_id,
            created_at: chrono::Utc::now().timestamp(),
        })
        .await;
}
