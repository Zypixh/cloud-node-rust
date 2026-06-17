use crate::api_config::ApiConfig;
use crate::pb;

#[derive(Debug, Clone, Default)]
pub struct HttpFirewallEvent {
    pub server_id: i64,
    pub policy_id: i64,
    pub group_id: i64,
    pub set_id: i64,
    pub url: String,
    pub client_ip: String,
    pub user_agent: String,
}

impl HttpFirewallEvent {
    pub async fn notify(self, api_config: &ApiConfig) {
        let client = match crate::rpc::client::SharedRpcClient::get(api_config).await {
            Ok(s) => s.as_rpc_client(),
            Err(_) => return,
        };
        let mut service = client.firewall_service();
        let _ = crate::rpc::track_rpc(service.notify_http_firewall_event(
            pb::NotifyHttpFirewallEventRequest {
                server_id: self.server_id,
                http_firewall_policy_id: self.policy_id,
                http_firewall_rule_group_id: self.group_id,
                http_firewall_rule_set_id: self.set_id,
                created_at: crate::utils::time::now_timestamp(),
                source_url: self.url,
                source_ip: self.client_ip,
                source_user_agent: self.user_agent,
            },
        ))
        .await;
    }
}
