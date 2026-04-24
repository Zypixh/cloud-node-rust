use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::RpcClient;
use once_cell::sync::Lazy;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::{error, info};

pub struct IpReportMessage {
    pub ip_list_id: i64,
    pub value: String,
    pub ip_from: String,
    pub ip_to: String,
    pub expired_at: i64,
    pub reason: String,
    pub r#type: String,
    pub event_level: String,
    pub node_id: i64,
    pub server_id: i64,
    pub source_node_id: i64,
    pub source_server_id: i64,
    pub source_http_firewall_policy_id: i64,
    pub source_http_firewall_rule_group_id: i64,
    pub source_http_firewall_rule_set_id: i64,
    pub source_url: String,
    pub source_user_agent: String,
    pub source_category: String,
}

static REPORT_CHAN: Lazy<(
    mpsc::Sender<IpReportMessage>,
    Mutex<Option<mpsc::Receiver<IpReportMessage>>>,
)> = Lazy::new(|| {
    let (tx, rx) = mpsc::channel(1000);
    (tx, Mutex::new(Some(rx)))
});

pub async fn start_ip_report_service(api_config: ApiConfig) {
    let mut rx_opt = REPORT_CHAN.1.lock().await;
    let mut rx = match rx_opt.take() {
        Some(r) => r,
        None => return,
    };
    drop(rx_opt);

    info!("IP Report service started.");

    loop {
        let mut items = Vec::new();
        if let Some(item) = rx.recv().await {
            items.push(item);
            while items.len() < 50 {
                match rx.try_recv() {
                    Ok(i) => items.push(i),
                    Err(_) => break,
                }
            }
        }

        if items.is_empty() {
            continue;
        }

        let client = match RpcClient::new(&api_config).await {
            Ok(c) => c,
            Err(e) => {
                error!(
                    "Failed to connect to API for IP reporting: {}. Waiting 10s...",
                    e
                );
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        let mut ip_item_service = client.ip_item_service_with_type();

        let item_count = items.len();
        let req = pb::CreateIpItemsRequest {
            ip_items: items
                .into_iter()
                .map(|i| pb::create_ip_items_request::IpItem {
                    ip_list_id: i.ip_list_id,
                    value: i.value,
                    ip_from: i.ip_from,
                    ip_to: i.ip_to,
                    expired_at: i.expired_at,
                    reason: i.reason,
                    r#type: i.r#type,
                    event_level: i.event_level,
                    node_id: i.node_id,
                    server_id: i.server_id,
                    source_node_id: i.source_node_id,
                    source_server_id: i.source_server_id,
                    source_http_firewall_policy_id: i.source_http_firewall_policy_id,
                    source_http_firewall_rule_group_id: i.source_http_firewall_rule_group_id,
                    source_http_firewall_rule_set_id: i.source_http_firewall_rule_set_id,
                    source_url: i.source_url,
                    source_user_agent: i.source_user_agent,
                    source_category: i.source_category,
                })
                .collect(),
        };

        match ip_item_service.create_ip_items(req).await {
            Ok(_) => info!("Successfully reported {} IP block items to API", item_count),
            Err(e) => error!("Failed to report IP items: {}", e),
        }
    }
}

pub fn report_block(item: IpReportMessage) {
    let tx = &REPORT_CHAN.0;
    let _ = tx.try_send(item);
}
