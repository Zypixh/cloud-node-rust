pub mod acme;
pub mod api_node;
pub mod cache;
pub mod client;
pub mod events;
pub mod files;
pub mod firewall;
pub mod ip_list;
pub mod logs;
pub mod node;
pub mod node_task;
pub mod plan;
pub mod server;
pub mod ssl;
pub mod stats;
pub mod stream;
pub mod ip_report;
pub mod utils;

// Re-export syncers for main.rs
pub use node::{start_config_syncer, start_metrics_reporter, start_node_value_reporter};
pub use ip_report::start_ip_report_service;
pub use stream::start_node_stream;
pub use ip_list::start_ip_list_syncer;
pub use api_node::{start_api_node_syncer, start_updating_server_list_syncer};
pub use stats::{start_metrics_aggregator_reporter, start_bandwidth_reporter, start_daily_stat_reporter, start_metric_stat_reporter, start_top_ip_stat_reporter};
pub use ssl::start_ocsp_syncer;
pub use files::start_ip_library_syncer;

pub async fn find_node_level_info(
    api_config: &crate::api_config::ApiConfig,
    config_store: &crate::config::ConfigStore,
) -> bool {
    let client = match client::RpcClient::new(api_config).await {
        Ok(client) => client,
        Err(err) => {
            tracing::debug!("Failed to connect for node level sync: {}", err);
            return false;
        }
    };

    let mut service = client.node_service();
    match service
        .find_node_level_info(crate::pb::FindNodeLevelInfoRequest {})
        .await
    {
        Ok(resp) => {
            let resp = resp.into_inner();
            let parent_nodes = if resp.parent_nodes_map_json.is_empty() {
                std::collections::HashMap::new()
            } else {
                serde_json::from_slice::<
                    std::collections::HashMap<String, Vec<crate::config_models::ParentNodeConfig>>,
                >(&resp.parent_nodes_map_json)
                .map(|raw| {
                    raw.into_iter()
                        .filter_map(|(key, value)| key.parse::<i64>().ok().map(|id| (id, value)))
                        .collect()
                })
                .unwrap_or_default()
            };

            config_store
                .update_node_level_info(resp.level, parent_nodes)
                .await;
            true
        }
        Err(err) => {
            tracing::debug!("Failed to fetch node level info: {}", err);
            false
        }
    }
}
