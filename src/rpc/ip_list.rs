use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::SharedRpcClient;
use std::sync::Arc;
use tracing::{debug, warn};

pub async fn start_ip_list_syncer(
    api_config: ApiConfig,
    config_store: Arc<crate::config::ConfigStore>,
    ip_list_manager: Arc<crate::firewall::lists::GlobalIpListManager>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;

        // Check if IP list sync is enabled in global config
        if !config_store.get_node_enable_ip_lists_sync() {
            debug!("IP list sync is DISABLED in node settings. Skipping...");
            continue;
        }

        // cloud API exposes IPListService.list_enabled_ip_lists / find_enabled_ip_list
        // only to admin credentials. Nodes pull items incrementally via
        // IPItemService.list_ip_items_after_version (which is node-accessible);
        // the listType on each item already carries the kind, so we don't need
        // separate list metadata.
        let _ = sync_ip_items_incremental(&api_config, ip_list_manager.as_ref()).await;
    }
}

pub async fn sync_ip_items_incremental(
    api_config: &ApiConfig,
    ip_list_manager: &crate::firewall::lists::GlobalIpListManager,
) -> bool {
    let client = match SharedRpcClient::get(api_config).await {
        Ok(shared) => shared.as_rpc_client(),
        Err(e) => {
            debug!("Failed to connect for IP item sync: {}", e);
            return false;
        }
    };
    let mut service = client.ip_item_service();

    let last_version = ip_list_manager.last_version();
    match service
        .list_ip_items_after_version(pb::ListIpItemsAfterVersionRequest {
            version: last_version,
            size: 5000,
        })
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            let mut failed_count = 0usize;
            for item in inner.ip_items {
                if !ip_list_manager.apply_item(item) {
                    failed_count += 1;
                }
            }
            ip_list_manager.waf_state.persist_blocked_snapshot();
            if inner.version > last_version {
                ip_list_manager.update_last_version(inner.version);
            }
            if failed_count > 0 {
                warn!(
                    "IP item sync skipped {} invalid items and advanced cursor from {} to {}",
                    failed_count, last_version, inner.version
                );
            }
            failed_count == 0
        }
        Err(e) => {
            debug!("Failed to sync IP items incrementally: {}", e);
            false
        }
    }
}
