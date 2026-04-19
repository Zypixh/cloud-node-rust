use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::RpcClient;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

pub async fn start_ip_list_syncer(
    api_config: ApiConfig,
    config_store: Arc<crate::config::ConfigStore>,
    ip_list_manager: Arc<crate::firewall::lists::GlobalIpListManager>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut last_meta_sync = Instant::now() - Duration::from_secs(300);
    loop {
        interval.tick().await;

        // Check if IP list sync is enabled in global config
        if !config_store.get_node_enable_ip_lists_sync() {
            debug!("IP list sync is DISABLED in node settings. Skipping...");
            continue;
        }

        if last_meta_sync.elapsed() >= Duration::from_secs(300) {
            let _ = sync_ip_list_metadata(&api_config, ip_list_manager.as_ref()).await;
            last_meta_sync = Instant::now();
        }
        let _ = sync_ip_items_incremental(&api_config, ip_list_manager.as_ref()).await;
    }
}

pub async fn fetch_ip_list_items(api_config: &ApiConfig, list_id: i64) -> Vec<String> {
    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let mut service = client.ip_item_service();

    match service
        .list_ip_items_with_list_id(pb::ListIpItemsWithListIdRequest {
            ip_list_id: list_id,
            ..Default::default()
        })
        .await
    {
        Ok(resp) => resp
            .into_inner()
            .ip_items
            .into_iter()
            .map(|item| item.value)
            .collect(),
        Err(_) => vec![],
    }
}

pub async fn sync_ip_items_incremental(
    api_config: &ApiConfig,
    ip_list_manager: &crate::firewall::lists::GlobalIpListManager,
) -> bool {
    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(e) => {
            debug!("Failed to connect for IP item sync: {}", e);
            return false;
        }
    };
    let mut service = client.ip_item_service_with_type();

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
            for item in inner.ip_items {
                ip_list_manager.apply_item(item.list_id, &item.value, item.is_deleted);
            }
            ip_list_manager.update_last_version(inner.version);
            true
        }
        Err(e) => {
            debug!("Failed to sync IP items incrementally: {}", e);
            false
        }
    }
}

pub async fn sync_ip_list_metadata(
    api_config: &ApiConfig,
    ip_list_manager: &crate::firewall::lists::GlobalIpListManager,
) -> bool {
    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(e) => {
            debug!("Failed to connect for IP list metadata sync: {}", e);
            return false;
        }
    };
    let mut service = client.ip_list_service();
    let mut offset = 0i64;
    let size = 1000i64;
    let mut all_lists = Vec::new();

    loop {
        match service
            .list_enabled_ip_lists(pb::ListEnabledIpListsRequest {
                r#type: "cluster".to_string(),
                offset,
                size,
                ..Default::default()
            })
            .await
        {
            Ok(resp) => {
                let mut lists = resp.into_inner().ip_lists;
                let count = lists.len() as i64;
                all_lists.append(&mut lists);
                if count < size {
                    break;
                }
                offset += count;
            }
            Err(e) => {
                debug!("Failed to list enabled IP lists: {}", e);
                return false;
            }
        }
    }

    ip_list_manager.replace_metadata(all_lists);
    true
}

pub async fn sync_ip_list_ref(
    api_config: &ApiConfig,
    ip_list_manager: &crate::firewall::lists::GlobalIpListManager,
    list_id: i64,
) -> bool {
    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(e) => {
            debug!("Failed to connect for IP list ref sync: {}", e);
            return false;
        }
    };
    let mut service = client.ip_list_service();

    match service
        .find_enabled_ip_list(pb::FindEnabledIpListRequest {
            ip_list_id: list_id,
        })
        .await
    {
        Ok(resp) => {
            if let Some(list) = resp.into_inner().ip_list {
                ip_list_manager.update_metadata(list);
                true
            } else {
                ip_list_manager.remove_list(list_id);
                false
            }
        }
        Err(e) => {
            debug!("Failed to find IP list {}: {}", list_id, e);
            false
        }
    }
}

pub async fn report_blocked_ip(api_config: &ApiConfig, list_id: i64, ip: String, reason: String) {
    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut service = client.ip_item_service();

    let _ = service
        .create_ip_item(pb::CreateIpItemRequest {
            ip_list_id: list_id,
            value: ip,
            reason,
            ..Default::default()
        })
        .await;
}
