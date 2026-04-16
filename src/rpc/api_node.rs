use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::pb;
use crate::rpc::client::RpcClient;
use crate::rpc::logs::report_node_log_with_context;
use std::sync::Arc;
use tracing::{debug, warn};

pub async fn start_api_node_syncer(api_config: ApiConfig) {
    if api_config.rpc_disable_update {
        return;
    }

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
    loop {
        interval.tick().await;
        sync_api_nodes(&api_config).await;
    }
}

pub async fn start_updating_server_list_syncer(
    api_config: ApiConfig,
    config_store: Arc<ConfigStore>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut last_id = 0i64;
    let mut updating_set = std::collections::HashSet::new();

    loop {
        interval.tick().await;
        sync_updating_server_list_once(
            &api_config,
            config_store.as_ref(),
            &mut last_id,
            &mut updating_set,
        )
        .await;
    }
}

pub async fn sync_updating_server_list_once(
    api_config: &ApiConfig,
    config_store: &ConfigStore,
    last_id: &mut i64,
    updating_set: &mut std::collections::HashSet<i64>,
) {
    let client = match RpcClient::new(api_config).await {
        Ok(client) => client,
        Err(e) => {
            warn!("Failed to connect for updating server sync: {}", e);
            report_node_log_with_context(
                api_config,
                "warn",
                "API_NODE",
                &format!("failed to connect for updating server sync: {}", e),
                None,
                Some("updatingServerSyncConnectFailed"),
                None,
            )
            .await;
            return;
        }
    };

    let mut service = client.updating_server_list_service();
    match service
        .find_updating_server_lists(pb::FindUpdatingServerListsRequest { last_id: *last_id })
        .await
    {
        Ok(resp) => {
            let resp = resp.into_inner();
            if resp.max_id > *last_id {
                *last_id = resp.max_id;
            }

            if !resp.servers_json.is_empty() {
                match serde_json::from_slice::<Vec<crate::config_models::ServerConfig>>(
                    &resp.servers_json,
                ) {
                    Ok(servers) => {
                        for s in servers {
                            if let Some(id) = s.id {
                                if s.is_on {
                                    updating_set.insert(id);
                                } else {
                                    updating_set.remove(&id);
                                }
                            }
                        }
                        config_store
                            .set_updating_servers(updating_set.iter().cloned().collect())
                            .await;
                    }
                    Err(e) => {
                        warn!("Failed to parse updating servers JSON: {}", e);
                        report_node_log_with_context(
                            api_config,
                            "error",
                            "API_NODE",
                            &format!("failed to parse updating servers JSON: {}", e),
                            None,
                            Some("updatingServerSyncDecodeFailed"),
                            None,
                        )
                        .await;
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to sync updating server list: {}", e);
            report_node_log_with_context(
                api_config,
                "warn",
                "API_NODE",
                &format!("failed to sync updating server list: {}", e),
                None,
                Some("updatingServerSyncFailed"),
                None,
            )
            .await;
        }
    }
}

pub async fn sync_api_nodes(api_config: &ApiConfig) {
    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(e) => {
            debug!("Failed to connect for api-node sync: {}", e);
            report_node_log_with_context(
                api_config,
                "warn",
                "API_NODE",
                &format!("failed to connect for api-node sync: {}", e),
                None,
                Some("apiNodeSyncConnectFailed"),
                None,
            )
            .await;
            return;
        }
    };
    let mut api_node_service = client.api_node_service();

    let resp = match api_node_service
        .find_all_enabled_api_nodes(pb::FindAllEnabledApiNodesRequest {})
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(e) => {
            debug!("Failed to list api nodes: {}", e);
            report_node_log_with_context(
                api_config,
                "warn",
                "API_NODE",
                &format!("failed to list api nodes: {}", e),
                None,
                Some("apiNodeListFailed"),
                None,
            )
            .await;
            return;
        }
    };

    let mut endpoints = Vec::new();
    for node in resp.api_nodes {
        if !node.is_on {
            continue;
        }
        for addr in node.access_addrs {
            if !addr.is_empty() {
                endpoints.push(addr);
            }
        }
    }
    endpoints.sort();
    endpoints.dedup();

    let current_endpoints = api_config.effective_rpc_endpoints();
    if endpoints.is_empty() || endpoints == current_endpoints {
        return;
    }

    let mut new_config = api_config.clone();
    new_config.rpc_endpoints = endpoints.clone();
    if let Err(e) = new_config.write_default() {
        debug!("Failed to write updated api_node config: {}", e);
        report_node_log_with_context(
            api_config,
            "error",
            "API_NODE",
            &format!("failed to write updated api_node config: {}", e),
            None,
            Some("apiNodeConfigWriteFailed"),
            Some(serde_json::json!({ "endpoints": new_config.rpc_endpoints })),
        )
        .await;
    }
    ApiConfig::set_runtime_rpc_endpoints(endpoints);
}
