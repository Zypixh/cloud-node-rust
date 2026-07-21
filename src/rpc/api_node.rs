use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::health_manager::GlobalHealthManager;
use crate::pb;
use crate::rpc::client::{RpcClient, SharedRpcClient};
use crate::rpc::logs::report_node_log_with_context;
use crate::rpc::utils::build_runtime_maps;
use crate::ssl::DynamicCertSelector;
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
    health_manager: Arc<GlobalHealthManager>,
    cert_selector: Arc<DynamicCertSelector>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut last_id = 0i64;

    loop {
        interval.tick().await;
        if config_store.get_node_id().await <= 0 {
            continue;
        }
        let baseline = config_store.get_updating_server_list_id().await;
        if last_id <= 0 || baseline > last_id {
            last_id = baseline;
        }
        sync_updating_server_list_once(
            &api_config,
            config_store.as_ref(),
            health_manager.as_ref(),
            cert_selector.as_ref(),
            &mut last_id,
        )
        .await;
    }
}

pub async fn sync_updating_server_list_once(
    api_config: &ApiConfig,
    config_store: &ConfigStore,
    health_manager: &GlobalHealthManager,
    cert_selector: &DynamicCertSelector,
    last_id: &mut i64,
) -> bool {
    if *last_id <= 0 {
        *last_id = config_store.get_updating_server_list_id().await;
    }

    let client = match SharedRpcClient::get(api_config).await {
        Ok(shared) => shared.as_rpc_client(),
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
            return false;
        }
    };

    let mut service = client.updating_server_list_service();
    match crate::rpc::track_rpc(
        service
            .find_updating_server_lists(pb::FindUpdatingServerListsRequest { last_id: *last_id }),
    )
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
                        let changed = servers
                            .iter()
                            .filter_map(|server| server.id)
                            .collect::<std::collections::HashSet<_>>();
                        let enabled = servers
                            .into_iter()
                            .filter(|server| server.is_on)
                            .collect::<Vec<_>>();
                        let (node_level, parent_nodes, tiered_origin_bypass, allow_lan) =
                            config_store.get_origin_runtime_context().await;
                        let global_http =
                            Some((*config_store.get_global_http_config_sync()).clone());
                        let (server_map, route_map) = build_runtime_maps(
                            enabled.clone(),
                            health_manager,
                            node_level,
                            parent_nodes,
                            tiered_origin_bypass,
                            allow_lan,
                            global_http,
                        )
                        .await;
                        for server_id in changed {
                            if server_id > 0 {
                                config_store.remove_server(server_id).await;
                            }
                        }
                        for server in enabled {
                            if let Some(server_id) = server.id
                                && server_id > 0
                            {
                                let replacement = Arc::new(server);
                                config_store
                                    .replace_server(
                                        server_id,
                                        vec![replacement],
                                        server_map
                                            .iter()
                                            .filter_map(|(host, cfg)| {
                                                (cfg.id == Some(server_id))
                                                    .then_some((host.clone(), cfg.clone()))
                                            })
                                            .collect(),
                                        route_map
                                            .iter()
                                            .filter_map(|(host, lb)| {
                                                server_map.get(host).and_then(|cfg| {
                                                    (cfg.id == Some(server_id))
                                                        .then_some((host.clone(), lb.clone()))
                                                })
                                            })
                                            .collect(),
                                    )
                                    .await;
                            }
                        }
                        refresh_certificates(config_store, cert_selector).await;
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
                        return false;
                    }
                }
            }
            true
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
            false
        }
    }
}

async fn refresh_certificates(config_store: &ConfigStore, cert_selector: &DynamicCertSelector) {
    let certs = config_store.collect_ssl_config().await;
    crate::ssl::sync_certs(cert_selector, &certs).await;
}

pub async fn sync_api_nodes(api_config: &ApiConfig) {
    let client = match SharedRpcClient::get(api_config).await {
        Ok(shared) => shared.as_rpc_client(),
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

    let resp = match crate::rpc::track_rpc(
        api_node_service.find_all_enabled_api_nodes(pb::FindAllEnabledApiNodesRequest {}),
    )
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
            match crate::api_config::validate_rpc_endpoint(&addr) {
                Ok(endpoint) => endpoints.push(endpoint),
                Err(err) => warn!("Ignoring invalid discovered API endpoint {:?}: {}", addr, err),
            }
        }
    }
    endpoints.sort();
    endpoints.dedup();

    let current_endpoints = api_config.effective_rpc_endpoints();
    if api_config.rpc_disable_update || endpoints.is_empty() || endpoints == current_endpoints {
        return;
    }

    let mut healthy_endpoints = Vec::new();
    for endpoint in &endpoints {
        if RpcClient::ping_endpoint(api_config, endpoint).await {
            healthy_endpoints.push(endpoint.clone());
        }
    }

    if healthy_endpoints.is_empty() {
        debug!(
            "Skipping api-node endpoint update because none of the discovered endpoints passed PingService health check"
        );
        report_node_log_with_context(
            api_config,
            "warn",
            "API_NODE",
            "discovered api-node endpoints failed PingService health check",
            None,
            Some("apiNodePingFailed"),
            Some(serde_json::json!({ "endpoints": endpoints })),
        )
        .await;
        return;
    }

    if healthy_endpoints == current_endpoints {
        return;
    }

    if let Err(e) = ApiConfig::set_runtime_rpc_endpoints(healthy_endpoints.clone()) {
        warn!("Rejected discovered API node endpoints: {}", e);
        report_node_log_with_context(
            api_config,
            "error",
            "API_NODE",
            &format!("rejected discovered API node endpoints: {}", e),
            None,
            Some("apiNodeEndpointRejected"),
            None,
        )
        .await;
        return;
    }

    let mut new_config = api_config.clone();
    new_config.rpc_endpoints = healthy_endpoints;
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
    if let Err(e) = crate::rpc::client::SharedRpcClient::refresh(api_config) {
        warn!(
            "Failed to refresh shared RPC channel after endpoint change: {}",
            e
        );
    }
}
