use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::config_models::ServerConfig;
use crate::pb;
use crate::rpc::client::RpcClient;
use crate::rpc::logs::report_node_log_with_context;
use crate::rpc::plan::sync_active_plans;
use crate::rpc::utils::build_runtime_maps;
use tracing::{debug, error};

fn log_server_json_hints(label: &str, raw: &[u8]) {
    let text = String::from_utf8_lossy(raw);
    for needle in ["@sni_passthrough", "speedtest", "www.speedtest.cn"] {
        if let Some(pos) = text.find(needle) {
            let start = pos.saturating_sub(240);
            let end = (pos + needle.len() + 240).min(text.len());
            tracing::info!(
                "RPC_SERVER: Raw {} contains {:?}. snippet={}",
                label,
                needle,
                &text[start..end]
            );
        }
    }
}

pub async fn sync_single_server_config(
    api_config: &ApiConfig,
    config_store: &ConfigStore,
    health_manager: &crate::health_manager::GlobalHealthManager,
    server_id: i64,
) -> bool {
    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(e) => {
            debug!("Failed to connect for server config sync: {}", e);
            report_node_log_with_context(
                api_config,
                "error",
                "SERVER_SYNC",
                &format!("failed to connect for server config sync: {}", e),
                Some(server_id),
                Some("serverConfigSyncFailed"),
                None,
            )
            .await;
            return false;
        }
    };
    let mut server_service = client.server_service();

    match server_service
        .compose_server_config(pb::ComposeServerConfigRequest { server_id })
        .await
    {
        Ok(resp) => {
            let payload = resp.into_inner();
            if payload.server_config_json.is_empty() {
                config_store.remove_server(server_id).await;
                let _ = sync_active_plans(api_config, config_store).await;
                return true;
            }
            log_server_json_hints("server_config_json", &payload.server_config_json);
            match serde_json::from_slice::<ServerConfig>(&payload.server_config_json) {
                Ok(server) => {
                    let user_id = server.user_id;
                    let runtime_servers = vec![server];
                    let (servers, routes) = build_runtime_maps(runtime_servers.clone(), health_manager);
                    if user_id > 0 {
                        config_store
                            .replace_user_servers(user_id, runtime_servers, servers, routes)
                            .await;
                    } else {
                        config_store
                            .replace_server(server_id, runtime_servers, servers, routes)
                            .await;
                    }
                    let _ = sync_active_plans(api_config, config_store).await;
                    true
                }
                Err(e) => {
                    error!("Failed to decode server config {}: {}", server_id, e);
                    report_node_log_with_context(
                        api_config,
                        "error",
                        "SERVER_SYNC",
                        &format!("failed to decode server config {}: {}", server_id, e),
                        Some(server_id),
                        Some("serverConfigDecodeFailed"),
                        None,
                    )
                    .await;
                    false
                }
            }
        }
        Err(e) => {
            debug!("Failed to sync single server config {}: {}", server_id, e);
            report_node_log_with_context(
                api_config,
                "error",
                "SERVER_SYNC",
                &format!("failed to compose server config {}: {}", server_id, e),
                Some(server_id),
                Some("serverConfigComposeFailed"),
                None,
            )
            .await;
            false
        }
    }
}

pub async fn sync_user_servers_state(
    api_config: &ApiConfig,
    config_store: &ConfigStore,
    health_manager: &crate::health_manager::GlobalHealthManager,
    user_id: i64,
) -> bool {
    if user_id <= 0 {
        return true;
    }

    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(e) => {
            debug!("Failed to connect for user server state sync: {}", e);
            report_node_log_with_context(
                api_config,
                "error",
                "SERVER_SYNC",
                &format!(
                    "failed to connect for user {} server state sync: {}",
                    user_id, e
                ),
                None,
                Some("userServerStateSyncFailed"),
                Some(serde_json::json!({ "userId": user_id })),
            )
            .await;
            return false;
        }
    };
    let mut user_service = client.user_service();
    let mut server_service = client.server_service();

    let is_enabled = match user_service
        .check_user_servers_state(pb::CheckUserServersStateRequest { user_id })
        .await
    {
        Ok(resp) => resp.into_inner().is_enabled,
        Err(e) => {
            debug!("Failed to check user {} server state: {}", user_id, e);
            report_node_log_with_context(
                api_config,
                "error",
                "SERVER_SYNC",
                &format!("failed to check user {} server state: {}", user_id, e),
                None,
                Some("userServerStateCheckFailed"),
                Some(serde_json::json!({ "userId": user_id })),
            )
            .await;
            return false;
        }
    };

    if !is_enabled {
        config_store.remove_user_servers(user_id).await;
        let _ = sync_active_plans(api_config, config_store).await;
        return true;
    }

    match server_service
        .compose_all_user_servers_config(pb::ComposeAllUserServersConfigRequest { user_id })
        .await
    {
        Ok(resp) => {
            let payload = resp.into_inner();
            if payload.servers_config_json.is_empty() {
                config_store.remove_user_servers(user_id).await;
                let _ = sync_active_plans(api_config, config_store).await;
                return true;
            }
            log_server_json_hints("servers_config_json", &payload.servers_config_json);
            match serde_json::from_slice::<Vec<ServerConfig>>(&payload.servers_config_json) {
                Ok(servers) => {
                    let runtime_servers = servers;
                    let (servers_map, routes_map) = build_runtime_maps(runtime_servers.clone(), health_manager);
                    config_store
                        .replace_user_servers(user_id, runtime_servers, servers_map, routes_map)
                        .await;
                    let _ = sync_active_plans(api_config, config_store).await;
                    true
                }
                Err(e) => {
                    error!("Failed to decode user {} servers config: {}", user_id, e);
                    report_node_log_with_context(
                        api_config,
                        "error",
                        "SERVER_SYNC",
                        &format!("failed to decode user {} servers config: {}", user_id, e),
                        None,
                        Some("userServersConfigDecodeFailed"),
                        Some(serde_json::json!({ "userId": user_id })),
                    )
                    .await;
                    false
                }
            }
        }
        Err(e) => {
            debug!("Failed to compose user {} servers config: {}", user_id, e);
            report_node_log_with_context(
                api_config,
                "error",
                "SERVER_SYNC",
                &format!("failed to compose user {} servers config: {}", user_id, e),
                None,
                Some("userServersConfigComposeFailed"),
                Some(serde_json::json!({ "userId": user_id })),
            )
            .await;
            false
        }
    }
}
