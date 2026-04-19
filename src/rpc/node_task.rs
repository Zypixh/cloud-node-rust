use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::pb;
use crate::rpc::api_node::sync_updating_server_list_once;
use crate::rpc::cache::sync_cache_tasks;
use crate::rpc::client::RpcClient;
use crate::rpc::ip_list::sync_ip_items_incremental;
use crate::rpc::scripts::sync_script_configs;
use crate::rpc::server::{sync_single_server_config, sync_user_servers_state};
use tracing::{debug, info, warn};
use tokio::sync::Notify;
use once_cell::sync::Lazy;

static TASK_SYNC_NOTIFY: Lazy<Notify> = Lazy::new(Notify::new);

pub fn trigger_task_sync() {
    info!("Triggering immediate task sync...");
    TASK_SYNC_NOTIFY.notify_one();
}

pub async fn wait_for_task_sync() {
    TASK_SYNC_NOTIFY.notified().await;
}

pub async fn sync_node_tasks(
    api_config: &ApiConfig,
    config_store: &ConfigStore,
    health_manager: &crate::health_manager::GlobalHealthManager,
    ip_list_manager: &crate::firewall::lists::GlobalIpListManager,
    task_version: &mut i64,
) {
    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut task_service = client.node_task_service();

    let req = pb::FindNodeTasksRequest {
        version: *task_version,
    };
    match task_service.find_node_tasks(req).await {
        Ok(resp) => {
            let tasks = resp.into_inner().node_tasks;
            for task in tasks {
                info!("Processing NodeTask: {} (Type: {})", task.id, task.r#type);
                let task_type = task.r#type.as_str();
                let success = match task_type {
                    "configChanged"
                    | "ddosProtectionChanged"
                    | "globalServerConfigChanged"
                    | "uamPolicyChanged"
                    | "httpCCPolicyChanged"
                    | "http3PolicyChanged"
                    | "httpPagesPolicyChanged"
                    | "toaChanged"
                    | "networkSecurityPolicyChanged"
                    | "webPPolicyChanged" => {
                        if task.server_id > 0 {
                            sync_single_server_config(
                                api_config,
                                config_store,
                                health_manager,
                                task.server_id,
                            )
                            .await
                        } else {
                            true
                        }
                    }
                    "nodeLevelChanged" | "planChanged" => {
                        crate::rpc::find_node_level_info(api_config).await;
                        true
                    }
                    "purgeServerCache" | "purgePathCache" | "preheatCache" => {
                        sync_cache_tasks(client.channel(), api_config).await
                    }
                    "ipItemChanged" => sync_ip_items_incremental(api_config, ip_list_manager).await,
                    "updatingServers" => {
                        let mut last_id = 0i64;
                        let mut updating = std::collections::HashSet::new();
                        sync_updating_server_list_once(
                            api_config,
                            config_store,
                            &mut last_id,
                            &mut updating,
                        )
                        .await;
                        true
                    }
                    "userServersStateChanged" => {
                        sync_user_servers_state(
                            api_config,
                            config_store,
                            health_manager,
                            task.user_id,
                        )
                        .await
                    }
                    "upgradeNode" | "installNode" | "startNode" => {
                        info!(
                            "Received node lifecycle task '{}'. Tracking as completed.",
                            task.r#type
                        );
                        let numeric_node_id = config_store.get_node_id().await;
                        if numeric_node_id == 0 {
                            warn!(
                                "Skipping '{}' report because numeric node ID has not been synced yet.",
                                task.r#type
                            );
                            false
                        } else {
                            let mut node_client = client.node_service_with_type();
                            node_client
                                .update_node_is_installed(pb::UpdateNodeIsInstalledRequest {
                                    node_id: numeric_node_id,
                                    is_installed: true,
                                })
                                .await
                                .is_ok()
                        }
                    }
                    "scriptsChanged" => sync_script_configs(api_config).await,
                    "plusChanged" | "nodeVersionChanged" => true,
                    _ => true,
                };

                if let Some(options) = task_type.strip_prefix("ipListDeleted@")
                    && let Ok(value) = serde_json::from_str::<serde_json::Value>(options)
                        && let Some(list_id) = value.get("listId").and_then(|v| v.as_i64()) {
                            ip_list_manager.remove_list(list_id);
                        }

                let _ = task_service
                    .report_node_task_done(pb::ReportNodeTaskDoneRequest {
                        node_task_id: task.id,
                        is_ok: success,
                        error: if success {
                            "".to_string()
                        } else {
                            "Task failed".to_string()
                        },
                    })
                    .await;

                if task.version > *task_version {
                    *task_version = task.version;
                }
            }
        }
        Err(e) => {
            debug!("Failed to find node tasks: {}", e);
        }
    }
}
