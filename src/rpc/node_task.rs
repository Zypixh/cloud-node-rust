use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::pb;
use crate::rpc::api_node::sync_updating_server_list_once;
use crate::rpc::cache::sync_cache_tasks;
use crate::rpc::client::SharedRpcClient;
use crate::rpc::ip_list::sync_ip_items_incremental;
use crate::rpc::plan::{sync_active_plans, sync_active_plans_for_generation};
use crate::rpc::server::{
    PrepareServerConfigError, apply_prepared_server_config_batch, prepare_server_config_mutation,
    sync_user_servers_state,
};
use std::sync::LazyLock as Lazy;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

static TASK_SYNC_NOTIFY: Lazy<Notify> = Lazy::new(Notify::new);

pub fn trigger_task_sync() {
    info!("Triggering immediate task sync...");
    TASK_SYNC_NOTIFY.notify_one();
}

pub async fn wait_for_task_sync() {
    TASK_SYNC_NOTIFY.notified().await;
}

fn is_server_scoped_config_task(task: &pb::NodeTask) -> bool {
    task.server_id > 0
        && matches!(
            task.r#type.as_str(),
            "configChanged"
                | "ddosProtectionChanged"
                | "globalServerConfigChanged"
                | "uamPolicyChanged"
                | "httpCCPolicyChanged"
                | "http3PolicyChanged"
                | "httpPagesPolicyChanged"
                | "toaChanged"
                | "networkSecurityPolicyChanged"
                | "webPPolicyChanged"
                | "accessLogChanged"
                | "dnsResolverChanged"
                | "grpcPolicyChanged"
                | "scheduleChanged"
                | "apiConfigChanged"
                | "indexNodeConfigChanged"
                | "cachePolicyChanged"
                | "firewallPolicyChanged"
        )
}

pub async fn sync_node_tasks(
    api_config: &ApiConfig,
    config_store: &ConfigStore,
    health_manager: &crate::health_manager::GlobalHealthManager,
    cert_selector: &crate::ssl::DynamicCertSelector,
    ip_list_manager: &crate::firewall::lists::GlobalIpListManager,
    task_version: &mut i64,
    config_synced: bool,
) {
    let client = match SharedRpcClient::get(api_config).await {
        Ok(shared) => shared.as_rpc_client(),
        Err(_) => return,
    };
    let mut task_service = client.node_task_service();

    let req = pb::FindNodeTasksRequest {
        version: *task_version,
    };
    let tasks = match crate::rpc::track_rpc(task_service.find_node_tasks(req)).await {
        Ok(resp) => resp.into_inner().node_tasks,
        Err(e) => {
            debug!("Failed to find node tasks: {}", e);
            return;
        }
    };

    let mut index = 0;
    while index < tasks.len() {
        if is_server_scoped_config_task(&tasks[index]) {
            let context = config_store.origin_build_context_snapshot();
            let mut prepared = Vec::new();
            let mut staged_bytes = 0_u64;
            let mut next = index;
            let mut stopped_before_task = false;

            while next < tasks.len() && is_server_scoped_config_task(&tasks[next]) {
                let budget = crate::memory_governor::MEMORY_GOVERNOR.config_sync_budget();
                if !budget.allow_new_prepare {
                    crate::pipeline_metrics::increment(
                        crate::pipeline_metrics::PipelineCounter::ConfigTaskBatchesDeferred,
                    );
                    crate::pipeline_metrics::increment(
                        crate::pipeline_metrics::PipelineCounter::ConfigTaskDeferred,
                    );
                    info!(
                        pressure = budget.pressure_level.as_str(),
                        available_bytes = budget.available_bytes,
                        "deferring configuration task batch under memory pressure"
                    );
                    stopped_before_task = true;
                    break;
                }

                let task = &tasks[next];
                let singleton_capacity = budget
                    .available_bytes
                    .saturating_sub(budget.commit_reserve_bytes);
                let max_payload_bytes = if prepared.is_empty() {
                    singleton_capacity
                } else {
                    budget.staging_budget_bytes.saturating_sub(staged_bytes)
                };
                info!("Preparing NodeTask: {} (Type: {})", task.id, task.r#type);
                let item = match prepare_server_config_mutation(
                    api_config,
                    task.server_id,
                    &context,
                    max_payload_bytes,
                )
                .await
                {
                    Ok(item) => item,
                    Err(PrepareServerConfigError::PayloadTooLarge { payload_bytes }) => {
                        crate::pipeline_metrics::increment(
                            crate::pipeline_metrics::PipelineCounter::ConfigTaskBatchesDeferred,
                        );
                        crate::pipeline_metrics::increment(
                            crate::pipeline_metrics::PipelineCounter::ConfigTaskDeferred,
                        );
                        info!(
                            task_id = task.id,
                            payload_bytes,
                            max_payload_bytes,
                            "deferring configuration task before runtime-map preparation"
                        );
                        stopped_before_task = true;
                        break;
                    }
                    Err(PrepareServerConfigError::Failed) => {
                        crate::pipeline_metrics::increment(
                            crate::pipeline_metrics::PipelineCounter::ConfigTaskPrepareFailed,
                        );
                        stopped_before_task = true;
                        break;
                    }
                };

                let budget = crate::memory_governor::MEMORY_GOVERNOR.config_sync_budget();
                let next_staged_bytes = staged_bytes.saturating_add(item.payload_bytes);
                let singleton_capacity = budget
                    .available_bytes
                    .saturating_sub(budget.commit_reserve_bytes);
                let fits_staging_budget = next_staged_bytes <= budget.staging_budget_bytes;
                let fits_as_singleton =
                    prepared.is_empty() && item.payload_bytes <= singleton_capacity;
                if !fits_staging_budget && !fits_as_singleton {
                    crate::pipeline_metrics::increment(
                        crate::pipeline_metrics::PipelineCounter::ConfigTaskBatchesDeferred,
                    );
                    crate::pipeline_metrics::increment(
                        crate::pipeline_metrics::PipelineCounter::ConfigTaskDeferred,
                    );
                    info!(
                        task_id = task.id,
                        payload_bytes = item.payload_bytes,
                        staged_bytes,
                        staging_budget_bytes = budget.staging_budget_bytes,
                        "deferring configuration task outside staging budget"
                    );
                    stopped_before_task = true;
                    break;
                }

                staged_bytes = next_staged_bytes;
                prepared.push(item);
                next += 1;
            }

            if prepared.is_empty() {
                break;
            }

            let commit_budget = crate::memory_governor::MEMORY_GOVERNOR.config_sync_budget();
            if !commit_budget.allow_commit
                || staged_bytes
                    > commit_budget
                        .available_bytes
                        .saturating_sub(commit_budget.commit_reserve_bytes)
            {
                crate::pipeline_metrics::increment(
                    crate::pipeline_metrics::PipelineCounter::ConfigTaskBatchesDeferred,
                );
                info!(
                    pressure = commit_budget.pressure_level.as_str(),
                    available_bytes = commit_budget.available_bytes,
                    staged_bytes,
                    commit_reserve_bytes = commit_budget.commit_reserve_bytes,
                    "deferring prepared configuration task batch before commit"
                );
                break;
            }

            if !apply_prepared_server_config_batch(
                config_store,
                health_manager,
                context.generation,
                prepared,
            )
            .await
            {
                crate::pipeline_metrics::increment(
                    crate::pipeline_metrics::PipelineCounter::ConfigTaskCommitRejected,
                );
                warn!("Configuration task batch became stale before commit");
                break;
            }

            crate::pipeline_metrics::increment(
                crate::pipeline_metrics::PipelineCounter::ConfigTaskBatchesPublished,
            );

            for task in &tasks[index..next] {
                let reported = crate::rpc::track_rpc(task_service.report_node_task_done(
                    pb::ReportNodeTaskDoneRequest {
                        node_task_id: task.id,
                        is_ok: true,
                        error: String::new(),
                    },
                ))
                .await
                .is_ok();
                if !reported {
                    crate::pipeline_metrics::increment(
                        crate::pipeline_metrics::PipelineCounter::ConfigTaskAckFailed,
                    );
                    warn!("Failed to report NodeTask {} completion", task.id);
                    return;
                }
                if task.version > *task_version {
                    *task_version = task.version;
                }
            }

            let _ = sync_active_plans_for_generation(
                api_config,
                config_store,
                context.generation.wrapping_add(1),
            )
            .await;

            if stopped_before_task {
                return;
            }
            index = next;
            continue;
        }

        let task = &tasks[index];
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
            | "webPPolicyChanged"
            | "accessLogChanged"
            | "dnsResolverChanged"
            | "grpcPolicyChanged"
            | "scheduleChanged"
            | "apiConfigChanged"
            | "indexNodeConfigChanged"
            | "cachePolicyChanged"
            | "firewallPolicyChanged" => {
                if config_synced {
                    trigger_task_sync();
                    true
                } else {
                    warn!(
                        "Deferring NodeTask {} ({}) because config sync has not completed successfully in this round.",
                        task.id, task.r#type
                    );
                    break;
                }
            }
            "nodeLevelChanged" => crate::rpc::find_node_level_info(api_config, config_store).await,
            "planChanged" => sync_active_plans(api_config, config_store).await,
            "purgeServerCache" | "purgePathCache" | "preheatCache" => {
                if crate::cluster::leader::require_leader("cache_tasks") {
                    sync_cache_tasks(
                        client.channel(),
                        api_config,
                        config_store,
                        task.id,
                        task.server_id,
                    )
                    .await
                } else {
                    break;
                }
            }
            "ipItemChanged" => sync_ip_items_incremental(api_config, ip_list_manager).await,
            "updatingServers" => {
                let mut last_id = 0_i64;
                sync_updating_server_list_once(
                    api_config,
                    config_store,
                    health_manager,
                    cert_selector,
                    &mut last_id,
                )
                .await
            }
            "userServersStateChanged" => {
                sync_user_servers_state(api_config, config_store, health_manager, task.user_id)
                    .await
            }
            "upgradeNode" | "installNode" | "startNode" => {
                info!(
                    "Received node lifecycle task '{}'. Acknowledging locally.",
                    task.r#type
                );
                true
            }
            "scriptsChanged" => {
                let unsupported = crate::unsupported::request_scripts::unsupported();
                warn!(
                    "Ignoring unsupported task 'scriptsChanged': {} ({})",
                    unsupported.reason, unsupported.code
                );
                true
            }
            "plusChanged" | "nodeVersionChanged" => true,
            other => {
                warn!(
                    "Unknown NodeTask type '{}' (task id={}). Marking done to avoid retry loop.",
                    other, task.id
                );
                true
            }
        };

        if let Some(options) = task_type.strip_prefix("ipListDeleted@")
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(options)
            && let Some(list_id) = value.get("listId").and_then(|v| v.as_i64())
        {
            ip_list_manager.remove_list(list_id);
        }

        let reported = crate::rpc::track_rpc(task_service.report_node_task_done(
            pb::ReportNodeTaskDoneRequest {
                node_task_id: task.id,
                is_ok: success,
                error: if success {
                    String::new()
                } else {
                    "Task failed".to_string()
                },
            },
        ))
        .await
        .is_ok();

        if !reported {
            warn!("Failed to report NodeTask {} completion", task.id);
            break;
        }
        if task.version > *task_version {
            *task_version = task.version;
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_server_scoped_configuration_tasks_are_batchable() {
        let config_task = pb::NodeTask {
            server_id: 7,
            r#type: "configChanged".to_string(),
            ..Default::default()
        };
        assert!(is_server_scoped_config_task(&config_task));

        let global_config_task = pb::NodeTask {
            server_id: 0,
            r#type: "configChanged".to_string(),
            ..Default::default()
        };
        assert!(!is_server_scoped_config_task(&global_config_task));

        let ordering_boundary = pb::NodeTask {
            server_id: 7,
            r#type: "planChanged".to_string(),
            ..Default::default()
        };
        assert!(!is_server_scoped_config_task(&ordering_boundary));
    }
}
