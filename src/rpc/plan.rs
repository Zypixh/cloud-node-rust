use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::pb;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::debug;

static PLAN_NODE_TYPE_UNSUPPORTED_LOGGED: AtomicBool = AtomicBool::new(false);

pub async fn sync_active_plans(api_config: &ApiConfig, config_store: &ConfigStore) -> bool {
    sync_active_plans_for_generation(
        api_config,
        config_store,
        config_store.runtime_reload_generation(),
    )
    .await
}

pub async fn sync_active_plans_for_generation(
    api_config: &ApiConfig,
    config_store: &ConfigStore,
    expected_generation: u64,
) -> bool {
    if config_store.runtime_reload_generation() != expected_generation {
        return false;
    }

    let server_ids = config_store
        .get_all_servers()
        .await
        .into_iter()
        .filter_map(|server| server.id)
        .collect::<Vec<_>>();

    if server_ids.is_empty() {
        return config_store
            .set_active_plans_if_generation(
                expected_generation,
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
            )
            .await;
    }

    let client = match crate::rpc::client::SharedRpcClient::get(api_config).await {
        Ok(s) => s.as_rpc_client(),
        Err(err) => {
            debug!("Failed to connect for plan sync: {}", err);
            return false;
        }
    };

    let mut server_service = client.server_service_with_type();
    let mut user_plans = std::collections::HashMap::new();
    let mut plan_ids = std::collections::HashSet::new();

    for server_id in server_ids {
        match server_service
            .find_server_user_plan(pb::FindServerUserPlanRequest { server_id })
            .await
        {
            Ok(resp) => {
                if let Some(user_plan) = resp.into_inner().user_plan {
                    if user_plan.id > 0 {
                        plan_ids.insert(user_plan.plan_id);
                        user_plans.insert(user_plan.id, user_plan);
                    }
                }
            }
            Err(err) => {
                if is_unsupported_node_type_error(&err) {
                    if !PLAN_NODE_TYPE_UNSUPPORTED_LOGGED.swap(true, Ordering::Relaxed) {
                        debug!(
                            "Plan sync is not supported by this API node for node credentials: {}",
                            err
                        );
                    }
                    return false;
                }
                debug!(
                    "Failed to fetch user plan for server {}: {}",
                    server_id, err
                );
            }
        }
    }

    let mut plans = std::collections::HashMap::new();
    let mut plan_service = client.plan_service();
    for plan_id in plan_ids {
        if plan_id <= 0 {
            continue;
        }

        let resp = match plan_service
            .find_enabled_plan(pb::FindEnabledPlanRequest { plan_id })
            .await
        {
            Ok(resp) => resp.into_inner().plan,
            Err(_) => match plan_service
                .find_basic_plan(pb::FindBasicPlanRequest { plan_id })
                .await
            {
                Ok(resp) => resp.into_inner().plan,
                Err(err) => {
                    debug!("Failed to sync plan {}: {}", plan_id, err);
                    continue;
                }
            },
        };

        if let Some(plan) = resp {
            plans.insert(plan.id, plan);
        }
    }

    config_store
        .set_active_plans_if_generation(expected_generation, user_plans, plans)
        .await
}

fn is_unsupported_node_type_error(err: &tonic::Status) -> bool {
    err.message().contains("not supported node type")
}
