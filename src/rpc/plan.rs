use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::pb;
use crate::rpc::client::RpcClient;
use tracing::debug;

pub async fn sync_active_plans(api_config: &ApiConfig, config_store: &ConfigStore) -> bool {
    let server_ids = config_store
        .get_all_servers()
        .await
        .into_iter()
        .filter_map(|server| server.id)
        .collect::<Vec<_>>();

    if server_ids.is_empty() {
        config_store
            .set_user_plans(std::collections::HashMap::new())
            .await;
        config_store.set_plans(std::collections::HashMap::new()).await;
        return true;
    }

    let client = match RpcClient::new(api_config).await {
        Ok(client) => client,
        Err(err) => {
            debug!("Failed to connect for plan sync: {}", err);
            return false;
        }
    };

    let mut server_service = client.server_service();
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
                debug!("Failed to fetch user plan for server {}: {}", server_id, err);
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

    config_store.set_user_plans(user_plans).await;
    config_store.set_plans(plans).await;
    true
}
