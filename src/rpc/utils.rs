use std::collections::HashMap;
use std::sync::Arc;
use pingora_load_balancing::{LoadBalancer, selection::RoundRobin};
use crate::config_models::{ServerConfig, ParentNodeConfig};
use crate::health_manager::GlobalHealthManager;
use crate::api_config::ApiConfig;
use std::time::Duration;

#[allow(clippy::type_complexity)]
pub fn build_runtime_maps(
    servers: Vec<ServerConfig>,
    health_manager: &GlobalHealthManager,
) -> (
    HashMap<String, ServerConfig>,
    HashMap<String, Arc<LoadBalancer<RoundRobin>>>,
) {
    let mut new_servers = HashMap::new();
    let mut new_routes = HashMap::new();

    for server in servers {
        if !server.is_on {
            continue;
        }

        let lb_arc = build_lb(&server, 1, &HashMap::new(), false);
        
        if let Some(id) = server.id {
            health_manager.register(id, lb_arc.clone(), Duration::from_secs(30));
        }

        for name in &server.server_names {
            new_servers.insert(name.clone(), server.clone());
            new_routes.insert(name.clone(), lb_arc.clone());
        }
    }

    (new_servers, new_routes)
}

pub fn build_lb(
    server: &ServerConfig,
    _level: i32,
    _parents: &HashMap<i64, Vec<ParentNodeConfig>>,
    _bypass: bool,
) -> Arc<LoadBalancer<RoundRobin>> {
    let mut upstreams = Vec::new();
    if let Some(rp) = &server.reverse_proxy {
        for origin in &rp.primary_origins {
            if origin.is_on
                && let Some(addr) = &origin.addr {
                    upstreams.push(addr.to_address());
                }
        }
    }
    
    if upstreams.is_empty() {
        upstreams.push("127.0.0.1:80".to_string());
    }

    let lb = LoadBalancer::try_from_iter(upstreams).expect("Failed to build LB");
    Arc::new(lb)
}

pub async fn sync_deleted_contents(
    _api_config: &ApiConfig,
    _config_store: &crate::config::ConfigStore,
    _version: &mut i64,
) {
}
