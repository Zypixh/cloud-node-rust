use std::collections::HashMap;
use std::sync::Arc;
use pingora_load_balancing::{LoadBalancer, selection::RoundRobin};
use crate::config_models::ServerConfig;
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

        let server_id = server.numeric_id();
        let (lb_arc, has_hc) = if let Some(rp) = &server.reverse_proxy {
            crate::lb_factory::build_lb(server_id, rp, 1, &HashMap::new(), false, false)
        } else {
             // Fallback if no reverse proxy config
             let mut b = pingora_load_balancing::Backend::new("127.0.0.1:80").unwrap();
             let mut ext = http::Extensions::new();
             ext.insert(crate::lb_factory::BackendExtension {
                use_tls: false,
                host: String::new(),
                follow_host: false,
                tls_verify: true,
                client_cert: None,
             });
             b.ext = ext;
             let mut set = std::collections::BTreeSet::new();
             set.insert(b);
             let backends = pingora_load_balancing::Backends::new(pingora_load_balancing::discovery::Static::new(set));
             (Arc::new(LoadBalancer::from_backends(backends)), false)
        };
        
        if let Some(id) = server.id {
            if has_hc {
                health_manager.register(id, lb_arc.clone(), Duration::from_secs(30));
            }
        }

        for name in server.get_plain_server_names() {
            new_servers.insert(name.clone(), server.clone());
            new_routes.insert(name.clone(), lb_arc.clone());
        }
    }

    (new_servers, new_routes)
}

pub async fn sync_deleted_contents(
    _api_config: &ApiConfig,
    _config_store: &crate::config::ConfigStore,
    _version: &mut i64,
) {
}
